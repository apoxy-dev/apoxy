package apiserver

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	goruntime "runtime"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	driversgeneric "github.com/k3s-io/kine/pkg/drivers/generic"
	"github.com/k3s-io/kine/pkg/endpoint"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/apiserver/pkg/util/flowcontrol/request"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/rest"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// encodeSQLiteConnArgs encodes connection arguments as a query string.
func encodeSQLiteConnArgs(args map[string]string) string {
	var buf strings.Builder
	for k, v := range args {
		if buf.Len() > 0 {
			buf.WriteString("&")
		}
		buf.WriteString(k)
		buf.WriteString("=")
		buf.WriteString(v)
	}
	return buf.String()
}

// enableAutoVacuum enables incremental auto_vacuum on a SQLite database.
// This must be called before kine opens the database. If auto_vacuum is already
// set to incremental (2), this is a no-op. Otherwise it sets the pragma and runs
// a full VACUUM to convert the database (one-time cost).
func enableAutoVacuum(path string) error {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return fmt.Errorf("opening database for auto_vacuum: %w", err)
	}
	defer db.Close()

	var mode int
	if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil {
		return fmt.Errorf("querying auto_vacuum mode: %w", err)
	}
	if mode == 2 {
		slog.Info("SQLite auto_vacuum already set to incremental")
		return nil
	}

	slog.Info("Setting SQLite auto_vacuum to incremental", "current_mode", mode)
	if _, err := db.Exec("PRAGMA auto_vacuum = INCREMENTAL"); err != nil {
		return fmt.Errorf("setting auto_vacuum: %w", err)
	}
	// VACUUM is required to convert the database to the new auto_vacuum mode.
	if _, err := db.Exec("VACUUM"); err != nil {
		return fmt.Errorf("vacuuming database: %w", err)
	}
	slog.Info("SQLite auto_vacuum enabled successfully")
	return nil
}

// startIncrementalVacuum runs PRAGMA incremental_vacuum periodically to reclaim
// freelist pages. It opens a separate connection and stops on context cancellation.
func startIncrementalVacuum(ctx context.Context, path string, interval time.Duration) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		slog.Error("Failed to open database for incremental vacuum", "error", err)
		return
	}

	go func() {
		defer db.Close()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var freePages int
				if err := db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freePages); err != nil {
					if ctx.Err() != nil {
						return
					}
					slog.Error("Failed to query freelist_count", "error", err)
					continue
				}
				if freePages == 0 {
					continue
				}
				slog.Info("Running incremental vacuum", "freelist_pages", freePages)
				if _, err := db.ExecContext(ctx, "PRAGMA incremental_vacuum"); err != nil {
					if ctx.Err() != nil {
						return
					}
					slog.Error("Incremental vacuum failed", "error", err)
				}
			}
		}
	}()
}

// NewKineStorage creates a new kine storage.
// dbPath is the SQLite database file path (or "file::memory:" for in-memory).
// connArgs are SQLite connection parameters (e.g. {"cache": "shared", "_journal_mode": "WAL"}).
// logFormat should be "json" for production or "plain" for development.
func NewKineStorage(ctx context.Context, dbPath string, connArgs map[string]string, logFormat string) (rest.StoreFn, error) {
	// Skipped for in-memory DBs where there are no file pages to reclaim.
	if !strings.Contains(dbPath, ":memory:") {
		// Enable incremental auto_vacuum before kine opens the database.
		if err := enableAutoVacuum(dbPath); err != nil {
			return nil, fmt.Errorf("enabling auto_vacuum: %w", err)
		}
	}

	// Assemble the kine SQLite DSN.
	dsn := "sqlite://" + dbPath
	if args := encodeSQLiteConnArgs(connArgs); args != "" {
		dsn += "?" + args
	}
	slog.Debug("Using SQLite connection", "dsn", dsn)

	tmpDir := os.Getenv("KINE_TMPDIR")
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}
	etcdConfig, err := endpoint.Listen(ctx, endpoint.Config{
		Endpoint: dsn,
		Listener: "unix://" + tmpDir + "/apiserver-kine.sock",
		ConnectionPoolConfig: driversgeneric.ConnectionPoolConfig{
			MaxOpen: goruntime.NumCPU(),
		},
		MetricsRegisterer: metrics.Registry,
		// Default are defined in kine: https://github.com/k3s-io/kine/blob/0dc5b174a18cf13b299a2b597afe0608cd769663/pkg/app/app.go#L27
		NotifyInterval:      5 * time.Second,
		EmulatedETCDVersion: "3.5.13",
		CompactInterval:     5 * time.Minute,
		CompactTimeout:      5 * time.Second,
		CompactMinRetain:    1000,
		CompactBatchSize:    1000,
		PollBatchSize:       500,
		LogFormat:           logFormat,
	})
	if err != nil {
		return nil, err
	}

	// Start periodic incremental vacuum to reclaim freelist pages.
	// Skipped for in-memory DBs where there are no file pages to reclaim.
	if !strings.Contains(dbPath, ":memory:") {
		startIncrementalVacuum(ctx, dbPath, 5*time.Minute)
	}

	return func(scheme *runtime.Scheme, s *genericregistry.Store, options *generic.StoreOptions) {
		options.RESTOptions = &kineRESTOptionsGetter{
			scheme:         scheme,
			etcdConfig:     etcdConfig,
			groupVersioner: s.StorageVersioner,
		}
	}, nil
}

type kineRESTOptionsGetter struct {
	scheme         *runtime.Scheme
	etcdConfig     endpoint.ETCDConfig
	groupVersioner runtime.GroupVersioner
}

// GetRESTOptions implements generic.RESTOptionsGetter.
func (g *kineRESTOptionsGetter) GetRESTOptions(resource schema.GroupResource, _ runtime.Object) (generic.RESTOptions, error) {
	s := json.NewSerializer(json.DefaultMetaFactory, g.scheme, g.scheme, false)
	codec := serializer.NewCodecFactory(g.scheme).
		CodecForVersions(s, s, g.groupVersioner, g.groupVersioner)
	return generic.RESTOptions{
		ResourcePrefix:            resource.String(),
		Decorator:                 genericregistry.StorageWithCacher(),
		EnableGarbageCollection:   true,
		DeleteCollectionWorkers:   1,
		CountMetricPollPeriod:     time.Minute,
		StorageObjectCountTracker: request.NewStorageObjectCountTracker(),
		StorageConfig: &storagebackend.ConfigForResource{
			GroupResource: resource,
			Config: storagebackend.Config{
				Prefix: "/kine/",
				Codec:  codec,
				Transport: storagebackend.TransportConfig{
					ServerList:    g.etcdConfig.Endpoints,
					TrustedCAFile: g.etcdConfig.TLSConfig.CAFile,
					CertFile:      g.etcdConfig.TLSConfig.CertFile,
					KeyFile:       g.etcdConfig.TLSConfig.KeyFile,
				},
			},
		},
	}, nil
}
