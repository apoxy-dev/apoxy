package controllers

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy/pkg/backplane/envoy"
	"github.com/apoxy-dev/apoxy/pkg/backplane/logs"
	"github.com/apoxy-dev/apoxy/pkg/backplane/otel"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/bootstrap"
	xdstypes "github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

const (
	proxyReplicaPendingTimeout = 5 * time.Minute
)

var _ reconcile.Reconciler = &ProxyReconciler{}

// ProxyReconciler reconciles a Proxy object.
type ProxyReconciler struct {
	client.Client
	envoy.Runtime

	proxyName     string
	replicaName   string
	privateAddr   netip.Addr
	apiServerHost string

	options *options
}

type options struct {
	chConn                       clickhouse.Conn
	chOpts                       *clickhouse.Options
	apiServerTLSClientConfig     *tls.Config
	goPluginDir                  string
	releaseURL                   string
	useEnvoyContrib              bool
	overloadMaxHeapSizeBytes     *uint64
	overloadMaxActiveConnections *uint64
}

// Option is a functional option for ProxyReconciler.
type Option func(*options)

// WithClickHouseConn sets the ClickHouse connection for the ProxyReconciler.
// If not set, log shipping will be disabled.
func WithClickHouseConn(chConn clickhouse.Conn) Option {
	return func(o *options) {
		o.chConn = chConn
	}
}

// WithClickHouseOptions sets the ClickHouse options for the ProxyReconciler.
func WithClickHouseOptions(opts *clickhouse.Options) Option {
	return func(o *options) {
		o.chOpts = opts
	}
}

// WithAPIServerTLSClientConfig sets the TLS client configuration for the API server.
// If not set, the client will use an insecure connection.
func WithAPIServerTLSClientConfig(tlsConfig *tls.Config) Option {
	return func(o *options) {
		o.apiServerTLSClientConfig = tlsConfig
	}
}

// WithGoPluginDir sets the directory for Go plugins.
func WithGoPluginDir(dir string) Option {
	return func(o *options) {
		o.goPluginDir = dir
	}
}

// WithURLRelease enables the use of URL release. (Default is GitHub release).
func WithURLRelease(url string) Option {
	return func(o *options) {
		o.releaseURL = url
	}
}

// WithEnvoyContrib enables the use of Envoy contrib filters.
func WithEnvoyContrib() Option {
	return func(o *options) {
		o.useEnvoyContrib = true
	}
}

// WithOverloadMaxHeapSizeBytes sets the maximum heap size in bytes for the Envoy overload manager.
func WithOverloadMaxHeapSizeBytes(size uint64) Option {
	return func(o *options) {
		o.overloadMaxHeapSizeBytes = &size
	}
}

// WithOverloadMaxActiveConnections sets the maximum number of active downstream connections for the Envoy overload manager.
func WithOverloadMaxActiveConnections(count uint64) Option {
	return func(o *options) {
		o.overloadMaxActiveConnections = &count
	}
}

func defaultOptions() *options {
	return &options{}
}

// NewProxyReconciler returns a new reconcile.Reconciler implementation for the Proxy resource.
func NewProxyReconciler(
	c client.Client,
	proxyName string,
	replicaName string,
	privateAddr netip.Addr,
	apiServerHost string,
	opts ...Option,
) *ProxyReconciler {
	sOpts := defaultOptions()
	for _, opt := range opts {
		opt(sOpts)
	}

	return &ProxyReconciler{
		Client:        c,
		proxyName:     proxyName,
		replicaName:   replicaName,
		privateAddr:   privateAddr,
		apiServerHost: apiServerHost,
		options:       sOpts,
	}
}

func findReplicaStatus(p *corev1alpha2.Proxy, rname string) (*corev1alpha2.ProxyReplicaStatus, bool) {
	for i := range p.Status.Replicas {
		if p.Status.Replicas[i].Name == rname {
			return p.Status.Replicas[i], true
		}
	}
	return nil, false
}

func (r *ProxyReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	p := &corev1alpha2.Proxy{}
	err := r.Get(ctx, request.NamespacedName, p)
	if errors.IsNotFound(err) {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if err != nil {
		return reconcile.Result{}, err
	}

	logger := slog.With("app", string(p.UID), "name", p.Name, "replica", r.replicaName)

	ps := r.RuntimeStatus()

	if !p.ObjectMeta.DeletionTimestamp.IsZero() { // The object is being deleted
		logger.Info("Proxy is being deleted")

		if ps.Running {
			logger.Info("Proxy is being stopped")
			go func() {
				if err := r.Runtime.Shutdown(ctx); err != nil {
					logger.Error("failed to shutdown runtime", "error", err)
				}
			}()
		}

		return ctrl.Result{}, nil // Deleted.
	}

	// Envoy runtime was never started:
	//   1. Initialize and start the runtime restart loop.
	//   2. Create a new replica status entry and update status.
	//
	//  If status update fails, it can be
	if ps.StartedAt.IsZero() {
		logger.Info("Starting Proxy runtime")

		bsOpts := []bootstrap.BootstrapOption{
			bootstrap.WithXdsServerHost(r.apiServerHost),
			// TODO(dilyevsky): Add TLS config from r.options.apiServerTLSConfig.
		}

		if r.options.overloadMaxHeapSizeBytes != nil {
			bsOpts = append(bsOpts, bootstrap.WithOverloadMaxHeapSizeBytes(*r.options.overloadMaxHeapSizeBytes))
		}

		if r.options.overloadMaxActiveConnections != nil {
			bsOpts = append(bsOpts, bootstrap.WithOverloadMaxActiveConnections(*r.options.overloadMaxActiveConnections))
		}
		cfg, err := bootstrap.GetRenderedBootstrapConfig(bsOpts...)
		if err != nil {
			// If the config is invalid, we can't start the proxy.
			logger.Error("failed to validate proxy config", "error", err)
			return reconcile.Result{}, nil
		}

		// TODO(dilyevsky): Pass these values from the Proxy object.
		adminHost := bootstrap.EnvoyAdminAddress + ":" + strconv.Itoa(bootstrap.EnvoyAdminPort)
		opts := []envoy.Option{
			envoy.WithBootstrapConfigYAML(cfg),
			envoy.WithCluster(p.Name),
			envoy.WithGoPluginDir(r.options.goPluginDir),
			envoy.WithDrainTimeout(&p.Spec.Shutdown.DrainTimeout.Duration),
			envoy.WithMinDrainTime(&p.Spec.Shutdown.MinimumDrainTime.Duration),
			envoy.WithAdminHost(adminHost),
			envoy.WithLogsDir("/var/log/apoxy"),
			envoy.WithNodeMetadata(&xdstypes.NodeMetadata{
				Name:           r.replicaName,
				PrivateAddress: r.privateAddr.String(),
			}),
		}
		if r.options.releaseURL != "" {
			opts = append(opts, envoy.WithRelease(&envoy.URLRelease{
				URL: r.options.releaseURL,
			}))
		} else if r.options.useEnvoyContrib {
			opts = append(opts, envoy.WithRelease(&envoy.GitHubRelease{
				Contrib: true,
			}))
		}

		if p.Spec.Telemetry != nil {
			if p.Spec.Telemetry.Tracing != nil && p.Spec.Telemetry.Tracing.Enabled {
				logger.Info("Enabling tracing")
				opts = append(opts, envoy.WithOtelCollector(&otel.Collector{
					ClickHouseOpts: r.options.chOpts,
				}))
			}
		}

		if r.options.chConn != nil {
			pUUID, _ := uuid.Parse(string(p.UID))
			lc := logs.NewClickHouseLogsCollector(r.options.chConn, pUUID)
			opts = append(opts, envoy.WithLogsCollector(lc))
		}

		if err := r.Start(ctx, opts...); err != nil {
			if fatalErr, ok := err.(envoy.FatalError); ok {
				logger.Error("failed to create proxy replica", "error", fatalErr)

				return reconcile.Result{}, nil // Leave the proxy in failed state.
			}

			return reconcile.Result{}, fmt.Errorf("failed to create proxy: %w", err)
		}

		logger.Info("Started Envoy")

		// Requeue after a short delay to check the status of the proxy.
		return reconcile.Result{RequeueAfter: 2 * time.Second}, nil
	}

	// Find the proxy replica by name.
	rs, found := findReplicaStatus(p, r.replicaName)
	if !found {
		logger.Error("failed to find proxy replica", "name", r.replicaName)

		// Requeue again and check in a bit if replica is created (on connection to xDS server).
		// TODO(dilyevsky): Eventually we should do something more like killing the process
		// if the proxy replica never connects.
		return reconcile.Result{RequeueAfter: 2 * time.Second}, nil
	}

	logger.Info("Proxy replica found", "name", r.replicaName, "connectedAt", rs.ConnectedAt)

	return reconcile.Result{}, nil
}

func namePredicate(name string) predicate.Funcs {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj == nil {
			return false
		}

		p, ok := obj.(*corev1alpha2.Proxy)
		if !ok {
			return false
		}

		return name == p.Name
	})
}

func (r *ProxyReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	err := mgr.GetFieldIndexer().IndexField(ctx, &corev1alpha2.Proxy{}, "metadata.name", func(rawObj client.Object) []string {
		p := rawObj.(*corev1alpha2.Proxy)
		return []string{p.Name}
	})
	if err != nil {
		return fmt.Errorf("failed to set up field indexer: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.Proxy{},
			builder.WithPredicates(
				&predicate.ResourceVersionChangedPredicate{},
				namePredicate(r.proxyName),
			),
		).
		Complete(r)
}

func (r *ProxyReconciler) DownloadEnvoy(ctx context.Context) error {
	opts := []envoy.Option{
		envoy.WithGoPluginDir(r.options.goPluginDir),
	}
	if r.options.releaseURL != "" {
		opts = append(opts, envoy.WithRelease(&envoy.URLRelease{
			URL: r.options.releaseURL,
		}))
	} else if r.options.useEnvoyContrib {
		opts = append(opts, envoy.WithRelease(&envoy.GitHubRelease{
			Contrib: true,
		}))
	}

	if err := r.Runtime.Start(ctx, opts...); err != nil {
		return fmt.Errorf("failed to start Envoy runtime: %w", err)
	}
	if err := r.Runtime.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown Envoy runtime: %w", err)
	}
	return nil
}
