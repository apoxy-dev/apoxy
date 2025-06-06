// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package runner

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	runtimev3 "github.com/envoyproxy/go-control-plane/envoy/service/runtime/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"

	"github.com/apoxy-dev/apoxy/pkg/gateway/message"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/bootstrap"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/cache"
	xdstypes "github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/envoyproxy/gateway/api/v1alpha1"
)

const (
	// XdsServerAddress is the listening address of the xds-server.
	XdsServerAddress = "0.0.0.0"
	// xdsTLSCertFilename is the fully qualified path of the file containing the
	// xDS server TLS certificate.
	xdsTLSCertFilename = "/certs/tls.crt"
	// xdsTLSKeyFilename is the fully qualified path of the file containing the
	// xDS server TLS key.
	xdsTLSKeyFilename = "/certs/tls.key"
	// xdsTLSCaFilename is the fully qualified path of the file containing the
	// xDS server trusted CA certificate.
	xdsTLSCaFilename = "/certs/ca.crt"
)

type Config struct {
	Xds    *message.Xds
	grpc   *grpc.Server
	cache  cache.SnapshotCacheWithCallbacks
	Logger *slog.Logger
}

type Runner struct {
	Config
}

func New(cfg *Config) *Runner {
	return &Runner{Config: *cfg}
}

func (r *Runner) Name() string {
	return string(v1alpha1.LogComponentXdsServerRunner)
}

// Start starts the xds-server runner
func (r *Runner) Start(ctx context.Context) (err error) {
	r.Logger = log.DefaultLogger.With("runner", r.Name())

	// Set up the gRPC server and register the xDS handler.
	// Create SnapshotCache before start subscribeAndTranslate,
	// prevent panics in case cache is nil.
	// cfg := r.tlsConfig(xdsTLSCertFilename, xdsTLSKeyFilename, xdsTLSCaFilename)
	// TODO(dilyevsky): Use supplied x509 key pair and CA certificate.
	r.grpc = grpc.NewServer(
		//grpc.Creds(credentials.NewTLS(cfg)),
		grpc.Creds(insecure.NewCredentials()),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             15 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	r.cache = cache.NewSnapshotCache(true, r.Logger)
	registerServer(serverv3.NewServer(ctx, r.cache, r.cache), r.grpc)

	// Start and listen xDS gRPC Server.
	go r.serveXdsServer(ctx)

	// Start message Subscription.
	go r.subscribeAndTranslate(ctx)
	r.Logger.Info("started")
	return
}

func (r *Runner) serveXdsServer(ctx context.Context) {
	addr := net.JoinHostPort(XdsServerAddress, strconv.Itoa(bootstrap.DefaultXdsServerPort))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		r.Logger.Error("failed to listen on address", "address", addr, "error", err)
		return
	}

	go func() {
		<-ctx.Done()
		r.Logger.Info("grpc server shutting down")
		// We don't use GracefulStop here because envoy
		// has long-lived hanging xDS requests. There's no
		// mechanism to make those pending requests fail,
		// so we forcibly terminate the TCP sessions.
		r.grpc.Stop()
	}()

	if err = r.grpc.Serve(l); err != nil {
		r.Logger.Error("failed to start grpc based xds server", "error", err)
	}
}

// registerServer registers the given xDS protocol Server with the gRPC
// runtime.
func registerServer(srv serverv3.Server, g *grpc.Server) {
	// register services
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(g, srv)
	secretv3.RegisterSecretDiscoveryServiceServer(g, srv)
	clusterv3.RegisterClusterDiscoveryServiceServer(g, srv)
	endpointv3.RegisterEndpointDiscoveryServiceServer(g, srv)
	listenerv3.RegisterListenerDiscoveryServiceServer(g, srv)
	routev3.RegisterRouteDiscoveryServiceServer(g, srv)
	runtimev3.RegisterRuntimeDiscoveryServiceServer(g, srv)
}

func (r *Runner) subscribeAndTranslate(ctx context.Context) {
	// Subscribe to resources
	message.HandleSubscription(
		message.Metadata{
			Runner:  string(v1alpha1.LogComponentXdsServerRunner),
			Message: "xds",
		},
		r.Xds.Subscribe(ctx),
		func(update message.Update[string, *xdstypes.ResourceVersionTable], errChan chan error) {
			r.Logger.Info("received an update", "key", update.Key, "isDelete", update.Delete, "isNil", update.Value == nil)
			key := update.Key
			val := update.Value

			var err error
			if update.Delete {
				err = r.cache.GenerateNewSnapshot(key, nil)
			} else if val != nil && val.XdsResources != nil {
				if r.cache == nil {
					err = errors.New("snapshot cache is nil")
					r.Logger.Error("failed to init snapshot cache", "error", err)
					errChan <- err
					return
				}

				r.Logger.Info("generating a new snapshot", "key", key, "resources", val.XdsResources)
				// Update snapshot cache
				err = r.cache.GenerateNewSnapshot(key, val.XdsResources)
			}
			if err != nil {
				r.Logger.Error("failed to generate a snapshot", "error", err)
				errChan <- err
			}
		},
	)

	r.Logger.Info("subscriber shutting down")
}

func (r *Runner) tlsConfig(cert, key, ca string) *tls.Config {
	loadConfig := func() (*tls.Config, error) {
		cert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}

		// Load the CA cert.
		ca, err := os.ReadFile(ca)
		if err != nil {
			return nil, err
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certPool,
			MinVersion:   tls.VersionTLS13,
		}, nil
	}

	// Attempt to load certificates and key to catch configuration errors early.
	if _, lerr := loadConfig(); lerr != nil {
		r.Logger.Error("failed to load certificate and key", "error", lerr)
	}
	r.Logger.Info("loaded TLS certificate and key")

	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		Rand:       rand.Reader,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return loadConfig()
		},
	}
}
