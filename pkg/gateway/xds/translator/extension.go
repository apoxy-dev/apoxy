// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Extension.go contains functions to encapsulate all of the logic in handling interacting with
// Extensions for Envoy Gateway when performing xDS translation

package translator

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	"github.com/apoxy-dev/apoxy/pkg/log"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/gateway/proto/extension"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ExtensionServer encapsulates the logic for interacting with Extensions for
// Envoy Gateway when performing xDS translation.
type ExtensionServer struct {
	extension.EnvoyGatewayExtensionClient

	// conn is the underlying gRPC connection, used for RPCs not present in
	// the current version of the extension proto (e.g., PostClusterModify).
	conn grpc.ClientConnInterface

	// FailOpen indicates whether xDS translation should continue if an extension
	// fails to respond.
	FailOpen bool
}

type ExtensionServerOption func(*extensionServerOptions)

type extensionServerOptions struct {
	FailOpen bool
	Creds    credentials.TransportCredentials
}

// WithExtensionFailOpen sets the fail open option for the extension server.
func WithExtensionFailOpen(failOpen bool) func(*extensionServerOptions) {
	return func(opts *extensionServerOptions) {
		opts.FailOpen = failOpen
	}
}

// WithExtensionCreds sets the credentials for the extension server.
func WithExtensionCreds(creds credentials.TransportCredentials) func(*extensionServerOptions) {
	return func(opts *extensionServerOptions) {
		opts.Creds = creds
	}
}

// NewExtensionServer dials the extension server at the given address and returns a new ExtensionServer instance.
func NewExtensionServer(addr string, opts ...ExtensionServerOption) (*ExtensionServer, error) {
	options := &extensionServerOptions{}
	for _, opt := range opts {
		opt(options)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(options.Creds))
	if err != nil {
		return nil, err
	}
	return &ExtensionServer{
		EnvoyGatewayExtensionClient: extension.NewEnvoyGatewayExtensionClient(conn),
		conn:                        conn,
		FailOpen:                    options.FailOpen,
	}, nil
}

func translateUnstructuredToUnstructuredBytes(e []*unstructured.Unstructured) ([]*extension.ExtensionResource, error) {
	extensionResourceBytes := []*extension.ExtensionResource{}
	for _, res := range e {
		if res != nil {
			unstructuredBytes, err := res.MarshalJSON()
			// This is probably a programming error, but just return the unmodified route if so.
			if err != nil {
				slog.Error("failed to marshal unstructured resource", "error", err)
				return nil, err
			}

			extensionResourceBytes = append(extensionResourceBytes,
				&extension.ExtensionResource{
					UnstructuredBytes: unstructuredBytes,
				},
			)
		}
	}
	return extensionResourceBytes, nil
}

func processExtensionPostListenerHook(
	ctx context.Context,
	tCtx *types.ResourceVersionTable,
	xdsListener *listenerv3.Listener,
	extensionRefs []*ir.UnstructuredRef,
	c extension.EnvoyGatewayExtensionClient,
) error {
	log := log.DefaultLogger

	unstructuredResources := make([]*unstructured.Unstructured, len(extensionRefs))
	for refIdx, ref := range extensionRefs {
		unstructuredResources[refIdx] = ref.Object
	}
	extensionResources, err := translateUnstructuredToUnstructuredBytes(unstructuredResources)
	if err != nil {
		return err
	}
	log.Info("Processing extension post listener hook", "listener", xdsListener.Name)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	resp, err := c.PostHTTPListenerModify(ctx,
		&extension.PostHTTPListenerModifyRequest{
			Listener: xdsListener,
			PostListenerContext: &extension.PostHTTPListenerExtensionContext{
				ExtensionResources: extensionResources,
			},
		},
	)
	if err != nil {
		return err
	}
	if resp.Listener != nil {
		// Use the resource table to update the listener with the modified version returned by the extension
		// We're assuming that Listener names are unique.
		if err := tCtx.AddOrReplaceXdsResource(
			resourcev3.ListenerType,
			resp.Listener,
			func(existing, new cachetypes.Resource) bool {
				oldListener := existing.(*listenerv3.Listener)
				newListener := new.(*listenerv3.Listener)
				if newListener == nil || oldListener == nil {
					return false
				}
				if oldListener.Name == newListener.Name {
					return true
				}
				return false
			},
		); err != nil {
			return err
		}
	}

	return nil
}

// TODO(APO-426): Remove these vendored types and use extension.PostClusterModifyRequest/Response
// directly once envoyproxy/gateway is upgraded to v1.5.0+ (blocked on apiserver-runtime k8s v0.33 compat).
//
// postClusterModifyRequest mirrors the PostClusterModifyRequest message from
// envoyproxy/gateway v1.5.0+ extension proto, vendored here to avoid a dep
// upgrade that cascades into incompatible k8s versions.
type postClusterModifyRequest struct {
	Cluster *clusterv3.Cluster `protobuf:"bytes,1,opt,name=cluster,proto3" json:"cluster,omitempty"`
}

func (m *postClusterModifyRequest) Reset()         { *m = postClusterModifyRequest{} }
func (m *postClusterModifyRequest) String() string  { return fmt.Sprintf("%+v", *m) }
func (m *postClusterModifyRequest) ProtoMessage()   {}

// postClusterModifyResponse mirrors the PostClusterModifyResponse message.
type postClusterModifyResponse struct {
	Cluster *clusterv3.Cluster `protobuf:"bytes,1,opt,name=cluster,proto3" json:"cluster,omitempty"`
}

func (m *postClusterModifyResponse) Reset()         { *m = postClusterModifyResponse{} }
func (m *postClusterModifyResponse) String() string  { return fmt.Sprintf("%+v", *m) }
func (m *postClusterModifyResponse) ProtoMessage()   {}

const postClusterModifyFullMethod = "/envoygateway.extension.EnvoyGatewayExtension/PostClusterModify"

// processExtensionPostClusterHook calls PostClusterModify on the extension
// server for each translated xDS cluster, allowing the extension to modify
// clusters in-place (e.g., to set per-project DNS resolver ports).
func processExtensionPostClusterHook(
	ctx context.Context,
	tCtx *types.ResourceVersionTable,
	conn grpc.ClientConnInterface,
) error {
	clusters := tCtx.XdsResources[resourcev3.ClusterType]
	if len(clusters) == 0 {
		return nil
	}

	log.DefaultLogger.Info("Processing extension post cluster hook", "clusters", len(clusters))

	for i, r := range clusters {
		cluster := r.(*clusterv3.Cluster)

		reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		resp := &postClusterModifyResponse{}
		err := conn.Invoke(reqCtx, postClusterModifyFullMethod, &postClusterModifyRequest{
			Cluster: cluster,
		}, resp)
		cancel()
		if err != nil {
			return err
		}
		if resp.Cluster != nil {
			tCtx.XdsResources[resourcev3.ClusterType][i] = resp.Cluster
		}
	}

	return nil
}
