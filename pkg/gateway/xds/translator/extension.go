// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Extension.go contains functions to encapsulate all of the logic in handling interacting with
// Extensions for Envoy Gateway when performing xDS translation

package translator

import (
	"context"
	"log/slog"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	"github.com/envoyproxy/gateway/proto/extension"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type ExtensionServer struct {
	extension.EnvoyGatewayExtensionClient

	// FailOpen indicates whether xDS translation should continue if an extension fails to respond.
	FailOpen bool
}

type ExtensionServerOption func(*extensionServerOptions)

type extensionServerOptions struct {
	FailOpen bool
}

func WithFailOpen(failOpen bool) func(*extensionServerOptions) {
	return func(opts *extensionServerOptions) {
		opts.FailOpen = failOpen
	}
}

// NewExtensionServer dials the extension server at the given address and returns a new ExtensionServer instance.
func NewExtensionServer(addr string, opts ...ExtensionServerOption) (*ExtensionServer, error) {
	conn, err := grpc.NewClient(addr)
	if err != nil {
		return nil, err
	}
	options := &extensionServerOptions{}
	for _, opt := range opts {
		opt(options)
	}
	return &ExtensionServer{
		EnvoyGatewayExtensionClient: extension.NewEnvoyGatewayExtensionClient(conn),
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
	if c == nil {
		return nil
	}

	unstructuredResources := make([]*unstructured.Unstructured, len(extensionRefs))
	for refIdx, ref := range extensionRefs {
		unstructuredResources[refIdx] = ref.Object
	}
	extensionResources, err := translateUnstructuredToUnstructuredBytes(unstructuredResources)
	if err != nil {
		return err
	}
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
