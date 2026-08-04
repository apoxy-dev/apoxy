// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package runner

import (
	"context"
	"log/slog"
	"sync"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/message"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/translator"
	xdstypes "github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	xdsRuner = "xds-runner"
)

// PatchFunc changes the translated xDS resource table for one IR key. It runs
// before the table goes to the snapshot cache. Unlike the gRPC extension
// hooks, it runs in-process. It sees every resource type: clusters,
// endpoints, and listeners. An embedding process can thus rewrite clusters
// and add the matching EDS resources in one place. It runs on the
// translation path and must not block.
type PatchFunc func(key string, res *xdstypes.ResourceVersionTable)

type Config struct {
	Logger            *slog.Logger
	XdsIR             *message.XdsIR
	Xds               *message.Xds
	ProviderResources *message.ProviderResources
	// ExtensionServer is an optional extension server to send hooks
	// to during translation.
	ExtensionServer *translator.ExtensionServer
	// XdsPatch, when set, runs on every translation result before it is
	// published.
	XdsPatch PatchFunc
	// Retranslate runs translation again for every known IR key when
	// signaled. This also runs the extension hooks and XdsPatch again. No
	// Gateway-API resource has to change. Embedders use it when data those
	// hooks read, such as endpoint sets or latency ranks, changes out of
	// band. The message bus and the snapshot cache both discard unchanged
	// output. A spurious signal thus causes no Envoy churn.
	Retranslate <-chan struct{}
}

type Runner struct {
	Config

	// translateMu serializes translateAndStore between the IR subscription
	// and the retranslate loop. Without it, two translations of the same key
	// can race their Store calls. The last write then wins with a stale
	// value.
	translateMu sync.Mutex
}

func New(cfg *Config) *Runner {
	return &Runner{Config: *cfg}
}

func (r *Runner) Name() string {
	return xdsRuner
}

// Start starts the xds-translator runner
func (r *Runner) Start(ctx context.Context) (err error) {
	r.Logger = log.DefaultLogger.With("runner", r.Name())
	go r.subscribeAndTranslate(ctx)
	if r.Retranslate != nil {
		go r.handleRetranslate(ctx)
	}
	r.Logger.Info("Started")
	return
}

// handleRetranslate runs translation again for every known IR key each time
// the Retranslate channel fires.
func (r *Runner) handleRetranslate(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.Retranslate:
		}
		for key, val := range r.XdsIR.LoadAll() {
			if err := r.translateAndStore(ctx, key, val); err != nil {
				r.Logger.Error("Failed to retranslate xds ir", "key", key, "error", err)
			}
		}
	}
}

// translateAndStore runs xDS translation for one IR key and publishes the
// result, or returns the translation error. A nil/empty result is a no-op:
// translation is best-effort and may legitimately yield no resources.
func (r *Runner) translateAndStore(ctx context.Context, key string, val *ir.Xds) error {
	r.translateMu.Lock()
	defer r.translateMu.Unlock()
	t := &translator.Translator{Ctx: ctx, ExtensionServer: r.ExtensionServer}
	result, err := t.Translate(val)
	if err != nil {
		return err
	}
	if result == nil || result.XdsResources == nil {
		return nil
	}
	if r.XdsPatch != nil {
		r.XdsPatch(key, result)
	}
	r.Xds.Store(key, result)
	return nil
}

func (r *Runner) subscribeAndTranslate(ctx context.Context) {
	// Subscribe to resources
	message.HandleSubscription(
		message.Metadata{Runner: r.Name(), Message: "xds-ir"},
		r.XdsIR.Subscribe(ctx),
		func(update message.Update[string, *ir.Xds], errChan chan error) {
			r.Logger.Info("Received an update", "key", update.Key, "isDelete", update.Delete, "isNil", update.Value == nil)
			key := update.Key
			val := update.Value

			if update.Delete {
				r.Xds.Delete(key)
			} else {
				// The full IR dump is Debug-only — at Info it is a 100KB+ line
				// on every bus update.
				r.Logger.Debug("Translating xds ir", "key", key, "xds", val)
				if err := r.translateAndStore(ctx, key, val); err != nil {
					r.Logger.Error("Failed to translate xds ir", "error", err)
					errChan <- err
					return
				}
			}
		},
	)
	r.Logger.Info("Subscriber shutting down")
}
