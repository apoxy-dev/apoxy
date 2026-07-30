package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/apoxy-dev/icx"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/conntrackpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

// connectAllRedialInterval paces re-dials of a desired relay whose session
// ended (relay crash, transient network failure). Deliberately short: while
// a consumer is disconnected from a relay, every agent homed on ONLY that
// relay is unreachable from this consumer.
var connectAllRedialInterval = 5 * time.Second

// runConnectAll maintains one live session per relay address in the pool,
// tracking pool refreshes: an address appearing spawns a session runner, an
// address disappearing stops the runner's re-dial. A live session is never
// killed on removal — a draining relay deregisters at drain start but keeps
// forwarding through its lame duck, so the session is left to end on its own
// (the drain grace bounds it).
//
// This is the connection policy for relay CONSUMERS (backplane VTEP
// sessions): relays do not federate routes, so reaching agents homed on any
// relay requires a session to every relay. Agents themselves use the
// MinConns slot policy instead.
func runConnectAll(
	ctx context.Context,
	cfg Config,
	pcQuicMux *conntrackpc.ConntrackPacketConn,
	handler *icx.Handler,
	r router.Router,
	routes *routeReconciler,
	seed sets.Set[string],
	tlsConf *tls.Config,
) error {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		desired = sets.New[string]()
		running = sets.New[string]()
	)

	isDesired := func(addr string) bool {
		mu.Lock()
		defer mu.Unlock()
		return desired.Has(addr)
	}

	// runRelay owns the session lifecycle for one relay address: dial, run
	// the session until it ends, re-dial while the address is still desired.
	runRelay := func(addr string) {
		defer func() {
			mu.Lock()
			running.Delete(addr)
			mu.Unlock()
		}()
		for {
			run := startSessionRun(ctx, cfg, pcQuicMux, handler, r, routes, addr, tlsConf)
			select {
			case <-ctx.Done():
				run.cancel()
				<-run.done
				return
			case err := <-run.done:
				run.cancel()
				if err != nil && !errors.Is(err, context.Canceled) {
					slog.Warn("Relay session ended",
						slog.String("relay", addr), slog.Any("error", err))
				}
			}
			// The relay deregistering (drain, scale-down) ends the re-dial;
			// a replacement re-registering — often at the same address, a
			// restarted hostNetwork pod keeps its node IP — is picked up by
			// the next sync.
			if !isDesired(addr) {
				slog.Info("Relay no longer registered; not re-dialing",
					slog.String("relay", addr))
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(connectAllRedialInterval):
			}
		}
	}

	// sync reconciles the desired set: spawns runners for new addresses.
	// Runners for removed addresses exit on their own (see runRelay); sync
	// runs every refresh tick, so a runner that exited between ticks while
	// its address became desired again is respawned within one interval.
	sync := func(addrs sets.Set[string]) {
		mu.Lock()
		defer mu.Unlock()
		desired = addrs
		for addr := range addrs {
			if running.Has(addr) {
				continue
			}
			running.Insert(addr)
			wg.Add(1)
			go func(a string) {
				defer wg.Done()
				runRelay(a)
			}(addr)
		}
	}

	sync(seed)

	if cfg.RelayLister != nil {
		ticker := time.NewTicker(relayRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				wg.Wait()
				return ctx.Err()
			case <-ticker.C:
				listCtx, cancel := context.WithTimeout(ctx, relayRefreshInterval)
				addrs, err := cfg.RelayLister(listCtx)
				cancel()
				if err != nil {
					slog.Warn("Failed to refresh relay list; keeping current set", slog.Any("error", err))
					continue
				}
				// An empty list is trusted here, unlike the slot pool: a
				// consumer must drop relays that deregistered, and its
				// runners keep re-dialing nothing otherwise.
				sync(addrs)
			}
		}
	}

	<-ctx.Done()
	wg.Wait()
	return ctx.Err()
}
