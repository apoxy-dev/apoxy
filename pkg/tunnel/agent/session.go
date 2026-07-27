package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/psp"
	"github.com/avast/retry-go/v4"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/conntrackpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/randalloc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

type bootstrapInfo struct {
	Connect *api.ConnectResponse
}

// bootstrapSession connects to the seed relay, retrieves tunnel config and
// the relay address pool, disconnects, and returns that bootstrap data.
func bootstrapSession(
	ctx context.Context,
	cfg Config,
	seedRelayAddr string,
	pcQuicMux *conntrackpc.ConntrackPacketConn,
	tlsConf *tls.Config,
) (*bootstrapInfo, error) {
	seedAddr := strings.TrimSpace(seedRelayAddr)

	seedResolved, err := resolveAddrPort(ctx, seedAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve seed relay addr %q: %w", seedAddr, err)
	}

	seedPcQuic, err := pcQuicMux.Open(&net.UDPAddr{
		IP:   seedResolved.Addr().AsSlice(),
		Port: int(seedResolved.Port()),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create multiplexed packet conn for seed relay %q: %w", seedAddr, err)
	}
	defer seedPcQuic.Close()

	client, err := api.NewClient(api.ClientOptions{
		BaseURL:          (&url.URL{Scheme: "https", Host: seedAddr}).String(),
		Agent:            cfg.Agent,
		TunnelName:       cfg.Network,
		Token:            cfg.Token,
		TLSConfig:        tlsConf,
		PacketConn:       seedPcQuic,
		Labels:           cfg.Labels,
		AdvertisedRoutes: cfg.AdvertisedRoutes,
		AgentInstance:    cfg.Instance,
	})
	if err != nil {
		return nil, fmt.Errorf("create seed API client: %w", err)
	}
	defer client.Close()

	slog.Info("Bootstrapping against seed relay", slog.String("relay", seedAddr))

	connectResp, err := client.Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("bootstrap connect to seed relay %q: %w", seedAddr, err)
	}

	// We're only using this connection for discovery. Close it gracefully.
	if err := client.Disconnect(ctx, connectResp.ID); err != nil {
		slog.Warn("Failed to disconnect bootstrap session",
			slog.String("id", connectResp.ID),
			slog.Any("error", err))
	}

	return &bootstrapInfo{Connect: connectResp}, nil
}

// connectAndInitSession dials the relay, runs Connect, and returns the live
// api.Client, the ConnectResponse, and the handler. It also wires the relay
// into the handler via AddVirtualNetwork.
func connectAndInitSession(
	ctx context.Context,
	cfg Config,
	pcQuic net.PacketConn,
	handler *icx.Handler,
	relayAddr string,
	tlsConf *tls.Config,
) (*api.Client, *api.ConnectResponse, *icx.Handler, error) {
	client, err := api.NewClient(api.ClientOptions{
		BaseURL:          (&url.URL{Scheme: "https", Host: relayAddr}).String(),
		Agent:            cfg.Agent,
		TunnelName:       cfg.Network,
		Token:            cfg.Token,
		TLSConfig:        tlsConf,
		PacketConn:       pcQuic,
		Labels:           cfg.Labels,
		AdvertisedRoutes: cfg.AdvertisedRoutes,
		AgentInstance:    cfg.Instance,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create API client: %w", err)
	}

	cleanupOnErr := func(e error) (*api.Client, *api.ConnectResponse, *icx.Handler, error) {
		_ = client.Close()
		return nil, nil, nil, e
	}

	slog.Info("Connecting to relay", slog.String("relay", relayAddr))

	connectResp, err := client.Connect(ctx)
	if err != nil {
		return cleanupOnErr(fmt.Errorf("connect to relay: %w", err))
	}

	remoteAddr, err := resolveAddrPort(ctx, relayAddr)
	if err != nil {
		return cleanupOnErr(fmt.Errorf("resolve relay addr %q: %w", relayAddr, err))
	}

	overlayAddrs, err := parsePrefixes(connectResp.Addresses)
	if err != nil {
		return cleanupOnErr(fmt.Errorf("parse assigned addresses: %w", err))
	}

	if err := handler.AddVirtualNetwork(
		connectResp.VNI,
		netstack.ToFullAddress(remoteAddr),
		buildAllowedRoutes(overlayAddrs, parseRouteSet(connectResp.Routes)),
	); err != nil {
		return cleanupOnErr(fmt.Errorf("add virtual network: %w", err))
	}

	slog.Info("Connected to relay",
		slog.String("relay", relayAddr),
		slog.String("id", connectResp.ID),
		slog.Int("vni", int(connectResp.VNI)),
		slog.Int("mtu", connectResp.MTU),
	)

	return client, connectResp, handler, nil
}

// closeSession best-effort disconnect + close of an active session.
func closeSession(client *api.Client, connID string) {
	if client == nil || connID == "" {
		return
	}
	disconnectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Disconnect(disconnectCtx, connID); err != nil {
		slog.Error("Failed to disconnect from tunnel",
			slog.String("id", connID),
			slog.Any("error", err))
	}
	slog.Info("Disconnected from tunnel", slog.String("id", connID))
	_ = client.Close()
}

// manageRelayConnectionOnce establishes and maintains a single relay session
// to the specified relayAddr over pcQuic. It will:
//
//   - retry Connect() until it succeeds or ctx is canceled
//   - once connected, run key rotation and watchdog concurrently
//   - whichever fails first ends the session
func manageRelayConnectionOnce(
	ctx context.Context,
	cfg Config,
	pcQuic net.PacketConn,
	handler *icx.Handler,
	r router.Router,
	relayAddr string,
	tlsConf *tls.Config,
) error {
	var (
		currentClient *api.Client
		currentConnID string
		connectResp   *api.ConnectResponse
		sessionAddrs  []netip.Prefix
	)

	// When this function returns, that relay session is down, so decrement
	// if we had actually marked it active.
	defer func() {
		// Remove this session's virtual network from the handler so its routes
		// are freed from the route trie. Without this, a reconnect that is
		// assigned a fresh VNI but the same overlay address collides with the
		// dead session's leftover routes ("already routed to VNI N") and the
		// agent churns indefinitely, never re-establishing the tunnel.
		if connectResp != nil {
			if err := handler.RemoveVirtualNetwork(connectResp.VNI); err != nil {
				slog.Warn("Failed to remove virtual network on disconnect",
					slog.Int("vni", int(connectResp.VNI)),
					slog.Any("error", err))
			}
		}
		// Remove any addrs we attached for this session.
		for _, a := range sessionAddrs {
			if err := r.DelAddr(a); err != nil {
				slog.Warn("Failed to remove address on disconnect",
					slog.String("address", a.String()),
					slog.Any("error", err))
			} else {
				slog.Info("Removed address", slog.String("address", a.String()))
			}
		}
		if currentConnID != "" {
			connectionHealthCounter.Add(-1)
		}
		closeSession(currentClient, currentConnID)
	}()

	// Keep retrying connect until context canceled.
	err := retry.Do(
		func() error {
			c, cr, _, err := connectAndInitSession(ctx, cfg, pcQuic, handler, relayAddr, tlsConf)
			if err != nil {
				return err
			}
			currentClient = c
			currentConnID = cr.ID
			connectResp = cr
			return nil
		},
		retry.Context(ctx),
		retry.OnRetry(func(n uint, err error) {
			slog.Warn("Reconnect attempt failed; backing off",
				slog.String("relay", relayAddr),
				slog.Uint64("attempt", uint64(n+1)),
				slog.Any("error", err))
		}),
		retry.LastErrorOnly(true),
	)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.Error("Failed to (re)connect to relay",
			slog.String("relay", relayAddr),
			slog.Any("error", err))
		return fmt.Errorf("failed to connect to relay %q: %w", relayAddr, err)
	}

	// Successful session establishment: mark this connection active.
	connectionHealthCounter.Add(1)

	// Parse and attach the assigned addresses for this live session.
	if connectResp != nil {
		addrs, err := parsePrefixes(connectResp.Addresses)
		if err != nil {
			slog.Warn("Failed to parse assigned addresses", slog.Any("error", err))
		} else {
			sessionAddrs = addrs
			for _, a := range addrs {
				if err := r.AddAddr(a, nil); err != nil {
					slog.Warn("Failed to add address",
						slog.String("address", a.String()),
						slog.Any("error", err))
				} else {
					slog.Info("Added address", slog.String("address", a.String()))
				}
			}
		}
	}

	// Once connected, run key rotation and watchdog concurrently.
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()

	g, gctx := errgroup.WithContext(sessionCtx)
	g.Go(func() error {
		return manageKeyRotation(
			gctx,
			handler,
			currentClient,
			currentConnID,
			connectResp.VNI,
			connectResp.Keys,
		)
	})
	g.Go(func() error {
		return manageRouteRefresh(
			gctx,
			handler,
			currentClient,
			r,
			currentConnID,
			connectResp.VNI,
			sessionAddrs,
			connectResp.Routes,
			cfg.TunMode,
		)
	})
	g.Go(func() error {
		return relayWatchdog(
			gctx,
			handler,
			connectResp.VNI,
			watchdogMaxSilence,
			watchdogInterval,
		)
	})

	// Wait for either goroutine to return an error.
	waitErr := g.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	if waitErr != nil && waitErr != context.Canceled {
		slog.Warn("Connection ended",
			slog.String("relay", relayAddr),
			slog.Any("error", waitErr))
	}
	return waitErr
}

// manageConnectionSlot owns one "connection slot" that we promised to keep
// active. It repeatedly:
//
//   - asks the relay address pool for an exclusive relay address
//   - opens a PacketConn to that relay
//   - runs manageRelayConnectionOnce
//   - when that session ends, releases the relay back to the pool
//
// If MinConns > number of relays, extra goroutines will block in Acquire()
// until another slot releases a relay. This enforces "no two sessions to the
// same relay address" at any instant.
func manageConnectionSlot(
	ctx context.Context,
	cfg Config,
	pcQuicMux *conntrackpc.ConntrackPacketConn,
	handler *icx.Handler,
	r router.Router,
	relayAddressPool *randalloc.RandAllocator[string],
	tlsConf *tls.Config,
) error {
	for {
		// Block here until we get exclusive rights to a relay,
		// or until ctx is canceled.
		relayAddr, err := relayAddressPool.Acquire(ctx)
		if err != nil {
			return err // ctx canceled, etc.
		}

		slog.Info("Acquired relay slot",
			slog.String("relay", relayAddr))

		// We'll run the session in an inner func so we can defer cleanup
		// (pcQuic.Close) per-session but still always Release() after.
		err = func() error {
			// Resolve relay -> concrete IP:port.
			relayAddrParsed, err := resolveAddrPort(ctx, relayAddr)
			if err != nil {
				slog.Warn("failed to resolve relay, will pick a new relay",
					slog.String("relay", relayAddr),
					slog.Any("error", err))
				return nil // we'll just loop and Acquire again
			}

			// Open per-relay PacketConn off the shared mux.
			pcQuic, err := pcQuicMux.Open(&net.UDPAddr{
				IP:   relayAddrParsed.Addr().AsSlice(),
				Port: int(relayAddrParsed.Port()),
			})
			if err != nil {
				slog.Warn("failed to create multiplexed packet conn for relay, will pick a new relay",
					slog.String("relay", relayAddr),
					slog.Any("error", err))
				return nil // loop again
			}

			// Make sure we close the PacketConn when the session ends.
			defer pcQuic.Close()

			// Run the actual session lifecycle (watchdog, key rotation, etc). The
			// relay pool is refreshed out-of-band by refreshRelayPool, so no
			// per-connect pool update is needed here.
			sessErr := manageRelayConnectionOnce(ctx, cfg, pcQuic, handler, r, relayAddr, tlsConf)

			if ctx.Err() != nil {
				return ctx.Err()
			}

			if sessErr != nil && !errors.Is(sessErr, context.Canceled) {
				slog.Warn("Connection to relay ended; rotating to a new relay",
					slog.String("relay", relayAddr),
					slog.Any("error", sessErr))
			}
			return nil
		}()

		// Release the relay for other slots before the next loop iteration.
		relayAddressPool.Release(relayAddr)

		if err != nil {
			return err
		}

		// loop: grab a (maybe different) relay next time
	}
}

// manageKeyRotation applies initial keys and refreshes at half-life with retry
// on failures.
func manageKeyRotation(
	ctx context.Context,
	handler *icx.Handler,
	client *api.Client,
	connID string,
	vni uint,
	initial api.Keys,
) error {
	// applyKeys installs one epoch's keys, failing closed if the relay handed back
	// nothing usable. The agent is the Initiator; the relay installs the mirrored
	// Responder SPIs, so each epoch derives one distinct key per direction.
	applyKeys := func(k api.Keys) error {
		if k.MasterSecret == (api.MasterSecret{}) {
			return errors.New("relay returned an empty master secret")
		}
		rxSPI, txSPI, err := psp.EpochSPIs(psp.Initiator, k.Epoch)
		if err != nil {
			return fmt.Errorf("derive SPIs for epoch %d: %w", k.Epoch, err)
		}
		if err := handler.UpdateVirtualNetworkSecret(vni, [32]byte(k.MasterSecret), rxSPI, txSPI, k.ExpiresAt); err != nil {
			return fmt.Errorf("apply keys to router: %w", err)
		}
		return nil
	}

	// retryInterval is how long to wait before re-fetching keys after a failed
	// apply — short, so a transient failure does not leave the tunnel unkeyed for
	// half a key lifespan.
	const retryInterval = 10 * time.Second

	applyAndSchedule := func(k api.Keys) time.Duration {
		if err := applyKeys(k); err != nil {
			slog.Error("Failed to apply rotated keys; retrying soon", slog.Any("error", err))
			return retryInterval
		}
		remaining := time.Until(k.ExpiresAt)
		next := remaining / 2
		if next < retryInterval {
			next = retryInterval
		}
		return next
	}

	next := applyAndSchedule(initial)
	timer := time.NewTimer(next)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-timer.C:
			var upd *api.UpdateKeysResponse
			err := retry.Do(
				func() error {
					var err error
					upd, err = client.UpdateKeys(ctx, connID)
					return err
				},
				retry.Context(ctx),
				retry.Attempts(0), // keep trying until ctx canceled
				retry.OnRetry(func(n uint, err error) {
					slog.Warn("Key update failed; backing off",
						slog.Uint64("attempt", uint64(n+1)),
						slog.Any("error", err))
				}),
				retry.LastErrorOnly(true),
			)
			if err != nil {
				return err
			}

			slog.Info("Rotated tunnel keys",
				slog.Uint64("epoch", uint64(upd.Keys.Epoch)))

			timer.Reset(applyAndSchedule(upd.Keys))
		}
	}
}

// routeRefreshInterval paces polling of the relay's route set. Routes only
// change when agents (dis)connect, so this trades a small steady-state cost
// for bounded staleness of transit routes on long-lived sessions.
const routeRefreshInterval = 30 * time.Second

// manageRouteRefresh polls the relay for the connection's current route set
// and reconciles the local router and the VNI's cryptokey allowed-routes with
// it. The ConnectResponse route list is only a snapshot: CIDRs advertised by
// agents that connect later (e.g. a --route private subnet appearing behind a
// new agent) never reach an already-established session without this.
func manageRouteRefresh(
	ctx context.Context,
	handler *icx.Handler,
	client *api.Client,
	rt router.Router,
	connID string,
	vni uint,
	overlayAddrs []netip.Prefix,
	initial []api.Route,
	tunMode bool,
) error {
	current := parseRouteSet(initial)

	ticker := time.NewTicker(routeRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		resp, err := client.Routes(ctx, connID)
		if err != nil {
			slog.Warn("Failed to refresh relay routes", slog.Any("error", err))
			continue
		}
		desired := parseRouteSet(resp.Routes)
		if desired.Equal(current) {
			continue
		}

		// Reconcile the datapath routes. Default routes are a netstack-only
		// facility (see initRouter) and are never installed on a TUN device.
		installable := func(dst netip.Prefix) bool { return !tunMode || dst.Bits() != 0 }
		for dst := range desired.Difference(current) {
			if !installable(dst) {
				continue
			}
			slog.Info("Adding route", slog.String("destination", dst.String()))
			if err := rt.AddRoute(dst); err != nil {
				slog.Warn("Failed to add route", slog.String("prefix", dst.String()), slog.Any("error", err))
			}
		}
		for dst := range current.Difference(desired) {
			if !installable(dst) {
				continue
			}
			slog.Info("Removing route", slog.String("destination", dst.String()))
			if err := rt.DelRoute(dst); err != nil {
				slog.Warn("Failed to remove route", slog.String("prefix", dst.String()), slog.Any("error", err))
			}
		}

		// Replace the VNI's allowed-route set to match the connect-time
		// programming.
		if err := handler.UpdateVirtualNetworkRoutes(vni, buildAllowedRoutes(overlayAddrs, desired)); err != nil {
			slog.Warn("Failed to update allowed routes", slog.Any("error", err))
		}

		current = desired
	}
}

// parseRouteSet parses API routes into a prefix set, dropping unparseable
// entries with a warning.
func parseRouteSet(routes []api.Route) sets.Set[netip.Prefix] {
	set := sets.New[netip.Prefix]()
	for _, rt := range routes {
		dst, err := netip.ParsePrefix(rt.Destination)
		if err != nil {
			slog.Warn("Failed to parse route prefix",
				slog.String("prefix", rt.Destination),
				slog.Any("error", err))
			continue
		}
		set.Insert(dst)
	}
	return set
}

// buildAllowedRoutes expands the overlay-address × destination cross-product
// into the VNI's cryptokey allowed-route set. Connect-time programming and
// the post-connect route refresh both go through here so the two never
// diverge.
func buildAllowedRoutes(overlayAddrs []netip.Prefix, dsts sets.Set[netip.Prefix]) []icx.Route {
	routes := make([]icx.Route, 0, len(overlayAddrs)*dsts.Len())
	for dst := range dsts {
		for _, addr := range overlayAddrs {
			routes = append(routes, icx.Route{Src: addr, Dst: dst})
		}
	}
	return routes
}

// relayWatchdog monitors RX silence for a specific VNI and returns an error if
// we haven't received any packet from the remote in maxSilence.
// It polls at checkInterval and exits if ctx is canceled.
func relayWatchdog(
	ctx context.Context,
	handler *icx.Handler,
	vni uint,
	maxSilence time.Duration,
	checkInterval time.Duration,
) error {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			vnet, ok := handler.GetVirtualNetwork(vni)
			if !ok {
				// The VNI disappeared out from under us; treat as dead.
				return fmt.Errorf("relayWatchdog: VNI %d no longer present", vni)
			}

			lastRxNs := vnet.Stats.LastRXUnixNano.Load()
			now := time.Now()

			// If we've never received anything (0 == not set), this is suspicious,
			// but we don't want to instantly kill a brand new session.
			// We'll treat "never received" as "lastRx == connect time == now",
			// so it only trips after maxSilence has actually elapsed.
			var lastRx time.Time
			if lastRxNs == 0 {
				lastRx = now
			} else {
				lastRx = time.Unix(0, lastRxNs)
			}

			silence := now.Sub(lastRx)
			if silence > maxSilence {
				slog.Warn("relayWatchdog: RX silence threshold exceeded; declaring tunnel dead",
					slog.Uint64("vni", uint64(vni)),
					slog.Duration("silence", silence),
					slog.Duration("maxSilence", maxSilence),
					slog.Time("lastRx", lastRx),
				)
				return fmt.Errorf("rx silence (%s) exceeded max (%s)", silence, maxSilence)
			}
		}
	}
}

// resolveAddrPort resolves a host:port string into a netip.AddrPort by doing a
// short-lived UDP dial. This both resolves DNS and also captures the concrete
// remote address the OS actually chose.
func resolveAddrPort(ctx context.Context, relayAddr string) (netip.AddrPort, error) {
	// Create a short-lived UDP connection to the host:port.
	// This triggers the OS resolver and routing logic.
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", relayAddr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("probe dial failed for %q: %w", relayAddr, err)
	}
	defer conn.Close()

	// Extract the resolved remote address that the OS actually chose.
	ra := conn.RemoteAddr()
	udpAddr, ok := ra.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("unexpected remote addr type: %T", ra)
	}

	return netip.AddrPortFrom(netip.MustParseAddr(udpAddr.IP.String()), uint16(udpAddr.Port)), nil
}

// parsePrefixes parses a list of string addresses into netip.Prefixes.
func parsePrefixes(addrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(addrs))
	for _, addr := range addrs {
		p, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address %q: %w", addr, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}
