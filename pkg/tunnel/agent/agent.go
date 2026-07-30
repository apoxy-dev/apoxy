// Package agent implements the tunnel agent: the client side of the
// vpc.apoxy.dev relay stack. It owns the shared UDP packet plane (Geneve data
// + QUIC control on one socket), the overlay datapath (in-process netstack
// with a SOCKS listener, or a kernel TUN device), and the relay session
// lifecycle (bootstrap, connection slots, key rotation, watchdog).
//
// It is consumed by the `apoxy alpha tunnel run` command and embedded
// in-process by services that need a foot in the overlay themselves (e.g. the
// backplane's VTEP peer, which runs the agent in TUN mode so Envoy can reach
// overlay destinations by kernel route).
package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/conntrackpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/randalloc"
)

// Watchdog tuning knobs
const (
	watchdogMaxSilence = 120 * time.Second
	watchdogInterval   = 5 * time.Second
	// relayRefreshInterval is how often the agent re-lists ready relays from the
	// apiserver to keep its connection pool current.
	relayRefreshInterval = 30 * time.Second
)

// connectionHealthCounter tracks how many relay sessions are currently live.
var connectionHealthCounter atomic.Int32

// Config holds the agent identity, credential, and datapath configuration for
// one Run. Agent, Network, Token, and a relay source (SeedRelayAddr or a
// non-empty SeedRelays) are required.
type Config struct {
	Agent            string            // agent identifier
	Network          string            // VPC network name
	Token            string            // tunnel auth token
	Labels           map[string]string // agent-declared labels for VPCService selection
	AdvertisedRoutes []string          // CIDRs reachable behind this agent, advertised to the relay
	Instance         string            // stable per-process instance UUID

	// SeedRelayAddr is the relay dialed for the bootstrap session (host:port).
	// Empty means Run picks one at random from SeedRelays; set it only for the
	// static single-relay case.
	SeedRelayAddr string
	// SeedRelays is the initial relay pool. Empty means just SeedRelayAddr.
	SeedRelays sets.Set[string]
	// RelayLister, when set, is polled to keep the relay pool current; relays
	// coming and going are picked up without a restart. Nil = static pool.
	RelayLister func(context.Context) (sets.Set[string], error)
	// MinConns is the number of concurrent relay connection slots. Values
	// below 1 are treated as 1.
	MinConns int

	// TLSConfig is used for the QUIC control sessions. Nil means defaults.
	TLSConfig *tls.Config

	// SocksListenAddr is the SOCKS5 listen address for the netstack datapath.
	// Ignored in TUN mode.
	SocksListenAddr string
	// PcapPath writes a packet capture of the netstack datapath. Not
	// supported in TUN mode.
	PcapPath string
	// TunMode selects the kernel TUN datapath over the in-process netstack:
	// the agent creates a TUN device (TunIfaceName) and programs overlay
	// addresses/routes on it, so any process in the netns reaches the overlay
	// by kernel route. Linux only; requires NET_ADMIN and /dev/net/tun.
	TunMode bool
	// TunIfaceName names the TUN device created in TUN mode.
	TunIfaceName string
	// TunNetns, when non-empty, places the TUN device inside this named
	// network namespace (created and bind-mounted under /var/run/netns if
	// missing). Only sockets created in that namespace reach the overlay,
	// giving kernel-level isolation between tenants sharing the process.
	// Requires CAP_SYS_ADMIN. Ignored outside TUN mode.
	TunNetns string
}

// Run connects the agent to the relay fabric and blocks until ctx is canceled
// or the datapath fails: it bootstraps against the seed relay, starts the
// overlay router, and maintains MinConns concurrent relay sessions from the
// (optionally refreshed) relay pool.
func Run(ctx context.Context, cfg Config) error {
	if cfg.MinConns < 1 {
		cfg.MinConns = 1
	}

	g, ctx := errgroup.WithContext(ctx)

	packetPlane, err := newPacketPlane()
	if err != nil {
		return err
	}
	defer packetPlane.Close()

	tlsConf := cfg.TLSConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	}

	// Bootstrap against the seed relay to learn MTU/DNS/routes, keys, and VNI.
	// The seed is picked at random from the discovered pool unless the caller
	// pinned one explicitly.
	seedRelayAddr := cfg.SeedRelayAddr
	if seedRelayAddr == "" {
		if cfg.SeedRelays.Len() == 0 {
			return errors.New("no seed relay: SeedRelayAddr and SeedRelays are both empty")
		}
		seedRelayAddr = cfg.SeedRelays.UnsortedList()[rand.IntN(cfg.SeedRelays.Len())]
	}
	boot, err := bootstrapSession(ctx, cfg, seedRelayAddr, packetPlane.QuicMux, tlsConf)
	if err != nil {
		return err
	}

	// Initialize and start the router.
	r, handler, routes, err := initRouter(
		ctx,
		g,
		boot.Connect,
		routerInitOpts{
			pcGeneve:        packetPlane.Geneve,
			socksListenAddr: cfg.SocksListenAddr,
			pcapPath:        cfg.PcapPath,
			tunMode:         cfg.TunMode,
			tunIfaceName:    cfg.TunIfaceName,
			tunNetns:        cfg.TunNetns,
		},
	)
	if err != nil {
		return err
	}
	defer r.Close()

	// Create a relay address pool that ensures we never connect to the same
	// relay from multiple slots at once. In discovery mode it starts from the
	// ready-relay set; in static mode it holds just the seed relay.
	poolAddrs := cfg.SeedRelays
	if poolAddrs.Len() == 0 {
		poolAddrs = sets.New[string](seedRelayAddr)
	}
	relayAddressPool := randalloc.NewRandAllocator(poolAddrs)

	// A slot can only hold a relay no other slot holds, so a pool smaller than
	// MinConns leaves the surplus slots idle. In discovery mode that self-heals
	// as relays appear; in static mode (single seed) it never will, so surface
	// it rather than letting slots block silently.
	if poolAddrs.Len() < cfg.MinConns {
		slog.Warn("Fewer relays available than requested connections; surplus connection slots will idle until more relays appear",
			slog.Int("relays", poolAddrs.Len()),
			slog.Int("minConns", cfg.MinConns))
	}

	// Keep the pool fresh from the apiserver (discovery mode only). A slot
	// whose session dies re-Acquires from the refreshed pool, so relays going
	// NotReady drop out and newly-Ready relays get picked up automatically.
	if cfg.RelayLister != nil {
		g.Go(func() error {
			return refreshRelayPool(ctx, cfg.RelayLister, relayAddressPool, relayRefreshInterval)
		})
	}

	// Spawn MinConns independent connection slots.
	// Each slot:
	//   - acquires a unique relay from the allocator
	//   - connects & manages that session
	//   - when the session ends, releases the relay
	for i := 0; i < cfg.MinConns; i++ {
		g.Go(func() error {
			return manageConnectionSlot(ctx, cfg, packetPlane.QuicMux, handler, r, routes, relayAddressPool, tlsConf)
		})
	}

	return g.Wait()
}

// packetPlane bundles the shared UDP socket and its derived logical planes:
// - Geneve/data plane (pcGeneve)
// - QUIC/control plane mux (pcQuicMux)
type packetPlane struct {
	Geneve  batchpc.BatchPacketConn
	QuicMux *conntrackpc.ConntrackPacketConn
	closers []func()
}

// newPacketPlane:
//   - creates a UDP socket bound to :0
//   - wraps it in a BatchPacketConn
//   - bifurcates into Geneve (data plane) and QUIC (control)
//   - wraps QUIC side in a conntrack multiplexer
func newPacketPlane() (*packetPlane, error) {
	return newPacketPlaneAt(":0")
}

// newPacketPlaneAt is newPacketPlane with an explicit UDP bind address (tests
// bind to loopback so the relay advertises a dialable address).
func newPacketPlaneAt(bindAddr string) (*packetPlane, error) {
	lis, err := net.ListenPacket("udp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}

	bpc, err := batchpc.New("udp", lis)
	if err != nil {
		lis.Close()
		return nil, fmt.Errorf("failed to create batch packet conn: %w", err)
	}

	pcGeneveInner, pcQuicInner := bifurcate.Bifurcate(bpc)
	pcQuicMuxInner := conntrackpc.New(pcQuicInner, conntrackpc.Options{})

	return &packetPlane{
		Geneve:  pcGeneveInner,
		QuicMux: pcQuicMuxInner,
		closers: []func(){
			func() { pcGeneveInner.Close() },
			func() { pcQuicMuxInner.Close() },
			func() { pcQuicInner.Close() },
		},
	}, nil
}

func (pp *packetPlane) Close() {
	for _, c := range pp.closers {
		c()
	}
}

// HealthHandler returns 200 OK when at least one tunnel connection is active,
// 503 otherwise. This is used by external health checks.
//
// Response codes:
//   - 200 OK: At least one tunnel connection is active
//   - 503 Service Unavailable: No active tunnel connections
//
// Body is plain text with a short summary.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	active := connectionHealthCounter.Load()

	if active > 0 {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK - %d active connection(s)\n", active)
		return
	}

	w.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprintf(w, "UNHEALTHY - no active connections\n")
}
