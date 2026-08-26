package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/apoxy-dev/icx"
	"github.com/julienschmidt/httprouter"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	tunconn "github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

// TestRelayTeardownIsIdentityAware pins the reconnect race: a stale
// session-close watcher for a replaced connection (same 4-tuple, same ID)
// must not tear down the replacement, or its addresses get released while the
// session is live and the next connect is handed a duplicate /96.
func TestRelayTeardownIsIdentityAware(t *testing.T) {
	var disconnects []string
	r := &Relay{
		conns:  haxmap.New[string, *connection](),
		agents: haxmap.New[string, string](),
	}
	r.SetOnDisconnect(func(ctx context.Context, agent, id string) error {
		disconnects = append(disconnects, id)
		return nil
	})

	old := &connection{id: "same-id"}
	replacement := &connection{id: "same-id"}
	r.conns.Set("same-id", replacement)

	// Stale teardown for the replaced session: must be a no-op.
	r.teardownConn(context.Background(), old)
	if got, ok := r.conns.Get("same-id"); !ok || got != replacement {
		t.Fatal("stale teardown removed the replacement connection")
	}
	if len(disconnects) != 0 {
		t.Fatalf("stale teardown fired onDisconnect: %v", disconnects)
	}

	// Teardown of the live connection still works, exactly once.
	r.teardownConn(context.Background(), replacement)
	if _, ok := r.conns.Get("same-id"); ok {
		t.Fatal("teardown did not remove the live connection")
	}
	r.teardownConn(context.Background(), replacement)
	if len(disconnects) != 1 {
		t.Fatalf("onDisconnect fired %d times, want 1", len(disconnects))
	}
}

func TestRelayConnectRequiresHTTP3SessionTracking(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/tunnel/default", bytes.NewBufferString(`{"agent":"agent-a"}`))
	resp := httptest.NewRecorder()

	(&Relay{}).handleConnect(resp, req, httprouter.Params{{Key: "name", Value: "default"}})

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusInternalServerError)
	}
}

// testHandler builds an in-memory icx handler. It is never started, so it
// forwards nothing; the tests drive its counters directly.
func testHandler(t *testing.T) *icx.Handler {
	t.Helper()

	h, err := icx.NewHandler(
		icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}
	return h
}

// testRelay builds a relay with a real UDP socket and hasher, which is what
// the connection ID is derived from, and no listener behind it.
func testRelay(t *testing.T) *Relay {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	idKey := make([]byte, 32)
	if _, err := rand.Read(idKey); err != nil {
		t.Fatalf("failed to read random key: %v", err)
	}

	return &Relay{
		pc:       pc,
		idHasher: hasher.NewHasher(idKey),
		conns:    haxmap.New[string, *connection](),
		agents:   haxmap.New[string, string](),
	}
}

// connIDFor is the ID the relay derives for an agent at remoteAddr. The
// connect handler and the metrics push handler both get it from
// connIdentityFromRequest; this recomputes it from the 4-tuple on its own, so
// a change to that helper shows up here instead of passing unnoticed.
func connIDFor(t *testing.T, r *Relay, remoteAddr string) string {
	t.Helper()

	local, err := netip.ParseAddrPort(r.pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to parse local address: %v", err)
	}
	return r.idHasher.Hash(local, netip.MustParseAddrPort(remoteAddr))
}

// TestRelayMetricsPushRoute pins how the push route answers: metrics land
// under the connection the request 4-tuple resolves to, a push from an unknown
// 4-tuple is refused, a relay that keeps no store accepts and drops the push,
// and an oversized body is refused with 413 rather than buffered.
func TestRelayMetricsPushRoute(t *testing.T) {
	const (
		remoteAddr  = "127.0.0.1:34567"
		metricName  = metrics.RelayRTTMetric
		metricsBody = "# TYPE tunnel_relay_rtt_seconds gauge\ntunnel_relay_rtt_seconds{relay=\"relay-a\"} 0.012\n"
	)

	cases := []struct {
		name string
		// withStore registers a metrics store on the relay.
		withStore bool
		// withConn publishes a connection under the resolved ID.
		withConn bool
		body     string
		wantCode int
		// wantBody is the response text the handler must write, if any.
		wantBody string
		// wantStored is the metric name the store must hold afterward.
		wantStored string
	}{
		{
			name:       "a push from a live connection is stored",
			withStore:  true,
			withConn:   true,
			body:       metricsBody,
			wantCode:   http.StatusOK,
			wantStored: metricName,
		},
		{
			name:      "a push from an unknown connection is refused",
			withStore: true,
			body:      metricsBody,
			wantCode:  http.StatusNotFound,
		},
		{
			name:     "a relay with no store accepts and drops the push",
			withConn: true,
			body:     metricsBody,
			wantCode: http.StatusNoContent,
		},
		{
			name:      "a malformed body is rejected",
			withStore: true,
			withConn:  true,
			body:      "this is not the exposition format\n",
			wantCode:  http.StatusBadRequest,
			wantBody:  "Invalid metrics body",
		},
		{
			name:      "a body over the cap is refused as too large",
			withStore: true,
			withConn:  true,
			body:      strings.Repeat("tunnel_relay_rtt_seconds{relay=\"relay-a\"} 0.012\n", metrics.MaxPushBytes/40),
			wantCode:  http.StatusRequestEntityTooLarge,
			wantBody:  "request too large",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := testRelay(t)
			id := connIDFor(t, r, remoteAddr)

			var store *metrics.MetricsStore
			if tc.withStore {
				store = metrics.NewMetricsStore()
				r.SetMetricsStore(store)
				store.Register(metrics.StoreTarget{ConnID: id})
			}
			if tc.withConn {
				r.conns.Set(id, &connection{id: id})
			}

			req := httptest.NewRequest(http.MethodPost, api.MetricsPushPath, strings.NewReader(tc.body))
			req.RemoteAddr = remoteAddr
			resp := httptest.NewRecorder()

			r.handleMetricsPush(resp, req, nil)

			if resp.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", resp.Code, tc.wantCode)
			}
			if tc.wantBody != "" {
				if got := strings.TrimSpace(resp.Body.String()); got != tc.wantBody {
					t.Fatalf("body = %q, want %q", got, tc.wantBody)
				}
			}
			if store == nil {
				return
			}
			families := store.Results()[id].Families
			if tc.wantStored == "" {
				if len(families) != 0 {
					t.Fatalf("store holds %d families, want none", len(families))
				}
				return
			}
			mf, ok := families[tc.wantStored]
			if !ok {
				t.Fatalf("store holds %v, want %q", families, tc.wantStored)
			}
			if got := mf.GetMetric()[0].GetGauge().GetValue(); got != 0.012 {
				t.Errorf("%s = %v, want 0.012", tc.wantStored, got)
			}
		})
	}
}

// TestRelayConnectionStats pins the exported snapshot: identity comes off the
// connection, counters off its virtual network, every drop reason is folded
// into one receive and one transmit count, keep-alives get their own two
// counts, and a connection with no virtual network yet has nothing to report.
func TestRelayConnectionStats(t *testing.T) {
	h := testHandler(t)
	r := testRelay(t)
	r.handler = h

	const (
		liveVNI    = 7
		anotherVNI = 9
	)
	remote := netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))
	for _, vni := range []uint{liveVNI, anotherVNI} {
		if err := h.AddVirtualNetwork(vni, remote, nil); err != nil {
			t.Fatalf("failed to add virtual network %d: %v", vni, err)
		}
	}

	vnet, ok := h.GetVirtualNetwork(liveVNI)
	if !ok {
		t.Fatal("virtual network is missing right after it was added")
	}
	vnet.Stats.RXBytes.Store(4096)
	vnet.Stats.TXBytes.Store(2048)
	vnet.Stats.RXPackets.Store(40)
	vnet.Stats.TXPackets.Store(20)
	vnet.Stats.RXDropsNoKey.Store(1)
	vnet.Stats.RXReplayDrops.Store(2)
	vnet.Stats.RXInvalidDst.Store(3)
	vnet.Stats.TXDropsNoRemote.Store(4)
	vnet.Stats.TXErrors.Store(5)
	vnet.Stats.RXKeepAlives.Store(11)
	vnet.Stats.TXKeepAlives.Store(12)

	live := uint(liveVNI)
	other := uint(anotherVNI)
	r.conns.Set("bbb", &connection{
		id:            "bbb",
		handler:       h,
		vni:           &live,
		network:       "prod",
		scope:         "project-1",
		agentInstance: "agent-instance-1",
	})
	r.conns.Set("aaa", &connection{id: "aaa", handler: h, vni: &other, network: "prod"})
	// Still completing its connect: no virtual network, so no counters.
	r.conns.Set("ccc", &connection{id: "ccc", handler: h, network: "prod"})

	stats := r.ConnectionStats()

	if len(stats) != 2 {
		t.Fatalf("stats = %+v, want two connections", stats)
	}
	if stats[0].ID != "aaa" || stats[1].ID != "bbb" {
		t.Fatalf("stats are not sorted by ID: %+v", stats)
	}

	got := stats[1]
	want := ConnStats{
		ID:            "bbb",
		Network:       "prod",
		ProjectID:     "project-1",
		AgentInstance: "agent-instance-1",
		RXBytes:       4096,
		TXBytes:       2048,
		RXPackets:     40,
		TXPackets:     20,
		RXDrops:       6,
		TXDrops:       9,
		RXKeepAlives:  11,
		TXKeepAlives:  12,
	}
	if got != want {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

// TestRelayConnStatsFinalHookOnce pins the teardown hook: it delivers the
// counters the connection ended with, and it delivers them once however often
// teardown runs.
func TestRelayConnStatsFinalHookOnce(t *testing.T) {
	h := testHandler(t)
	r := testRelay(t)
	r.handler = h

	const vni = uint(11)
	remote := netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))
	if err := h.AddVirtualNetwork(vni, remote, nil); err != nil {
		t.Fatalf("failed to add virtual network: %v", err)
	}
	vnet, ok := h.GetVirtualNetwork(vni)
	if !ok {
		t.Fatal("virtual network is missing right after it was added")
	}
	vnet.Stats.RXBytes.Store(1500)
	vnet.Stats.TXBytes.Store(700)
	vnet.Stats.RXDecryptErrors.Store(2)

	var final []ConnStats
	r.SetOnConnStatsFinal(func(s ConnStats) { final = append(final, s) })

	id := vni
	conn := &connection{id: "conn-1", handler: h, vni: &id, network: "prod", scope: "project-1"}
	r.conns.Set(conn.ID(), conn)

	r.teardownConn(context.Background(), conn)
	r.teardownConn(context.Background(), conn)

	if len(final) != 1 {
		t.Fatalf("the hook ran %d times, want 1", len(final))
	}
	want := ConnStats{
		ID:        "conn-1",
		Network:   "prod",
		ProjectID: "project-1",
		RXBytes:   1500,
		TXBytes:   700,
		RXDrops:   2,
	}
	if final[0] != want {
		t.Fatalf("final stats = %+v, want %+v", final[0], want)
	}
	// The counters are gone with the virtual network, which is why the hook
	// must read them before the close.
	if _, ok := h.GetVirtualNetwork(vni); ok {
		t.Error("teardown left the virtual network in place")
	}
}

// stubRouter is a router that programs nothing. Start blocks until the context
// is canceled, the way the real routers do, so only the relay's own shutdown
// ends it, and Close records that the datapath is gone.
type stubRouter struct {
	closed atomic.Bool
}

func (s *stubRouter) Start(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (s *stubRouter) AddAddr(netip.Prefix, tunconn.Connection) error { return nil }

func (s *stubRouter) DelAddr(netip.Prefix) error { return nil }

func (s *stubRouter) AddRoute(netip.Prefix) error { return nil }

func (s *stubRouter) DelRoute(netip.Prefix) error { return nil }

func (s *stubRouter) Close() error {
	s.closed.Store(true)
	return nil
}

var _ router.Router = (*stubRouter)(nil)

// runRelayUntilShutdown starts r, stops it right away, and returns once Start
// has returned. It serves a self-signed certificate because the QUIC listener
// needs one even when no agent ever connects.
func runRelayUntilShutdown(t *testing.T, r *Relay) {
	t.Helper()

	_, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	if err != nil {
		t.Fatalf("failed to generate a certificate: %v", err)
	}
	r.getCert = staticCert(serverCert)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the relay stopped with an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the relay did not stop")
	}
}

// TestRelayShutdownReportsFinalStats pins the drain window: a connection that
// is still live when the relay stops must have its counters reported through
// the final hook, once, and before the router close takes its virtual network
// away. Both shutdown paths are covered, because a draining relay never tears
// its connections down and would otherwise lose everything they carried.
func TestRelayShutdownReportsFinalStats(t *testing.T) {
	cases := []struct {
		name     string
		lameDuck time.Duration
	}{
		{name: "immediate shutdown"},
		{name: "shutdown after a lame duck", lameDuck: 20 * time.Millisecond},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := testHandler(t)
			r := testRelay(t)
			r.handler = h
			rtr := &stubRouter{}
			r.router = rtr
			r.SetLameDuckPeriod(tc.lameDuck)

			var (
				mu              sync.Mutex
				final           []ConnStats
				afterRouterDown bool
			)
			r.SetOnConnStatsFinal(func(s ConnStats) {
				mu.Lock()
				defer mu.Unlock()
				if rtr.closed.Load() {
					afterRouterDown = true
				}
				final = append(final, s)
			})

			remote := netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))
			want := make(map[string]ConnStats)
			for i := 1; i <= 3; i++ {
				vni := uint(100 + i)
				if err := h.AddVirtualNetwork(vni, remote, nil); err != nil {
					t.Fatalf("failed to add virtual network %d: %v", vni, err)
				}
				vnet, ok := h.GetVirtualNetwork(vni)
				if !ok {
					t.Fatalf("virtual network %d is missing right after it was added", vni)
				}
				vnet.Stats.RXBytes.Store(uint64(1000 * i))
				vnet.Stats.TXBytes.Store(uint64(500 * i))
				vnet.Stats.RXInvalidSrc.Store(uint64(i))

				id := fmt.Sprintf("conn-%d", i)
				r.conns.Set(id, &connection{
					id:       id,
					instance: uint64(i),
					handler:  h,
					vni:      &vni,
					network:  "prod",
					scope:    "project-1",
				})
				want[id] = ConnStats{
					ID:        id,
					Instance:  uint64(i),
					Network:   "prod",
					ProjectID: "project-1",
					RXBytes:   uint64(1000 * i),
					TXBytes:   uint64(500 * i),
					RXDrops:   uint64(i),
				}
			}
			// A connection that has no virtual network yet counts nothing, so
			// it must not reach the hook.
			r.conns.Set("conn-pending", &connection{id: "conn-pending", handler: h})

			runRelayUntilShutdown(t, r)

			mu.Lock()
			defer mu.Unlock()

			seen := make(map[string]int)
			for _, got := range final {
				seen[got.ID]++
				if got != want[got.ID] {
					t.Errorf("final stats = %+v, want %+v", got, want[got.ID])
				}
			}
			if len(final) != len(want) {
				t.Fatalf("the hook ran %d times for %d connections: %+v", len(final), len(want), final)
			}
			for id, n := range seen {
				if n != 1 {
					t.Errorf("the hook ran %d times for %s, want 1", n, id)
				}
			}
			if afterRouterDown {
				t.Error("the final counters were read after the router closed")
			}
			if n := r.conns.Len(); n != 0 {
				t.Errorf("the shutdown left %d connections registered", n)
			}
		})
	}
}

// TestRelayFinalStatsReportedOnce pins the once-guard the shutdown flush
// shares with teardown: whichever of the two reaches a connection first reports
// its counters, and the other one reports nothing. A second report would make
// the reader of the counters count the same traffic twice.
//
// The guard is a compare-and-swap on the connection, not the removal from the
// registry, because the removal cannot promise once on its own: both paths can
// read the registry before either one removes the connection from it, and then
// both would report. Only the swap has one winner, which is why the last case
// runs the two paths at the same time.
func TestRelayFinalStatsReportedOnce(t *testing.T) {
	cases := []struct {
		name string
		// run drives the two paths in one order or the other.
		run func(r *Relay, conn *connection)
		// wantDisconnects is how often the control-plane cleanup runs. The
		// shutdown flush leaves it to the drain and adoption path, so it runs
		// only when teardown reached the connection first.
		wantDisconnects int
		// racing marks the case where the two paths run at the same time, so
		// which one arrives first, and with it the cleanup count, is open.
		racing bool
	}{
		{
			name: "teardown before the shutdown flush",
			run: func(r *Relay, conn *connection) {
				r.teardownConn(context.Background(), conn)
				r.flushFinalStats()
			},
			wantDisconnects: 1,
		},
		{
			name: "the shutdown flush before teardown",
			run: func(r *Relay, conn *connection) {
				r.flushFinalStats()
				r.teardownConn(context.Background(), conn)
			},
		},
		{
			name: "two shutdown flushes",
			run: func(r *Relay, conn *connection) {
				r.flushFinalStats()
				r.flushFinalStats()
			},
		},
		{
			name: "teardown and the shutdown flush at the same time",
			run: func(r *Relay, conn *connection) {
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					r.teardownConn(context.Background(), conn)
				}()
				go func() {
					defer wg.Done()
					r.flushFinalStats()
				}()
				wg.Wait()
			},
			racing: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := testHandler(t)
			r := testRelay(t)
			r.handler = h

			const vni = uint(21)
			remote := netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))
			if err := h.AddVirtualNetwork(vni, remote, nil); err != nil {
				t.Fatalf("failed to add virtual network: %v", err)
			}
			vnet, ok := h.GetVirtualNetwork(vni)
			if !ok {
				t.Fatal("virtual network is missing right after it was added")
			}
			vnet.Stats.RXBytes.Store(8192)
			vnet.Stats.TXBytes.Store(4096)
			vnet.Stats.TXErrors.Store(3)

			// Both callbacks can run from either path, so the racing case needs
			// them locked.
			var (
				mu          sync.Mutex
				final       []ConnStats
				disconnects int
			)
			r.SetOnConnStatsFinal(func(s ConnStats) {
				mu.Lock()
				defer mu.Unlock()
				final = append(final, s)
			})
			r.SetOnDisconnect(func(context.Context, string, string) error {
				mu.Lock()
				defer mu.Unlock()
				disconnects++
				return nil
			})

			live := vni
			conn := &connection{
				id:       "conn-1",
				instance: 7,
				handler:  h,
				vni:      &live,
				network:  "prod",
				scope:    "project-1",
			}
			r.conns.Set(conn.ID(), conn)
			r.agents.Set(conn.ID(), "agent-a")

			tc.run(r, conn)

			mu.Lock()
			defer mu.Unlock()

			want := ConnStats{
				ID:        "conn-1",
				Instance:  7,
				Network:   "prod",
				ProjectID: "project-1",
				RXBytes:   8192,
				TXBytes:   4096,
				TXDrops:   3,
			}
			if len(final) != 1 {
				t.Fatalf("the hook ran %d times, want 1: %+v", len(final), final)
			}
			if final[0] != want {
				t.Fatalf("final stats = %+v, want %+v", final[0], want)
			}
			if tc.racing {
				// Only the path that reached the connection first runs the
				// cleanup, and either one may be first here.
				if disconnects > 1 {
					t.Errorf("onDisconnect ran %d times, want at most 1", disconnects)
				}
			} else if disconnects != tc.wantDisconnects {
				t.Errorf("onDisconnect ran %d times, want %d", disconnects, tc.wantDisconnects)
			}
			if _, ok := r.conns.Get(conn.ID()); ok {
				t.Error("the connection is still registered")
			}
		})
	}
}

// TestDropFolding pins the drop arithmetic on its own: every reason the
// datapath counts separately lands in exactly one of the two totals.
func TestDropFolding(t *testing.T) {
	cases := []struct {
		name   string
		set    func(*icx.Statistics)
		wantRX uint64
		wantTX uint64
	}{
		{name: "no drops", set: func(*icx.Statistics) {}},
		{name: "missing key", set: func(s *icx.Statistics) { s.RXDropsNoKey.Store(1) }, wantRX: 1},
		{name: "expired receive key", set: func(s *icx.Statistics) { s.RXDropsExpiredKey.Store(2) }, wantRX: 2},
		{name: "SPI mismatch", set: func(s *icx.Statistics) { s.RXDropsSPIMismatch.Store(3) }, wantRX: 3},
		{name: "bad peer", set: func(s *icx.Statistics) { s.RXDropsBadPeer.Store(4) }, wantRX: 4},
		{name: "decrypt error", set: func(s *icx.Statistics) { s.RXDecryptErrors.Store(5) }, wantRX: 5},
		{name: "replay", set: func(s *icx.Statistics) { s.RXReplayDrops.Store(6) }, wantRX: 6},
		{name: "rate limit", set: func(s *icx.Statistics) { s.RXRateLimitDrops.Store(7) }, wantRX: 7},
		{name: "invalid source", set: func(s *icx.Statistics) { s.RXInvalidSrc.Store(8) }, wantRX: 8},
		{name: "invalid destination", set: func(s *icx.Statistics) { s.RXInvalidDst.Store(9) }, wantRX: 9},
		{name: "expired transmit key", set: func(s *icx.Statistics) { s.TXDropsExpiredKey.Store(10) }, wantTX: 10},
		{name: "no remote endpoint", set: func(s *icx.Statistics) { s.TXDropsNoRemote.Store(11) }, wantTX: 11},
		{name: "transmit error", set: func(s *icx.Statistics) { s.TXErrors.Store(12) }, wantTX: 12},
		{
			name: "counters that are not drops stay out",
			set: func(s *icx.Statistics) {
				s.RXPackets.Store(100)
				s.RXBytes.Store(200)
				s.TXPackets.Store(300)
				s.TXBytes.Store(400)
				s.RXLearnedRemotes.Store(5)
				s.RXLearnsDamped.Store(6)
				s.RXKeepAlives.Store(7)
				s.TXKeepAlives.Store(8)
			},
		},
		{
			name: "every reason at once",
			set: func(s *icx.Statistics) {
				s.RXDropsNoKey.Store(1)
				s.RXDropsExpiredKey.Store(2)
				s.RXDropsSPIMismatch.Store(3)
				s.RXDropsBadPeer.Store(4)
				s.RXDecryptErrors.Store(5)
				s.RXReplayDrops.Store(6)
				s.RXRateLimitDrops.Store(7)
				s.RXInvalidSrc.Store(8)
				s.RXInvalidDst.Store(9)
				s.TXDropsExpiredKey.Store(10)
				s.TXDropsNoRemote.Store(11)
				s.TXErrors.Store(12)
			},
			wantRX: 45,
			wantTX: 33,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s icx.Statistics
			tc.set(&s)

			if got := rxDrops(&s); got != tc.wantRX {
				t.Errorf("rxDrops = %d, want %d", got, tc.wantRX)
			}
			if got := txDrops(&s); got != tc.wantTX {
				t.Errorf("txDrops = %d, want %d", got, tc.wantTX)
			}
		})
	}
}

// TestConnStatsKeepAliveCounters pins the keep-alive counters on their own: a
// keep-alive carries no payload, so the datapath counts it apart from the
// packets and the bytes. A connection that only holds the tunnel open must
// therefore report keep-alives and no traffic, which is what tells an idle
// tunnel apart from a broken one.
func TestConnStatsKeepAliveCounters(t *testing.T) {
	cases := []struct {
		name string
		set  func(*icx.Statistics)
		want ConnStats
	}{
		{
			name: "no traffic at all",
			set:  func(*icx.Statistics) {},
		},
		{
			name: "idle tunnel exchanging only keep-alives",
			set: func(s *icx.Statistics) {
				s.RXKeepAlives.Store(9)
				s.TXKeepAlives.Store(10)
			},
			want: ConnStats{RXKeepAlives: 9, TXKeepAlives: 10},
		},
		{
			name: "traffic and keep-alives together",
			set: func(s *icx.Statistics) {
				s.RXPackets.Store(3)
				s.RXBytes.Store(300)
				s.TXPackets.Store(4)
				s.TXBytes.Store(400)
				s.RXKeepAlives.Store(5)
				s.TXKeepAlives.Store(6)
			},
			want: ConnStats{
				RXBytes:      300,
				TXBytes:      400,
				RXPackets:    3,
				TXPackets:    4,
				RXKeepAlives: 5,
				TXKeepAlives: 6,
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := testHandler(t)

			vni := uint(200 + i)
			remote := netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))
			if err := h.AddVirtualNetwork(vni, remote, nil); err != nil {
				t.Fatalf("failed to add virtual network: %v", err)
			}
			vnet, ok := h.GetVirtualNetwork(vni)
			if !ok {
				t.Fatal("virtual network is missing right after it was added")
			}
			tc.set(&vnet.Stats)

			conn := &connection{id: "conn-1", handler: h, vni: &vni, network: "prod"}
			got, ok := conn.datapathStats()
			if !ok {
				t.Fatal("the connection reported no counters")
			}

			want := tc.want
			want.ID = "conn-1"
			want.Network = "prod"
			if got != want {
				t.Fatalf("stats = %+v, want %+v", got, want)
			}
		})
	}
}
