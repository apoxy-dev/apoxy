// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func TestAttachErrors(t *testing.T) {
	w := newWorld(t)
	cases := []struct {
		name   string
		spec   AttachmentSpec
		noRC   bool // The agent has no relay session.
		detach string
		want   error
	}{
		{name: "name is not a DNS-1123 subdomain", spec: AttachmentSpec{Name: "X_1"}, want: ErrInvalidAttachment},
		{name: "label is not valid", spec: AttachmentSpec{Name: "x", Labels: map[string]string{"a b": "c"}}, want: ErrInvalidAttachment},
		{name: "route is not valid", spec: AttachmentSpec{Name: "x", Routes: []netip.Prefix{{}}}, want: ErrInvalidAttachment},
		{name: "name of the base", spec: AttachmentSpec{Name: "base"}, want: ErrAttachmentExists},
		{name: "name in use", spec: AttachmentSpec{Name: "used"}, want: ErrAttachmentExists},
		{name: "no relay session", spec: AttachmentSpec{Name: "x"}, noRC: true, want: errNoRelay},
		{name: "detach the base", detach: "base", want: ErrBaseAttachment},
		{name: "detach an unknown name", detach: "x", want: ErrNoAttachment},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := w.stubAgent(t, "a")
			a.cfg.Name = "base"
			a.specs["used"] = &AttachmentSpec{Name: "used"}
			if tc.noRC {
				a.conns = nil
			}
			var err error
			if tc.detach != "" {
				err = a.Detach(context.Background(), tc.detach)
			} else {
				_, err = a.Attach(context.Background(), tc.spec)
			}
			assert.ErrorIs(t, err, tc.want)
			assert.Len(t, a.specs, 1, "a failed call keeps no attachment")
		})
	}
}

// TestAttachInFlight checks that at most maxInFlight Attach calls of extra
// attachments run at once on a relay session, and that all of them end.
func TestAttachInFlight(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	a := w.agent(t, "a", r, agentOptions{})
	a.attached(t)
	release := w.addrs.hold("x-")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const n = 200
	errs := make(chan error, n)
	for i := range n {
		go func() {
			_, err := a.a.Attach(ctx, AttachmentSpec{Name: fmt.Sprintf("x-%d", i)})
			errs <- err
		}()
	}
	require.Eventually(t, func() bool {
		now, _ := w.addrs.held()
		return now == maxInFlight
	}, 5*time.Second, 10*time.Millisecond)
	// With no limit, all calls get to the relay in this time.
	time.Sleep(200 * time.Millisecond)
	release()
	for range n {
		require.NoError(t, <-errs)
	}
	_, most := w.addrs.held()
	assert.Equal(t, maxInFlight, most)
	assert.Len(t, a.a.Attachments(), n+1)
}

// TestAttachmentsOnNewSession checks that the agent attaches the extra
// attachments on each new relay session, and that the callbacks give the
// addresses of the old and the new session in order.
func TestAttachmentsOnNewSession(t *testing.T) {
	// A relay that drains keeps its session until the drain ends.
	drained := []string{"attach OLD", "deprecate OLD", "attach NEW", "detach OLD"}
	ended := []string{"attach OLD", "detach OLD", "attach NEW"}
	cases := []struct {
		name string
		move string // drain or lost.
		// The drain gives no alternate, and the draining relay stops Accept, as a
		// relay host in its lame duck. The agent has the other relay in its list.
		lameDuck bool
		want     []string // Callbacks of each extra attachment.
	}{
		{name: "drain", move: "drain", want: drained},
		{name: "drain with no alternate", move: "drain", lameDuck: true, want: drained},
		{name: "session lost", move: "lost", want: ended},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r1, r2 := w.relay(t, "relay-1"), w.relay(t, "relay-2")
			opts := agentOptions{}
			alts := []*dp.RelayRef{{Id: r2.id, Addresses: []string{r2.addr}}}
			if tc.lameDuck {
				opts.relays, alts = []identity.Relay{r1.ref(), r2.ref()}, nil
			}
			a := w.agent(t, "a", r1, opts)
			a.attached(t)
			from := r1
			if a.current().addr == r2.addr {
				from = r2
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			old := map[string]netip.Addr{}
			for _, name := range []string{"x-1", "x-2", "x-3"} {
				at, err := a.a.Attach(ctx, AttachmentSpec{Name: name})
				require.NoError(t, err)
				old[name] = at.Address
			}

			switch tc.move {
			case "drain":
				// The relay closes the sessions that stay when its drain ends.
				dctx, dcancel := context.WithTimeout(ctx, time.Second)
				defer dcancel()
				if tc.lameDuck {
					from.stopAccept()
				}
				var wg sync.WaitGroup
				wg.Go(func() { from.srv.Drain(dctx, alts) })
				t.Cleanup(wg.Wait)
			case "lost":
				a.reconnect()
			}
			a.attached(t)

			for name, addr := range old {
				require.Eventually(t, func() bool { return len(a.events(name)) == len(tc.want) }, 10*time.Second, 10*time.Millisecond,
					"callbacks of %s: %v", name, a.events(name))
				now := a.extraAddr(name)
				assert.NotEqual(t, addr, now, "%s has a new address", name)
				names := strings.NewReplacer("OLD", name+" "+addr.String(), "NEW", name+" "+now.String())
				var want []string
				for _, e := range tc.want {
					want = append(want, names.Replace(e))
				}
				assert.Equal(t, want, a.events(name))
			}
			id := identity.ID{Project: testProject, VPC: testVPC, Agent: "a"}.String()
			require.Eventually(t, func() bool { return w.addrs.LiveOf(id) == 4 }, 5*time.Second, 10*time.Millisecond,
				"the relay releases the old addresses")
			if tc.move == "drain" {
				assert.Equal(t, 8, w.addrs.Overlap(id), "the new session has all attachments before the old one closes")
			}
		})
	}
}

// TestDetachDialedAttachment checks that b reaches a again soon after a
// detaches the extra attachment that b dialed its peer session to.
func TestDetachDialedAttachment(t *testing.T) {
	cases := []struct {
		name string
		mode TransportMode
	}{
		{name: "PSP", mode: TransportAuto},
		{name: "QUIC", mode: TransportQUIC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a, b := w.agent(t, "a", r, agentOptions{mode: tc.mode}), w.agent(t, "b", r, agentOptions{mode: tc.mode})
			ea, eb := a.attached(t), b.attached(t)
			echo(t, a.stack, ea.addr, 9001)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			x1, err := a.a.Attach(ctx, AttachmentSpec{Name: "x-1"})
			require.NoError(t, err)
			echo(t, a.stack, x1.Address, 9002)
			ping(t, b.stack, eb.addr, x1.Address, 9002, "to x-1")
			require.Equal(t, x1.Address, onlyPeer(t, b.a).dst, "b dialed its peer session to x-1")

			start := time.Now()
			require.NoError(t, a.a.Detach(ctx, "x-1"))
			x2, err := a.a.Attach(ctx, AttachmentSpec{Name: "x-2"})
			require.NoError(t, err)
			echo(t, a.stack, x2.Address, 9003)
			deadline := start.Add(2 * time.Second)
			reachBy(t, b.stack, eb.addr, ea.addr, 9001, deadline)
			reachBy(t, b.stack, eb.addr, x2.Address, 9003, deadline)
			t.Logf("b reaches the base of a and x-2 %s after the detach of x-1", time.Since(start).Round(time.Millisecond))
		})
	}
}

// reachBy sends from src to dst:port until the echo comes, and fails the test
// at deadline.
func reachBy(t *testing.T, s *stack.Stack, src, dst netip.Addr, port uint16, deadline time.Time) {
	t.Helper()
	for time.Now().Before(deadline) {
		c, err := gonet.DialUDP(s, fullAddr(src, 0), fullAddr(dst, port), ipv6.ProtocolNumber)
		require.NoError(t, err)
		_, err = c.Write([]byte("x"))
		require.NoError(t, err)
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err = c.Read(make([]byte, 64))
		_ = c.Close()
		if err == nil {
			return
		}
	}
	t.Fatalf("no answer from %s by the deadline", dst)
}

// grantRelay answers Attach with grants that it signed before. Each answer is
// a new copy from bytes, as from the wire.
type grantRelay struct {
	dp.RelayClient
	mu      sync.Mutex
	answers [][]byte
}

func newGrantRelay(t *testing.T, cert *tls.Certificate, n int) *grantRelay {
	g := &grantRelay{}
	for i := range n {
		id := fmt.Sprintf("attachment-%d", i)
		grant := extraGrant(t, cert, "a", id, fmt.Sprintf("fd61:706f:7879:12:3400:%x::/96", i+1), nil)
		b, err := proto.Marshal(&dp.AttachResponse{AttachmentId: id, Grant: grant})
		require.NoError(t, err)
		g.answers = append(g.answers, b)
	}
	return g
}

func (g *grantRelay) Attach(context.Context, *dp.AttachRequest) (*dp.AttachResponse, error) {
	g.mu.Lock()
	b := g.answers[0]
	g.answers = g.answers[1:]
	g.mu.Unlock()
	res := &dp.AttachResponse{}
	return res, proto.Unmarshal(b, res)
}

func (g *grantRelay) Detach(context.Context, *dp.DetachRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// TestAttachmentMemory checks the heap and the goroutines that each extra
// attachment keeps.
func TestAttachmentMemory(t *testing.T) {
	const n, budget = 1000, 4096
	if os.Getenv("AGENT_MEMORY_TEST") == "" {
		// Other tests free memory while they stop, so the test runs in a new process.
		cmd := exec.Command(os.Args[0], "-test.run=^TestAttachmentMemory$", "-test.v")
		cmd.Env = append(os.Environ(), "AGENT_MEMORY_TEST=1")
		out, err := cmd.CombinedOutput()
		t.Logf("%s", out)
		require.NoError(t, err)
		return
	}
	w := newWorld(t)
	a := w.stubAgent(t, "a")
	cert := w.relayCA.relayCert(t, "relay-1")
	a.primary().c = newGrantRelay(t, cert, n)
	ctx := context.Background()

	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	goroutines := runtime.NumGoroutine()
	before := heap()
	var wg sync.WaitGroup
	for k := range 8 {
		wg.Go(func() {
			for i := k; i < n; i += 8 {
				_, err := a.Attach(ctx, AttachmentSpec{Name: fmt.Sprintf("x-%d", i)})
				assert.NoError(t, err)
			}
		})
	}
	wg.Wait()
	after := heap()
	per := (int64(after) - int64(before)) / n
	t.Logf("Heap for each extra attachment: %d bytes (grant relay chain: %d bytes)", per, len(cert.Certificate[0]))
	assert.LessOrEqual(t, per, int64(budget))
	assert.Len(t, a.Attachments(), n+1)
	assert.LessOrEqual(t, runtime.NumGoroutine(), goroutines, "no goroutine for each attachment")

	for i := range n {
		require.NoError(t, a.Detach(ctx, fmt.Sprintf("x-%d", i)))
	}
	assert.Len(t, a.Attachments(), 1)
	assert.Empty(t, a.primary().extras)
}
