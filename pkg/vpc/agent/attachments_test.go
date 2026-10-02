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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

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
				a.rc = nil
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

// TestAttachmentsMove checks that the extra attachments move to the new relay
// session, before the move when they can.
func TestAttachmentsMove(t *testing.T) {
	cases := []struct {
		name    string
		move    string        // drain, renew or lost.
		slow    bool          // The extras attach on the new session after the move.
		wait    time.Duration // moveWait. Zero keeps the default.
		oldEnds bool          // The relay closes the old session while the agent waits for the extras.
		before  bool          // The extras attach on the new session before the move.
	}{
		{name: "drain", move: "drain", before: true},
		{name: "cert renew", move: "renew", before: true},
		{name: "session lost", move: "lost"},
		{name: "drain with slow extras", move: "drain", slow: true, wait: 200 * time.Millisecond},
		{name: "old session ends while extras attach", move: "drain", slow: true, wait: 5 * time.Second, oldEnds: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wait != 0 {
				old := moveWait
				moveWait = tc.wait
				t.Cleanup(func() { moveWait = old })
			}
			w := newWorld(t)
			r1, r2 := w.relay(t, "relay-1"), w.relay(t, "relay-2")
			opts := agentOptions{}
			if tc.move == "renew" {
				opts.life = 3 * time.Second
			}
			a := w.agent(t, "a", r1, opts)
			a.attached(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			old := map[string]netip.Addr{}
			for _, name := range []string{"x-1", "x-2", "x-3"} {
				at, err := a.a.Attach(ctx, AttachmentSpec{Name: name})
				require.NoError(t, err)
				old[name] = at.Address
			}

			release := func() {}
			if tc.slow {
				release = w.addrs.hold("x-")
			}
			start := time.Now()
			switch tc.move {
			case "drain":
				dctx := ctx
				if tc.oldEnds {
					// The relay closes the sessions that did not move when its drain ends.
					var dcancel context.CancelFunc
					dctx, dcancel = context.WithTimeout(ctx, 300*time.Millisecond)
					defer dcancel()
				}
				var wg sync.WaitGroup
				wg.Go(func() { r1.srv.Drain(dctx, []*dp.RelayRef{{Id: r2.id, Addresses: []string{r2.addr}}}) })
				t.Cleanup(wg.Wait)
			case "lost":
				a.reconnect()
			}
			a.attached(t)
			if tc.oldEnds {
				assert.Less(t, time.Since(start), time.Second, "the agent moves when the old session ends, before moveWait")
			}
			release()

			now := map[string]netip.Addr{}
			require.Eventually(t, func() bool {
				for _, at := range a.a.Attachments()[1:] {
					if !at.Address.IsValid() || at.Address != a.extraAddr(at.Name) {
						return false
					}
					now[at.Name] = at.Address
				}
				return len(now) == 3
			}, 10*time.Second, 10*time.Millisecond, "the extras attach on the new session, and OnAttachment runs")
			for name, addr := range old {
				assert.NotEqual(t, addr, now[name], "%s has a new address", name)
				want := []string{"attach " + name + " " + addr.String()}
				if !tc.before {
					want = append(want, "detach "+name+" "+addr.String())
				}
				want = append(want, "attach "+name+" "+now[name].String())
				assert.Equal(t, want, a.events(name))
			}
			id := identity.ID{Project: testProject, VPC: testVPC, Agent: "a"}.String()
			require.Eventually(t, func() bool { return w.addrs.liveOf(id) == 4 }, 5*time.Second, 10*time.Millisecond,
				"the relay releases the old addresses")
			if tc.before {
				assert.Equal(t, 8, w.addrs.overlap(id), "the new session has all attachments before the old one closes")
			}
		})
	}
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
	a.rc.c = newGrantRelay(t, cert, n)
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
	assert.Empty(t, a.rc.extras)
}
