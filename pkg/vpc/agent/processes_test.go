// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
)

// TestProcesses checks the order of the public calls and the callbacks when
// they meet the work of the agent processes.
func TestProcesses(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, w *world, r *testRelay)
	}{
		{name: "callback reads during the shutdown", run: func(t *testing.T, w *world, r *testRelay) {
			in, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			got := make(chan error, 1)
			var a *testAgent
			a = w.agent(t, "a", r, agentOptions{onAttachment: func(Attachment) {
				once.Do(func() {
					close(in)
					<-release
					_ = a.a.Status()
					_, err := a.a.Attach(context.Background(), AttachmentSpec{Name: "x-2"})
					got <- err
				})
			}})
			a.attached(t)
			go func() { _, _ = a.a.Attach(context.Background(), AttachmentSpec{Name: "x-1"}) }()
			<-in
			a.cancel()
			close(release)
			select {
			case err := <-got:
				assert.ErrorIs(t, err, errNoRelay)
			case <-time.After(5 * time.Second):
				t.Fatal("the reads in the callback did not return")
			}
			select {
			case <-a.done:
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return after the callback")
			}
		}},
		{name: "OnDetach at the close", run: func(t *testing.T, w *world, r *testRelay) {
			r2 := w.relay(t, "relay-2")
			a, _ := w.agentOn(t, "a", agentOptions{}, 2, r, r2)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := a.a.Attach(ctx, AttachmentSpec{Name: "x-1"})
			require.NoError(t, err)
			require.Eventually(t, func() bool { return countPrefix(a.events("x-1"), "attach ") == 2 }, 5*time.Second, 10*time.Millisecond)
			a.stop()
			assert.Equal(t, 2, countPrefix(a.events("a"), "detach "), "OnDetach of the base on each session: %v", a.events("a"))
			assert.Equal(t, 2, countPrefix(a.events("x-1"), "detach "), "OnDetach of the extra on each session: %v", a.events("x-1"))
		}},
		{name: "DNS in the first OnAttach", run: func(t *testing.T, w *world, r *testRelay) {
			ready := make(chan struct{})
			first := make(chan []string, 1)
			var a *testAgent
			a = w.agent(t, "a", r, agentOptions{onAttach: func(netip.Addr) {
				<-ready
				servers, _ := a.a.DNS()
				select {
				case first <- servers:
				default:
				}
			}})
			close(ready)
			a.attached(t)
			assert.Equal(t, w.dns, <-first)
		}},
		{name: "Attach returns after its callback", run: func(t *testing.T, w *world, r *testRelay) {
			release := make(chan struct{})
			var released atomic.Bool
			a := w.agent(t, "a", r, agentOptions{onAttachment: func(Attachment) {
				<-release
				released.Store(true)
			}})
			a.attached(t)
			time.AfterFunc(time.Second, func() { close(release) })
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			x, err := a.a.Attach(ctx, AttachmentSpec{Name: "a-2"})
			require.NoError(t, err)
			assert.True(t, released.Load(), "Attach returned before its OnAttachment")
			assert.Equal(t, []string{"attach a-2 " + x.Address.String()}, a.events("a-2"))
		}},
		{name: "cancellation while calls wait", run: func(t *testing.T, w *world, r *testRelay) {
			a := w.agent(t, "a", r, agentOptions{})
			a.attached(t)
			release := w.addrs.hold("x-")
			defer release()
			for i := range maxInFlight {
				go func() { _, _ = a.a.Attach(context.Background(), AttachmentSpec{Name: fmt.Sprintf("x-%d", i)}) }()
			}
			// The relay assigns addresses for one call at a time, so the others wait
			// in the relay. The agent takes the specs in order, so y comes after them.
			require.Eventually(t, func() bool {
				now, _ := r.openCalls()
				return now == maxInFlight && len(a.a.Attachments()) == 1+maxInFlight
			}, 10*time.Second, 10*time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err := a.a.Attach(ctx, AttachmentSpec{Name: "y"})
			assert.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Less(t, time.Since(start), time.Second)
			now, _ := r.openCalls()
			assert.Equal(t, maxInFlight, now, "the held calls stay")
			assert.False(t, slices.ContainsFunc(r.r.AttachmentStats(), func(st relay.AttachmentStats) bool { return st.Name == "y" }), "the relay saw the Attach of y")
			assert.False(t, slices.ContainsFunc(a.a.Attachments(), func(at Attachment) bool { return at.Name == "y" }))
		}},
		{name: "cancellation after admission", run: func(t *testing.T, w *world, r *testRelay) {
			a := w.agent(t, "a", r, agentOptions{})
			a.attached(t)
			release := w.addrs.hold("a-2")
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			var x Attachment
			var err error
			go func() {
				defer close(done)
				x, err = a.a.Attach(ctx, AttachmentSpec{Name: "a-2"})
			}()
			require.Eventually(t, func() bool { now, _ := w.addrs.held(); return now == 1 }, 5*time.Second, 10*time.Millisecond)
			cancel()
			time.AfterFunc(time.Second, release)
			<-done
			require.NoError(t, err, "the relay took the call before the end of the context")
			assert.Equal(t, []string{"attach a-2 " + x.Address.String()}, a.events("a-2"), "OnAttachment ran before the return")
		}},
		{name: "stale Attach success", run: func(t *testing.T, w *world, r *testRelay) {
			a := w.agent(t, "a", r, agentOptions{})
			a.attached(t)
			release := w.addrs.hold("a-2")
			done := make(chan error, 1)
			go func() {
				_, err := a.a.Attach(context.Background(), AttachmentSpec{Name: "a-2"})
				done <- err
			}()
			require.Eventually(t, func() bool { now, _ := w.addrs.held(); return now == 1 }, 5*time.Second, 10*time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, a.a.Detach(ctx, "a-2"))
			release()
			select {
			case err := <-done:
				assert.ErrorIs(t, err, ErrNoAttachment)
			case <-time.After(5 * time.Second):
				t.Fatal("Attach did not return")
			}
			assert.False(t, slices.ContainsFunc(a.a.Attachments(), func(at Attachment) bool { return at.Name == "a-2" }))
			require.Eventually(t, func() bool {
				return !slices.ContainsFunc(r.r.AttachmentStats(), func(st relay.AttachmentStats) bool { return st.Name == "a-2" })
			}, 5*time.Second, 10*time.Millisecond, "the relay detached a-2")
		}},
		{name: "latency change with no session event", run: func(t *testing.T, w *world, r *testRelay) {
			slow := &slowConn{}
			a := w.agent(t, "a", r, agentOptions{mode: TransportQUIC, slow: slow})
			b := w.agent(t, "b", r, agentOptions{mode: TransportQUIC})
			ea, eb := a.attached(t), b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			// The RTT is the smoothed RTT of the QUIC connection, and the data
			// frames of the pings give it samples. The relay sends keepalives, so
			// the agent sends none when it is idle.
			rtt := func() time.Duration {
				_ = answers(a.stack, ea.addr, eb.addr, 9000)
				return a.a.Status().RTT
			}
			require.Eventually(t, func() bool { return rtt() > 0 }, 5*time.Second, 10*time.Millisecond)
			base := a.a.Status().RTT
			const extra = 40 * time.Millisecond
			slow.set(r, extra)
			require.Eventually(t, func() bool { return rtt() >= base+extra/2 }, 10*time.Second, 10*time.Millisecond,
				"RTT after the delay: %v", a.a.Status().RTT)
			slow.set(r, 0)
			require.Eventually(t, func() bool { return rtt() < base+extra/4 }, 10*time.Second, 10*time.Millisecond,
				"RTT after the delay went: %v", a.a.Status().RTT)
			assert.Equal(t, []string{"attach a " + a.current().self.String()}, a.events("a"), "no session event")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.dns = []string{"fd00::53"}
			tc.run(t, w, w.relay(t, "relay-1"))
		})
	}
}

// countPrefix returns the entries of events that start with prefix.
func countPrefix(events []string, prefix string) int {
	n := 0
	for _, e := range events {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}
