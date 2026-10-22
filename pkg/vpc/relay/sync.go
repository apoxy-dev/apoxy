// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// maxSyncQueue limits the messages that wait for the Session stream.
	maxSyncQueue = 4096
	// maxDeltaRoutes and maxDeltaBytes limit one RouteDelta. All changes of one prefix are in one
	// RouteDelta, so a part can be larger.
	maxDeltaRoutes = 256
	maxDeltaBytes  = 1 << 20
)

// sessionStream is the relay side of a Session call.
type sessionStream = rpc.BidiStreamServer[dpv1.SessionRequest, dpv1.SessionResponse]

// outbox has the messages for the agent that wait for the stream writer of A, apart from the
// routes. A puts them in, and the writer takes them.
type outbox struct {
	mu      sync.Mutex
	msgs    []*dpv1.SessionResponse
	report  *dpv1.RxReport
	dropped uint64
	sig     chan struct{}
}

func newOutbox() *outbox { return &outbox{sig: make(chan struct{}, 1)} }

// queue adds m. It reports false when the queue is full; then m drops.
func (o *outbox) queue(m *dpv1.SessionResponse) bool {
	o.mu.Lock()
	if len(o.msgs) >= maxSyncQueue {
		o.dropped++
		o.mu.Unlock()
		return false
	}
	o.msgs = append(o.msgs, m)
	o.mu.Unlock()
	o.poke()
	return true
}

// room reports whether the queue can take one more message.
func (o *outbox) room() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.msgs) < maxSyncQueue
}

// setReport makes r the next receive report. A newer one replaces it.
func (o *outbox) setReport(r *dpv1.RxReport) {
	o.mu.Lock()
	o.report = r
	o.mu.Unlock()
	o.poke()
}

func (o *outbox) poke() {
	select {
	case o.sig <- struct{}{}:
	default:
	}
}

func (o *outbox) take() ([]*dpv1.SessionResponse, *dpv1.RxReport) {
	o.mu.Lock()
	defer o.mu.Unlock()
	msgs, rep := o.msgs, o.report
	o.msgs, o.report = nil, nil
	return msgs, rep
}

// writer is the stream writer task of A. It sends the route changes, in parts, from the route
// table value of A, then the queued messages.
type writer struct {
	st     sessionStream
	values *valueMap // The down map of A, with the route table.
	s      session
	out    *outbox
	sent   map[netip.Prefix]*dpv1.Route
	rev    uint64
}

// run sends head, then the changes at each poke, until ctx ends or a send fails.
func (w *writer) run(ctx context.Context, head []*dpv1.SessionResponse) error {
	for _, m := range head {
		if err := w.st.Send(m); err != nil {
			return err
		}
	}
	w.out.poke()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.out.sig:
		}
		for _, m := range w.take() {
			if err := w.st.Send(m); err != nil {
				return err
			}
		}
	}
}

// take returns the messages that wait: the route changes as RouteDelta parts, then the queued
// messages and the receive report. The first take sends one more RouteDelta with no routes, which
// ends the first table.
func (w *writer) take() []*dpv1.SessionResponse {
	first := w.rev == 0
	var out []*dpv1.SessionResponse
	for _, d := range w.parts(load[*routeTable](w.values, keyRoutes).view(w.s)) {
		out = append(out, &dpv1.SessionResponse{Msg: &dpv1.SessionResponse_RouteDelta{RouteDelta: d}})
	}
	if first {
		w.rev++
		out = append(out, &dpv1.SessionResponse{Msg: &dpv1.SessionResponse_RouteDelta{RouteDelta: &dpv1.RouteDelta{Rev: w.rev}}})
	}
	msgs, rep := w.out.take()
	out = append(out, msgs...)
	if rep != nil {
		out = append(out, &dpv1.SessionResponse{Msg: &dpv1.SessionResponse_RxReport{RxReport: rep}})
	}
	return out
}

// change is the change of the route of one prefix.
type change struct {
	prefix      netip.Prefix
	remove, add *dpv1.Route
}

// parts returns the changes from the routes that the agent has to want, in RouteDeltas. A part
// closes before the changes of a prefix that would take it above maxDeltaRoutes routes or
// maxDeltaBytes bytes.
func (w *writer) parts(want map[netip.Prefix]*dpv1.Route) []*dpv1.RouteDelta {
	if w.sent == nil {
		w.sent = map[netip.Prefix]*dpv1.Route{}
	}
	var changes []change
	for p, r := range want {
		switch old := w.sent[p]; {
		case old == nil:
			changes = append(changes, change{prefix: p, add: r})
		case old.GetOrigin() != r.GetOrigin():
			changes = append(changes, change{prefix: p, remove: old, add: r})
		case !proto.Equal(old, r):
			// The route stays, with a new standby list or relay.
			changes = append(changes, change{prefix: p, add: r})
		}
	}
	for p, old := range w.sent {
		if want[p] == nil {
			changes = append(changes, change{prefix: p, remove: old})
		}
	}
	slices.SortFunc(changes, func(a, b change) int {
		return cmp.Or(a.prefix.Addr().Compare(b.prefix.Addr()), cmp.Compare(a.prefix.Bits(), b.prefix.Bits()))
	})
	var out []*dpv1.RouteDelta
	var cur *dpv1.RouteDelta
	n, size := 0, 0
	for _, c := range changes {
		cn, csize := 0, 0
		for _, r := range []*dpv1.Route{c.remove, c.add} {
			if r != nil {
				cn++
				csize += proto.Size(r)
			}
		}
		if cur == nil || (n > 0 && (n+cn > maxDeltaRoutes || size+csize > maxDeltaBytes)) {
			w.rev++
			cur = &dpv1.RouteDelta{Rev: w.rev}
			out = append(out, cur)
			n, size = 0, 0
		}
		if c.remove != nil {
			cur.Remove = append(cur.Remove, c.remove)
			delete(w.sent, c.prefix)
		}
		if c.add != nil {
			cur.Add = append(cur.Add, c.add)
			w.sent[c.prefix] = c.add
		}
		n, size = n+cn, size+csize
	}
	return out
}
