// SPDX-License-Identifier: AGPL-3.0-only

package relay_test

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// benchRoutes is the number of advertised routes in the VPC of the benchmarks.
const benchRoutes = 100_000

// manyRoutes returns n advertised /64 routes in 2001:db8::/32.
func manyRoutes(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("2001:db8:%x:%x::/64", i>>16, i&0xffff)
	}
	return out
}

// requireAccepted checks that the relay accepted each advertised route of res.
func requireAccepted(t testing.TB, res *dpv1.AttachResponse) {
	t.Helper()
	require.NotEmpty(t, res.GetRoutes())
	for _, r := range res.GetRoutes() {
		if r.GetResult() != dpv1.RouteResult_ROUTE_RESULT_ACCEPTED {
			t.Fatalf("route %s: %s", r.GetPrefix(), r.GetResult())
		}
	}
}

// waitPass sends packets of a from src to dst until one gets to to. It waits 1 ms for each
// packet, so that the time of a benchmark operation has an error of about 1 ms.
func (a *agent) waitPass(to *agent, src, dst netip.Addr) {
	a.t.Helper()
	deadline := time.Now().Add(wait)
	for !a.delivers(to, src, dst, time.Millisecond) {
		if time.Now().After(deadline) {
			a.t.Fatalf("no packet of %s from %s to %s", a.name, src, dst)
		}
	}
}

// benchEnv starts a relay with no mesh that writes each change at once, and attaches agent x
// and agent y.
func benchEnv(b *testing.B) (e *env, x, y *agent, resX, resY *dpv1.AttachResponse) {
	b.Helper()
	e = newEnvWith(b, envOpts{interval: new(time.Duration(0))})
	x = e.dial(b, "agent-x")
	x.open(dpv1.Mode_MODE_QUIC)
	resX = x.attach()
	y = e.dial(b, "agent-y")
	y.open(dpv1.Mode_MODE_QUIC)
	resY = y.attach()
	return e, x, y, resX, resY
}

// BenchmarkFallbackReport measures one report of remote addresses of x in a VPC with 100,000
// routes of agent w: from the send of the report until a packet of x from a reported address
// gets to y. Each report replaces the last one with other addresses, so the relay checks each
// address of each report. The time also has the route table copy of V and the writes of the
// step.
func BenchmarkFallbackReport(b *testing.B) {
	for _, n := range []int{1, 64} {
		b.Run(fmt.Sprintf("addresses=%d", n), func(b *testing.B) {
			e, x, y, resX, resY := benchEnv(b)
			w := e.dial(b, "agent-w")
			w.open(dpv1.Mode_MODE_QUIC)
			routes := manyRoutes(benchRoutes)
			requireAccepted(b, w.attach(routes...))
			// The route views of the sessions are sent before the first report.
			x.waitRoute(routes[len(routes)-1], true)
			y.waitRoute(routes[len(routes)-1], true)
			py := addr(b, resY)
			// The reports use 256 sets of n addresses of the VPC network in turn.
			sets := make([][]string, 256)
			for i := range sets {
				sets[i] = make([]string, n)
				for j := range sets[i] {
					sets[i][j] = fmt.Sprintf("fd61:706f:7879:12:3400:%x::/96", 0x8000+i*n+j)
				}
			}
			i := 0
			for b.Loop() {
				set := sets[i%len(sets)]
				i++
				x.report(resX.GetAttachmentId(), "relay-2", "far", set...)
				x.waitPass(y, overlay(set[n-1]), py)
			}
		})
	}
}

// BenchmarkFallbackSync measures the steps of V with 100,000 changes while x has a report of
// remote addresses: agent w attaches with 100,000 routes (add), then detaches (remove). The time
// of each is from the call until its answer, which comes after the writes of the step.
func BenchmarkFallbackSync(b *testing.B) {
	e, x, y, resX, resY := benchEnv(b)
	reported := "fd61:706f:7879:12:3400:8000::/96"
	x.report(resX.GetAttachmentId(), "relay-2", "far", reported)
	x.waitPass(y, overlay(reported), addr(b, resY))
	w := e.dial(b, "agent-w")
	w.open(dpv1.Mode_MODE_QUIC)
	routes := manyRoutes(benchRoutes)
	// One add and remove before the timed ones checks that the relay accepts the routes.
	res := w.attach(routes...)
	requireAccepted(b, res)
	w.detach(res.GetAttachmentId())
	var add, remove time.Duration
	for b.Loop() {
		start := time.Now()
		res := w.attach(routes...)
		mid := time.Now()
		w.detach(res.GetAttachmentId())
		add, remove = add+mid.Sub(start), remove+time.Since(mid)
	}
	b.ReportMetric(float64(add.Nanoseconds())/float64(b.N), "add-ns/op")
	b.ReportMetric(float64(remove.Nanoseconds())/float64(b.N), "remove-ns/op")
}
