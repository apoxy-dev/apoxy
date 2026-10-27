// SPDX-License-Identifier: AGPL-3.0-only

package dp_test

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp/aead"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// nopSender drops the batches of a benchmark.
type nopSender struct{}

func (nopSender) Send(*dp.TxBatch) {}

const (
	// benchInner is the size of the inner packets of the receive benchmark.
	benchInner = 1350
	// benchPass is the packets of each agent between two writes of its RX entry, which give it a
	// new replay window.
	benchPass = 4096
)

func benchSPI(k int) uint32 { return uint32(0x1000 + k) }

// benchPipeline returns a pipeline with agents 1 to n (port k, 100.64.k.0/24) that send to the
// agent at port 100 (100.64.200.0/24).
func benchPipeline(b *testing.B, n int) *dp.Pipeline {
	b.Helper()
	p := dp.New(nopSender{}, aead.GCM{})
	us := []*p4.Update{
		insert(dp.PortsKey{Port: 100}.Entry(dp.PortAction{Session: 1, Addr: addrA2, MTU: 9000, MeterIndex: 100})),
		insert(route(vpcA, "100.64.200.0/24", 100, 300, 100, 300)),
		tx(0x200, 100, 1, 0),
	}
	for k := 1; k <= n; k++ {
		port := uint64(k)
		us = append(us,
			insert(dp.PortsKey{Port: port}.Entry(dp.PortAction{Session: 1, Addr: benchAddr(k), MTU: 9000, MeterIndex: uint32(k)})),
			insert(context_(port, 1, 0, vpcA, vniA, uint32(k))),
			insert(source(port, 1, 0, fmt.Sprintf("100.64.%d.0/24", k), dp.NoAction{})),
			rx(benchSPI(k), port, 1, 0),
		)
	}
	mustWrite(b, p, us...)
	return p
}

func benchAddr(k int) netip.AddrPort { return netip.AddrPortFrom(addrA1.Addr(), uint16(5000+k)) }

func mustWrite(b *testing.B, p *dp.Pipeline, us ...*p4.Update) {
	b.Helper()
	if err := write(b.Context(), p, us...); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkReceive runs the pipeline alone on packets of 1350 inner bytes, with 1 to 8 workers. Each
// worker has its own agent and TxBatch, and receives in parts of 64 packets. One op is one packet.
func BenchmarkReceive(b *testing.B) {
	for _, workers := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			p := benchPipeline(b, workers)
			pkts := make([][]dp.RxPacket, workers)
			var renew []*p4.Update
			for k := range workers {
				src := fmt.Sprintf("100.64.%d.5", k+1)
				for seq := uint32(1); seq <= benchPass; seq++ {
					pkts[k] = append(pkts[k], dp.RxPacket{From: benchAddr(k + 1), Payload: seal(benchSPI(k+1), vniA, seq, ipv4(src, "100.64.200.5", benchInner))})
				}
				renew = append(renew,
					keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: benchSPI(k + 1)}),
					rx(benchSPI(k+1), uint64(k+1), 1, 0))
			}
			// Worker k receives the first n packets of its agent for each n on its channel.
			var wg sync.WaitGroup
			work := make([]chan int, workers)
			for k := range workers {
				work[k] = make(chan int)
				go func() {
					tx := &dp.TxBatch{}
					for n := range work[k] {
						p.Receive(pkts[k][:n], tx)
						wg.Done()
					}
				}()
			}
			defer func() {
				for _, c := range work {
					close(c)
				}
			}()
			pass := func(n int) {
				per := (n + workers - 1) / workers
				for k := range workers {
					if m := min(per, n-k*per); m > 0 {
						wg.Add(1)
						work[k] <- m
					}
				}
				wg.Wait()
			}
			pass(workers * benchPass) // The batches grow to their size.
			mustWrite(b, p, renew...)
			b.SetBytes(benchInner)
			b.ReportAllocs()
			b.ResetTimer()
			for left := b.N; left > 0; {
				n := min(left, workers*benchPass)
				pass(n)
				left -= n
				b.StopTimer()
				mustWrite(b, p, renew...)
				b.StartTimer()
			}
			b.StopTimer()
			var drops int64
			err := p.Read(b.Context(), &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{CounterId: dp.CounterDrops}}}}},
				func(e *p4.Entity) { drops += e.GetCounterEntry().GetData().GetPacketCount() })
			if err != nil || drops != 0 {
				b.Fatalf("drops %d: %v", drops, err)
			}
		})
	}
}

// BenchmarkWrite measures Writes with 100k routes of one VPC: one Write of 100k route INSERTs, one
// Write of one route MODIFY, and one Write of one ports entry MODIFY. One op is one Write.
func BenchmarkWrite(b *testing.B) {
	const routes = 100_000
	routeAt := func(i int, port uint64) *p4.TableEntry {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		return dp.RouteKey{VPC: vpcA, Dst: netip.PrefixFrom(a, 32)}.Entry(dp.ForwardAction{Port: port, Cell: 300, LocalPort: port, LocalCell: 300})
	}
	var ins, del []*p4.Update
	for i := range routes {
		ins, del = append(ins, insert(routeAt(i, 100))), append(del, remove(routeAt(i, 100)))
	}
	portAt := func(mtu uint16) *p4.Update {
		return modify(dp.PortsKey{Port: 100}.Entry(dp.PortAction{Session: 1, Addr: addrA2, MTU: mtu, MeterIndex: 100}))
	}
	cases := []struct {
		name string
		ops  [2][]*p4.Update // Op i writes ops[i%2].
	}{
		{name: "route_of_100k", ops: [2][]*p4.Update{{modify(routeAt(routes/2, 1))}, {modify(routeAt(routes/2, 100))}}},
		{name: "port_with_100k", ops: [2][]*p4.Update{{portAt(8000)}, {portAt(9000)}}},
	}
	b.Run("insert_100k", func(b *testing.B) {
		p := benchPipeline(b, 1)
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			mustWrite(b, p, ins...)
			b.StopTimer()
			mustWrite(b, p, del...)
			b.StartTimer()
		}
	})
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			p := benchPipeline(b, 1)
			mustWrite(b, p, ins...)
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				mustWrite(b, p, tc.ops[i%2]...)
			}
		})
	}
}
