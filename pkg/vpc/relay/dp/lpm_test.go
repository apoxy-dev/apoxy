// SPDX-License-Identifier: AGPL-3.0-only

package dp_test

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/softpsp/psp"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
)

// sealA1 returns the PSP packet of A1 with sequence number seq for an IPv4 or IPv6 packet.
func sealA1(t *testing.T, seq uint32, inner []byte) []byte {
	t.Helper()
	a, err := psp.NewAEAD(key(spiA1In))
	require.NoError(t, err)
	out := make([]byte, len(inner)+psp.Overhead)
	h := psp.Header{Version: psp.AESGCM128, SPI: spiA1In, IV: uint64(seq), VNI: vniA, Flags: psp.FlagSeq, Seq: seq}
	n, err := psp.Seal(a, h, out, inner)
	require.NoError(t, err)
	return out[:n]
}

// TestLPM checks the longest-prefix match of the source and route tables with packets from A1. A
// packet goes to the address of its out port, is a miss (a punt to the root), or is a drop. After
// the Writes, a Read of all tables gives the entries of the case.
func TestLPM(t *testing.T) {
	toA2 := func(p string) *p4.TableEntry { return route(vpcA, p, 2, 32, 2, 32) }
	toA4 := func(p string) *p4.TableEntry { return route(vpcA, p, 4, 44, 4, 44) }
	toT := func(p string) *p4.TableEntry { return route(vpcA, p, 10, 38, 10, 38) }
	src := func(p string, a dp.Action) *p4.TableEntry { return source(1, 1, 0, p, a) }
	src6e := src("2001:db8:a::/48", dp.NoAction{})
	src6 := insert(src6e)
	srcA1 := []*p4.TableEntry{src("100.64.1.0/24", dp.NoAction{}), src("100.64.77.7/32", dp.DropAction{Reason: 31})} // In base.
	bad := remove(route("uid-x/1", "10.0.0.0/8", 1, 1, 1, 1))                                                        // No such route.
	a2, a4, at, miss := addrA2.String(), addrA4.String(), addrT.String(), "miss"
	drop := func(reason uint8) string { return "drop " + strconv.Itoa(int(reason)) }
	const v4, v6 = "100.64.1.5", "2001:db8:a::5" // Sources of A1 that pass.

	type pkt struct{ src, dst, want string }
	cases := []struct {
		name   string
		writes [][]*p4.Update // Each Write must pass.
		failed []*p4.Update   // After writes: a Write that fails at the last update.
		next   []*p4.Update   // After failed: a Write that must pass.
		// The table entries after writes and after failed, other than those of base, and the
		// entries of base that writes delete.
		tables, gone []*p4.TableEntry
		after        []*p4.TableEntry // The table entries after next, other than those of base.
		pkts         []pkt
	}{
		{
			name:   "the longest IPv4 prefix",
			writes: [][]*p4.Update{{insert(toA2("10.0.0.0/8")), insert(toA4("10.1.0.0/16")), insert(toA2("10.1.2.3/32"))}},
			tables: []*p4.TableEntry{toA2("10.0.0.0/8"), toA4("10.1.0.0/16"), toA2("10.1.2.3/32")},
			pkts:   []pkt{{v4, "10.1.2.3", a2}, {v4, "10.1.2.4", a4}, {v4, "10.9.0.1", a2}, {v4, "11.0.0.1", miss}},
		},
		{
			name:   "the longest IPv6 prefix",
			writes: [][]*p4.Update{{src6, insert(toA2("2001:db8::/32")), insert(toA4("2001:db8:1::/48")), insert(toA2("2001:db8:1::7/128"))}},
			tables: []*p4.TableEntry{src6e, toA2("2001:db8::/32"), toA4("2001:db8:1::/48"), toA2("2001:db8:1::7/128")},
			pkts:   []pkt{{v6, "2001:db8:1::7", a2}, {v6, "2001:db8:1::8", a4}, {v6, "2001:db8:2::1", a2}, {v6, "2001:db9::1", miss}},
		},
		{
			name:   "0.0.0.0/0 does not match IPv6 addresses",
			writes: [][]*p4.Update{{src6, insert(toA2("0.0.0.0/0")), insert(toA4("2001:db8::/32"))}},
			tables: []*p4.TableEntry{src6e, toA2("0.0.0.0/0"), toA4("2001:db8::/32")},
			pkts:   []pkt{{v4, "11.0.0.1", a2}, {v6, "2001:db8::1", a4}, {v6, "2001:db9::1", miss}},
		},
		{
			name:   "the default route ::/0 matches IPv4 and IPv6 addresses",
			writes: [][]*p4.Update{{src6, insert(toA4("::/0")), insert(toA2("10.0.0.0/8"))}},
			tables: []*p4.TableEntry{src6e, toA4("::/0"), toA2("10.0.0.0/8")},
			pkts:   []pkt{{v4, "10.0.0.1", a2}, {v4, "11.0.0.1", a4}, {v6, "2001:db8::1", a4}},
		},
		{
			name:   "0.0.0.0/0 is longer than ::/0",
			writes: [][]*p4.Update{{src6, insert(toA4("::/0")), insert(toA2("0.0.0.0/0"))}},
			tables: []*p4.TableEntry{src6e, toA4("::/0"), toA2("0.0.0.0/0")},
			pkts:   []pkt{{v4, "11.0.0.1", a2}, {v6, "2001:db8::1", a4}},
		},
		{
			name:   "an IPv4-mapped IPv6 address matches the IPv4 prefixes",
			writes: [][]*p4.Update{{src6, insert(toA4("10.1.0.0/16")), insert(toA2("::/0"))}},
			tables: []*p4.TableEntry{src6e, toA4("10.1.0.0/16"), toA2("::/0")},
			pkts:   []pkt{{v6, "::ffff:10.1.2.3", a4}, {v6, "::ffff:11.0.0.1", a2}},
		},
		{
			// 100.64.8.0/24 goes to T. The /32 source 100.64.77.7 of base drops in the /16.
			name:   "the longest source prefix",
			writes: [][]*p4.Update{{src6, insert(src("100.64.0.0/16", dp.NoAction{}))}},
			tables: []*p4.TableEntry{src6e, src("100.64.0.0/16", dp.NoAction{})},
			pkts: []pkt{
				{"100.64.77.7", "100.64.8.5", drop(31)}, {"100.64.77.8", "100.64.8.5", at},
				{"100.65.0.1", "100.64.8.5", drop(dp.ReasonSource)},
				{v6, "2001:db8::1", miss}, {"2001:db8:b::5", "2001:db8::1", drop(dp.ReasonSource)},
			},
		},
		{
			name:   "a DELETE gives the next longest prefix",
			writes: [][]*p4.Update{{insert(toA2("10.0.0.0/8")), insert(toA4("10.1.0.0/16"))}, {remove(toA4("10.1.0.0/16"))}},
			tables: []*p4.TableEntry{toA2("10.0.0.0/8")},
			pkts:   []pkt{{v4, "10.1.2.3", a2}},
		},
		{
			name:   "a DELETE of the last prefix of a source set",
			writes: [][]*p4.Update{{remove(src("100.64.1.0/24", nil)), remove(src("100.64.77.7/32", nil))}},
			gone:   srcA1,
			pkts:   []pkt{{v4, "100.64.2.5", drop(dp.ReasonSource)}},
		},
		{
			name: "an INSERT after a DELETE of the last prefix",
			writes: [][]*p4.Update{
				{remove(src("100.64.1.0/24", nil)), remove(src("100.64.77.7/32", nil))},
				{insert(src("100.64.0.0/16", dp.NoAction{}))},
			},
			tables: []*p4.TableEntry{src("100.64.0.0/16", dp.NoAction{})},
			gone:   srcA1,
			pkts:   []pkt{{v4, "100.64.2.5", a2}, {"100.64.77.7", "100.64.8.5", at}},
		},
		{
			name:   "a DELETE and an INSERT of a prefix in one Write",
			writes: [][]*p4.Update{{insert(toA4("10.1.0.0/16"))}, {remove(toA4("10.1.0.0/16")), insert(toT("10.1.0.0/16"))}},
			tables: []*p4.TableEntry{toT("10.1.0.0/16")},
			pkts:   []pkt{{v4, "10.1.2.3", at}},
		},
		{
			name:   "an INSERT and a DELETE of a prefix in one Write",
			writes: [][]*p4.Update{{insert(toA2("10.0.0.0/8"))}, {insert(toA4("10.1.0.0/16")), remove(toA4("10.1.0.0/16"))}},
			tables: []*p4.TableEntry{toA2("10.0.0.0/8")},
			pkts:   []pkt{{v4, "10.1.2.3", a2}},
		},
		{
			name:   "a MODIFY",
			writes: [][]*p4.Update{{insert(toA4("10.1.0.0/16")), insert(toA4("2001:db8::/32")), src6}, {modify(toT("10.1.0.0/16"))}},
			tables: []*p4.TableEntry{toT("10.1.0.0/16"), toA4("2001:db8::/32"), src6e},
			pkts:   []pkt{{v4, "10.1.2.3", at}, {v6, "2001:db8::1", a4}},
		},
		{
			name:   "a failed Write leaves the old tries",
			writes: [][]*p4.Update{{insert(toA2("10.0.0.0/8")), insert(toA4("10.1.0.0/16"))}},
			failed: []*p4.Update{
				insert(toA2("10.1.2.0/24")), remove(toA4("10.1.0.0/16")), modify(toA4("10.0.0.0/8")),
				remove(src("100.64.1.0/24", nil)), insert(src("100.65.0.0/16", dp.NoAction{})),
			},
			tables: []*p4.TableEntry{toA2("10.0.0.0/8"), toA4("10.1.0.0/16")},
			pkts:   []pkt{{v4, "10.1.2.3", a4}, {v4, "10.2.0.1", a2}, {"100.65.0.1", "10.2.0.1", drop(dp.ReasonSource)}},
		},
		{
			name:   "a Write after a failed Write",
			writes: [][]*p4.Update{{insert(toA2("10.0.0.0/8")), insert(toA4("10.1.0.0/16"))}},
			failed: []*p4.Update{insert(toA2("10.1.2.0/24")), remove(toA4("10.1.0.0/16"))},
			next:   []*p4.Update{insert(toT("10.1.2.0/24"))},
			tables: []*p4.TableEntry{toA2("10.0.0.0/8"), toA4("10.1.0.0/16")},
			after:  []*p4.TableEntry{toA2("10.0.0.0/8"), toA4("10.1.0.0/16"), toT("10.1.2.0/24")},
			pkts:   []pkt{{v4, "10.1.2.3", at}, {v4, "10.1.3.1", a4}, {v4, "10.2.0.1", a2}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// withBase returns the entries of base without gone, and es.
			withBase := func(es []*p4.TableEntry) []*p4.TableEntry {
				out := slices.DeleteFunc(baseTables(), func(e *p4.TableEntry) bool {
					return slices.ContainsFunc(tc.gone, func(g *p4.TableEntry) bool { return proto.Equal(e, g) })
				})
				return append(out, es...)
			}
			r := newRelay(t)
			for _, w := range tc.writes {
				require.NoError(t, write(t.Context(), r, w...))
			}
			assertEntries(t, withBase(tc.tables), readTable(t, r, 0, ""))
			if tc.failed != nil {
				// Each update before bad is aborted, and bad is not found.
				err := write(t.Context(), r, append(tc.failed, bad)...)
				require.Error(t, err)
				st := status.Convert(err)
				assert.Equal(t, codes.Unknown, st.Code())
				want := slices.Repeat([]codes.Code{codes.Aborted}, len(tc.failed))
				var got []codes.Code
				for _, d := range st.Details() {
					got = append(got, codes.Code(d.(*p4.Error).GetCanonicalCode()))
				}
				require.Equal(t, append(want, codes.NotFound), got)
				assertEntries(t, withBase(tc.tables), readTable(t, r, 0, ""))
			}
			if tc.next != nil {
				require.NoError(t, write(t.Context(), r, tc.next...))
				assertEntries(t, withBase(tc.after), readTable(t, r, 0, ""))
			}
			var want, got []string
			for i, p := range tc.pkts {
				var inner []byte
				if netip.MustParseAddr(p.src).Is4() {
					inner = ipv4(p.src, p.dst, 100)
				} else {
					inner = ipv6(p.src, p.dst, 100)
				}
				sent, in, drops := len(r.sent), len(r.in), counts(t, r, dp.CounterDrops)
				r.receive(addrA1, sealA1(t, uint32(i+1), inner))
				out := "none"
				switch {
				case len(r.sent) > sent:
					out = r.sent[sent].to.String()
				case len(r.in) > in:
					md, err := dp.DecodePacketInMeta(r.in[in].GetMetadata())
					require.NoError(t, err)
					out = "punt " + strconv.Itoa(int(md.Kind))
					if md.Kind == dp.KindMiss {
						out = miss
					}
				default:
					for reason, n := range counts(t, r, dp.CounterDrops) {
						if n > drops[reason] {
							out = drop(uint8(reason))
						}
					}
				}
				want, got = append(want, p.src+" to "+p.dst+": "+p.want), append(got, p.src+" to "+p.dst+": "+out)
			}
			assert.Equal(t, want, got)
		})
	}
}

// TestLPMWrites sends packets from 100.64.1.5 to 10.1.0.5 while Writes change the tries between two
// states. A packet that sees a part of a Write has a result that no whole state gives.
func TestLPMWrites(t *testing.T) {
	toA2, toA4 := route(vpcA, "10.1.0.0/16", 2, 32, 2, 32), route(vpcA, "10.1.0.0/16", 4, 44, 4, 44)
	slice := route(vpcA, "10.1.0.0/24", 2, 32, 2, 32)
	routeDrop := dp.RouteKey{VPC: vpcA, Dst: pfx("10.1.0.0/16")}.Entry(dp.DropAction{Reason: 31})
	host5 := source(1, 1, 0, "100.64.1.5/32", dp.NoAction{})
	srcPass := source(1, 1, 0, "100.64.1.0/24", dp.NoAction{}) // The base entries have this source.
	srcDrop := source(1, 1, 0, "100.64.1.0/24", dp.DropAction{Reason: 30})
	cases := []struct {
		name string
		// start is the Write to state 0 after base, and to has the Writes into state 0 and state 1.
		start []*p4.Update
		to    [2][]*p4.Update
		// add has the entries of each state other than those of base; swap replaces srcPass in state 0.
		add  [2][]*p4.TableEntry
		swap *p4.TableEntry
		// With deliver, each whole state sends the packet to A2. Else each whole state drops it.
		deliver bool
	}{
		{
			// In state 0, the /16 goes to A4 and the /24 goes to A2. State 1 moves the /16 to A2, removes
			// the /24 and adds a /32 source. A part of a Write sends the packet to A4.
			name:  "one table",
			start: []*p4.Update{insert(toA4), insert(slice)},
			to: [2][]*p4.Update{
				{remove(host5), modify(toA4), insert(slice)},
				{insert(host5), remove(slice), modify(toA2)},
			},
			add:     [2][]*p4.TableEntry{{toA4, slice}, {toA2, host5}},
			deliver: true,
		},
		{
			// In state 0, the source drops the packet and the route goes to A2. In state 1, the source
			// passes it and the route drops it. Only a mix of the two states delivers the packet.
			name:  "two tables",
			start: []*p4.Update{modify(srcDrop), insert(toA2)},
			to: [2][]*p4.Update{
				{modify(toA2), modify(srcDrop)},
				{modify(srcPass), modify(routeDrop)},
			},
			add:  [2][]*p4.TableEntry{{toA2}, {routeDrop}},
			swap: srcDrop,
		},
	}
	host := func(j int) *p4.TableEntry {
		return route(vpcA, "10.1."+strconv.Itoa(1+j/150)+"."+strconv.Itoa(j%150)+"/32", 2, 32, 2, 32)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// want returns the table entries after Write i, as a set: base with the entries of the
			// state of Write i, and the 300 routes after an INSERT Write and before the next DELETE.
			want := func(i int) (map[string]bool, error) {
				st := (i + 1) % 2
				es := slices.Clone(tc.add[st])
				for _, e := range baseTables() {
					if st == 0 && tc.swap != nil && proto.Equal(e, srcPass) {
						e = tc.swap
					}
					es = append(es, e)
				}
				if i%4 == 0 || i%4 == 1 {
					for j := range 300 {
						es = append(es, host(j))
					}
				}
				return entrySet(es)
			}
			r := newRelay(t, tc.start...)
			stop, errc := make(chan struct{}), make(chan error, 1)
			var writes atomic.Int64
			go func() {
				for i := 0; ; i++ {
					select {
					case <-stop:
						errc <- nil
						return
					default:
					}
					us := slices.Clone(tc.to[(i+1)%2])
					for j := range 300 {
						e := host(j)
						switch i % 4 {
						case 0:
							us = append(us, insert(e))
						case 2:
							us = append(us, remove(e))
						}
					}
					if err := write(context.Background(), r, us...); err != nil {
						errc <- err
						return
					}
					var es []*p4.TableEntry
					req := &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_TableEntry{TableEntry: &p4.TableEntry{}}}}}
					if err := r.Read(context.Background(), req, func(e *p4.Entity) { es = append(es, e.GetTableEntry()) }); err != nil {
						errc <- err
						return
					}
					got, err := entrySet(es)
					if err != nil {
						errc <- err
						return
					}
					exp, err := want(i)
					if err != nil {
						errc <- err
						return
					}
					if !maps.Equal(exp, got) {
						errc <- fmt.Errorf("the tables after Write %d: %d entries, want %d entries", i, len(got), len(exp))
						return
					}
					writes.Add(1)
				}
			}()
			// The loop sends at least 2000 packets, and runs until 20 Writes are done or one fails.
			seq := uint32(1)
			for ; seq <= 2000 || (writes.Load() < 20 && len(errc) == 0); seq++ {
				r.receive(addrA1, seal(spiA1In, vniA, seq, ipv4("100.64.1.5", "10.1.0.5", 100)))
			}
			close(stop)
			require.NoError(t, <-errc)
			if tc.deliver {
				require.Len(t, r.sent, int(seq-1))
				for _, s := range r.sent {
					assert.Equal(t, addrA2, s.to)
				}
				assert.Empty(t, counts(t, r, dp.CounterDrops))
				return
			}
			assert.Empty(t, r.sent)
			drops := counts(t, r, dp.CounterDrops)
			assert.Equal(t, int64(seq-1), drops[30]+drops[31], "drops of the source (30) and of the route (31): %v", drops)
		})
	}
}

// entrySet returns the table entries es as a set of deterministic bytes.
func entrySet(es []*p4.TableEntry) (map[string]bool, error) {
	set := map[string]bool{}
	for _, e := range es {
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(e)
		if err != nil {
			return nil, err
		}
		set[string(b)] = true
	}
	return set, nil
}
