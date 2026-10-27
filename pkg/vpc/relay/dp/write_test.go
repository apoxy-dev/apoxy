// SPDX-License-Identifier: AGPL-3.0-only

package dp_test

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/softpsp/psp"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func withMetadata(e *p4.TableEntry, md string) *p4.TableEntry {
	e.Metadata = []byte(md)
	return e
}

// readTable returns the entries of a table with the metadata md.
func readTable(t *testing.T, tg dp.Target, table uint32, md string) []*p4.TableEntry {
	t.Helper()
	var got []*p4.TableEntry
	req := &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_TableEntry{TableEntry: &p4.TableEntry{TableId: table, Metadata: []byte(md)}}}}}
	require.NoError(t, tg.Read(t.Context(), req, func(e *p4.Entity) { got = append(got, e.GetTableEntry()) }))
	return got
}

func TestWrite(t *testing.T) {
	md := "p/50/1"
	port50 := withMetadata(access(50, netip.MustParseAddrPort("192.0.2.50:4000"), 50, 0), md)
	ctx50 := withMetadata(context_(50, 1, 0, "uid-c/1", 300, 50), md)
	route50 := withMetadata(route("uid-c/1", "2001:db8::/64", 50, 50, 50, 50), md)
	dropRoute := func(reason uint8) *p4.TableEntry {
		return withMetadata(dp.RouteKey{VPC: "uid-c/1", Dst: pfx("2001:db8:1::/64")}.Entry(dp.DropAction{Reason: reason}), md)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name      string
		ctx       context.Context
		atomicity p4.WriteRequest_Atomicity
		updates   []*p4.Update
		err       codes.Code   // The code of the call.
		details   []codes.Code // The code of each update.
		read      []*p4.TableEntry
	}{
		{
			name:    "a batch applies at one commit, and a Read gives back the VPC name",
			updates: []*p4.Update{insert(port50), insert(ctx50), insert(route50)},
			read:    []*p4.TableEntry{port50, ctx50, route50},
		},
		{
			name:    "an error stops the whole batch",
			updates: []*p4.Update{insert(port50), insert(ctx50), insert(access(1, addrA1, 7, 0))},
			err:     codes.Unknown,
			details: []codes.Code{codes.Aborted, codes.Aborted, codes.AlreadyExists},
		},
		{
			name:    "MODIFY of an entry that is not there",
			updates: []*p4.Update{insert(port50), modify(access(77, addrA1, 7, 0))},
			err:     codes.Unknown,
			details: []codes.Code{codes.Aborted, codes.NotFound},
		},
		{
			name: "DELETE of a route that is not there",
			updates: []*p4.Update{
				insert(port50), insert(ctx50),
				remove(route("uid-c/1", "2001:db8::/64", 50, 50, 50, 50)),
			},
			err:     codes.Unknown,
			details: []codes.Code{codes.Aborted, codes.Aborted, codes.NotFound},
		},
		{
			name:    "a key is never changed in place",
			updates: []*p4.Update{keys(p4.Update_MODIFY, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: spiA1In, Key: key(spiA1In), Port: 1, Session: 1})},
			err:     codes.Unknown,
			details: []codes.Code{codes.InvalidArgument},
		},
		{
			name:    "one TX entry for each lane",
			updates: []*p4.Update{tx(0x777, 1, 1, 0)},
			err:     codes.Unknown,
			details: []codes.Code{codes.AlreadyExists},
		},
		{
			name:    "an action that the table does not have",
			updates: []*p4.Update{insert(dp.ClassifyKey{Port: 50, Session: 1}.Entry(dp.ForwardAction{Port: 1}))},
			err:     codes.Unknown,
			details: []codes.Code{codes.InvalidArgument},
		},
		{
			name:    "a cell out of range",
			updates: []*p4.Update{insert(context_(50, 1, 0, vpcA, vniA, 1<<20))},
			err:     codes.Unknown,
			details: []codes.Code{codes.OutOfRange},
		},
		{
			name:    "a drop action with reason 31",
			updates: []*p4.Update{insert(port50), insert(ctx50), insert(dropRoute(31))},
			read:    []*p4.TableEntry{port50, ctx50, dropRoute(31)},
		},
		{
			name:    "a drop action with reason 32 is out of range",
			updates: []*p4.Update{insert(port50), insert(ctx50), insert(dropRoute(32))},
			err:     codes.Unknown,
			details: []codes.Code{codes.Aborted, codes.Aborted, codes.OutOfRange},
		},
		{
			name:    "a meter needs cir = pir",
			updates: []*p4.Update{meterUpdate(dp.MeterPort, 1, &p4.MeterConfig{Cir: 1, Cburst: 10, Pir: 2, Pburst: 10})},
			err:     codes.Unknown,
			details: []codes.Code{codes.InvalidArgument},
		},
		{
			name:      "only DATAPLANE_ATOMIC",
			atomicity: p4.WriteRequest_ROLLBACK_ON_ERROR,
			updates:   []*p4.Update{insert(port50)},
			err:       codes.InvalidArgument,
		},
		{
			name:    "a canceled call has no update errors",
			ctx:     canceled,
			updates: []*p4.Update{insert(port50)},
			err:     codes.Canceled,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t)
			ctx := tc.ctx
			if ctx == nil {
				ctx = t.Context()
			}
			atomicity := tc.atomicity
			if atomicity == 0 {
				atomicity = p4.WriteRequest_DATAPLANE_ATOMIC
			}
			err := r.Write(ctx, &p4.WriteRequest{Atomicity: atomicity, Updates: tc.updates})
			if tc.err == codes.OK {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				st := status.Convert(err)
				assert.Equal(t, tc.err, st.Code())
				var got []codes.Code
				for _, d := range st.Details() {
					got = append(got, codes.Code(d.(*p4.Error).GetCanonicalCode()))
				}
				assert.Equal(t, tc.details, got)
			}
			got := readTable(t, r, 0, md)
			if assert.Len(t, got, len(tc.read)) {
				for _, want := range tc.read {
					found := false
					for _, e := range got {
						found = found || proto.Equal(want, e)
					}
					assert.True(t, found, "entry %v", want)
				}
			}
		})
	}
}

// TestFinalCount deletes the entries that count into a cell, reads the cell and sets it to 0.
func TestFinalCount(t *testing.T) {
	r := newRelay(t)
	for seq := uint32(1); seq <= 2; seq++ {
		r.receive(addrA1, seal(spiA1In, vniA, seq, ipv4("100.64.1.5", "100.64.2.5", 100)))
	}
	require.NoError(t, write(t.Context(), r, remove(dp.PortsKey{Port: 1}.Entry(nil)), remove(dp.ClassifyKey{Port: 1, Session: 1}.Entry(nil))))
	r.receive(addrA1, seal(spiA1In, vniA, 3, ipv4("100.64.1.5", "100.64.2.5", 100)))

	cell := &p4.CounterEntry{CounterId: dp.CounterCells, Index: &p4.Index{Index: 2}}
	var got *p4.CounterData
	require.NoError(t, r.Read(t.Context(), &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_CounterEntry{CounterEntry: cell}}}},
		func(e *p4.Entity) { got = e.GetCounterEntry().GetData() }))
	assert.Equal(t, int64(2), got.GetPacketCount())
	assert.Equal(t, int64(200), got.GetByteCount())
	assert.Equal(t, map[int64]int64{int64(dp.ReasonOldSession): 1}, counts(t, r, dp.CounterDrops))

	reset := &p4.CounterEntry{CounterId: dp.CounterCells, Index: &p4.Index{Index: 2}, Data: &p4.CounterData{}}
	require.NoError(t, write(t.Context(), r, &p4.Update{Type: p4.Update_MODIFY, Entity: &p4.Entity{Entity: &p4.Entity_CounterEntry{CounterEntry: reset}}}))
	assert.NotContains(t, counts(t, r, dp.CounterCells), int64(2))
}

// readBack reads the entity e with e as the filter.
func readBack(t *testing.T, tg dp.Target, e *p4.Entity) []*p4.Entity {
	t.Helper()
	var got []*p4.Entity
	require.NoError(t, tg.Read(t.Context(), &p4.ReadRequest{Entities: []*p4.Entity{e}}, func(e *p4.Entity) { got = append(got, e) }))
	return got
}

// sameEntity tells if two entities are equal. A keys entry compares as its PspSaEntry.
func sameEntity(t *testing.T, want, got *p4.Entity) bool {
	t.Helper()
	if w := want.GetExternEntry(); w != nil {
		a, b := &dpv1.PspSaEntry{}, &dpv1.PspSaEntry{}
		require.NoError(t, w.GetEntry().UnmarshalTo(a))
		if got.GetExternEntry() == nil {
			return false
		}
		require.NoError(t, got.GetExternEntry().GetEntry().UnmarshalTo(b))
		return proto.Equal(a, b)
	}
	return proto.Equal(want, got)
}

func counterEntity(id uint32, index, packets, bytes int64) *p4.Entity {
	return &p4.Entity{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{
		CounterId: id, Index: &p4.Index{Index: index}, Data: &p4.CounterData{PacketCount: packets, ByteCount: bytes},
	}}}
}

// baseTables returns the table entries of base.
func baseTables() []*p4.TableEntry {
	var out []*p4.TableEntry
	for _, u := range base() {
		if e := u.GetEntity().GetTableEntry(); e != nil {
			out = append(out, e)
		}
	}
	return out
}

// assertEntries checks that got has the entries of want and no other entries.
func assertEntries(t *testing.T, want, got []*p4.TableEntry) {
	t.Helper()
	assert.Len(t, got, len(want))
	for _, w := range want {
		assert.True(t, slices.ContainsFunc(got, func(e *p4.TableEntry) bool { return proto.Equal(w, e) }), "entry %v", w)
	}
}

// keyEntry is a keys entry as a Read gives it.
type keyEntry struct {
	dir           dpv1.PspSaDirection
	spi           uint32
	port, session uint64
	lane          uint32
	packets       uint64
	seq           uint32
}

// readKeys returns all keys entries of tg, and checks that no key comes back.
func readKeys(t *testing.T, tg dp.Target) []keyEntry {
	t.Helper()
	var got []keyEntry
	all := &p4.Entity{Entity: &p4.Entity_ExternEntry{ExternEntry: &p4.ExternEntry{ExternTypeId: dp.ExternPspSa, ExternId: dp.ExternKeys}}}
	for _, e := range readBack(t, tg, all) {
		x := &dpv1.PspSaEntry{}
		require.NoError(t, e.GetExternEntry().GetEntry().UnmarshalTo(x))
		assert.Empty(t, x.GetKey(), "SPI %#x has no key in a Read", x.GetSpi())
		got = append(got, keyEntry{x.GetDirection(), x.GetSpi(), x.GetPort(), x.GetSession(), x.GetLane(), x.GetPackets(), x.GetSeq()})
	}
	return got
}

// baseKeys returns the keys entries of base, as a Read gives them before the first packet.
func baseKeys(t *testing.T) []keyEntry {
	t.Helper()
	var out []keyEntry
	for _, u := range base() {
		if x := u.GetEntity().GetExternEntry(); x != nil {
			e := &dpv1.PspSaEntry{}
			require.NoError(t, x.GetEntry().UnmarshalTo(e))
			out = append(out, keyEntry{dir: e.GetDirection(), spi: e.GetSpi(), port: e.GetPort(), session: e.GetSession(), lane: e.GetLane()})
		}
	}
	return out
}

// readMeters returns the meter indices of tg that have a config.
func readMeters(t *testing.T, tg dp.Target) []*p4.MeterEntry {
	t.Helper()
	var out []*p4.MeterEntry
	for _, e := range readBack(t, tg, &p4.Entity{Entity: &p4.Entity_MeterEntry{MeterEntry: &p4.MeterEntry{}}}) {
		out = append(out, e.GetMeterEntry())
	}
	return out
}

// TestFailedWrite checks that a Write with a failed update changes nothing: a Read gives back all
// table entries, all keys with their replay windows, the meter configs and the counters as they
// were, and the packets go as before. Packet 1 of A1 to A2 goes before the Write, then packet 2 and
// a replay of packet 1.
func TestFailedWrite(t *testing.T) {
	bad := remove(route("uid-x/1", "10.0.0.0/8", 1, 1, 1, 1)) // No such route.
	rxA1 := &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: spiA1In}
	txA2 := &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, Spi: spiA2Out, Port: 2, Session: 1}
	onePacket := &p4.MeterConfig{Cir: 1, Cburst: 200, Pir: 1, Pburst: 200} // 140 bytes go, the next 140 do not.
	zeroCell := &p4.Update{Type: p4.Update_MODIFY, Entity: counterEntity(dp.CounterCells, 2, 0, 0)}
	pass := map[int64]int64{int64(dp.ReasonOpen): 1}
	table := func(e *p4.TableEntry) *p4.Entity { return insert(e).GetEntity() }
	routeX := route("uid-x/1", "100.64.2.0/24", 4, 44, 4, 44)
	cases := []struct {
		name  string
		extra []*p4.Update // Before packet 1.
		batch []*p4.Update // The failed Write, before bad.
		want  []*p4.Entity // A Read with each as the filter gives it back after the failed Write.
		gone  []*p4.Entity // A Read with each as the filter gives nothing after the failed Write.
		// The table entries of extra, after those of base.
		tables []*p4.TableEntry
		next   []*p4.Update     // A Write after it, which must pass.
		after  []*p4.TableEntry // The table entries after next, after those of base.
		sent   []uint32         // The PSP sequence numbers of the packets to A2.
		drops  map[int64]int64
	}{
		{
			name:  "a removed RX key comes back with its replay window",
			batch: []*p4.Update{keys(p4.Update_DELETE, rxA1)},
			want: []*p4.Entity{keys(p4.Update_INSERT, &dpv1.PspSaEntry{
				Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: spiA1In, Port: 1, Session: 1, Packets: 1, Seq: 1,
			}).GetEntity()},
			sent: []uint32{0, 1}, drops: pass,
		},
		{
			name:  "a removed TX key comes back with its sequence number",
			batch: []*p4.Update{keys(p4.Update_DELETE, txA2)},
			want:  []*p4.Entity{keys(p4.Update_INSERT, txA2).GetEntity()},
			sent:  []uint32{0, 1}, drops: pass,
		},
		{
			name: "removed entries come back",
			batch: []*p4.Update{
				remove(dp.PortsKey{Port: 1}.Entry(nil)), remove(dp.ClassifyKey{Port: 1, Session: 1}.Entry(nil)),
				remove(source(1, 1, 0, "100.64.1.0/24", nil)), remove(route(vpcA, "100.64.2.0/24", 2, 32, 2, 32)),
			},
			want: []*p4.Entity{
				table(access(1, addrA1, 7, 4001<<32|4002<<16)), table(context_(1, 1, 0, vpcA, vniA, 1)),
				table(source(1, 1, 0, "100.64.1.0/24", dp.NoAction{})), table(route(vpcA, "100.64.2.0/24", 2, 32, 2, 32)),
			},
			sent: []uint32{0, 1}, drops: pass,
		},
		{
			name:  "a changed VPC of a context",
			batch: []*p4.Update{modify(context_(1, 1, 0, "uid-x/1", vniA, 1)), insert(routeX)},
			want:  []*p4.Entity{table(context_(1, 1, 0, vpcA, vniA, 1))},
			gone:  []*p4.Entity{table(routeX)},
			sent:  []uint32{0, 1}, drops: pass,
		},
		{
			name: "a failed INSERT and MODIFY in a route table with entries",
			batch: []*p4.Update{
				insert(route(vpcA, "100.64.7.0/24", 3, 37, 1, 31)), insert(route(vpcA, "100.64.2.128/25", 3, 33, 1, 31)),
				modify(route(vpcA, "100.64.2.0/24", 3, 33, 3, 33)),
			},
			sent: []uint32{0, 1}, drops: pass,
		},
		{
			name: "a failed INSERT and MODIFY in a source table with entries",
			batch: []*p4.Update{
				insert(source(1, 1, 0, "100.64.11.0/24", dp.NoAction{})), insert(source(1, 1, 0, "100.64.1.128/25", dp.LocalOnlyAction{})),
				modify(source(1, 1, 0, "100.64.1.0/24", dp.LocalOnlyAction{})),
			},
			sent: []uint32{0, 1}, drops: pass,
		},
		{
			name:  "a meter keeps its state",
			extra: []*p4.Update{meterUpdate(dp.MeterPort, 1, onePacket)},
			batch: []*p4.Update{meterUpdate(dp.MeterPort, 1, nil)},
			want:  []*p4.Entity{meterUpdate(dp.MeterPort, 1, onePacket).GetEntity()},
			sent:  []uint32{0}, drops: map[int64]int64{int64(dp.ReasonMeter): 1, int64(dp.ReasonOpen): 1},
		},
		{
			name:  "a meter keeps its config",
			extra: []*p4.Update{meterUpdate(dp.MeterPort, 1, onePacket)},
			batch: []*p4.Update{meterUpdate(dp.MeterPort, 1, &p4.MeterConfig{Cir: 1e9, Cburst: 1 << 20, Pir: 1e9, Pburst: 1 << 20})},
			want:  []*p4.Entity{meterUpdate(dp.MeterPort, 1, onePacket).GetEntity()},
			sent:  []uint32{0}, drops: map[int64]int64{int64(dp.ReasonMeter): 1, int64(dp.ReasonOpen): 1},
		},
		{
			name:  "a TX INSERT in a free lane of a port session and in a new port session",
			batch: []*p4.Update{tx(0x2b1, 2, 1, 1), tx(0x2b2, 50, 1, 0)},
			sent:  []uint32{0, 1}, drops: pass,
		},
		{
			name:  "a counter keeps its value",
			batch: []*p4.Update{zeroCell},
			want:  []*p4.Entity{counterEntity(dp.CounterCells, 2, 1, 100)}, // Packet 1, in the receive cell of A1.
			sent:  []uint32{0, 1}, drops: pass,
		},
		{
			name: "the free VPC numbers",
			extra: []*p4.Update{
				insert(route("uid-y/1", "100.64.2.0/24", 99, 1, 99, 1)),
				insert(route("uid-x/1", "10.1.0.0/16", 1, 1, 1, 1)), remove(route("uid-x/1", "10.1.0.0/16", 1, 1, 1, 1)),
			},
			// The batch takes the free number of uid-x/1 and frees the number of uid-y/1.
			batch:  []*p4.Update{insert(route("uid-z/1", "10.2.0.0/16", 1, 1, 1, 1)), remove(route("uid-y/1", "100.64.2.0/24", 99, 1, 99, 1))},
			want:   []*p4.Entity{table(route("uid-y/1", "100.64.2.0/24", 99, 1, 99, 1))},
			gone:   []*p4.Entity{table(route("uid-z/1", "10.2.0.0/16", 1, 1, 1, 1))},
			tables: []*p4.TableEntry{route("uid-y/1", "100.64.2.0/24", 99, 1, 99, 1)},
			// uid-w/1 gets the free number of uid-x/1, not the number of uid-y/1, which has this prefix.
			// The route of uid-y/1 stays as it is.
			next:  []*p4.Update{insert(route("uid-w/1", "100.64.2.0/24", 2, 32, 2, 32))},
			after: []*p4.TableEntry{route("uid-y/1", "100.64.2.0/24", 99, 1, 99, 1), route("uid-w/1", "100.64.2.0/24", 2, 32, 2, 32)},
			sent:  []uint32{0, 1}, drops: pass,
		},
	}
	toA2 := func(seq uint32) []byte { return seal(spiA1In, vniA, seq, ipv4("100.64.1.5", "100.64.2.5", 100)) }
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t, tc.extra...)
			r.receive(addrA1, toA2(1))
			err := write(t.Context(), r, append(tc.batch, bad)...)
			require.Error(t, err)
			st := status.Convert(err)
			assert.Equal(t, codes.Unknown, st.Code())
			// Each update before bad is aborted, and bad is not found.
			var codesOf []codes.Code
			for _, d := range st.Details() {
				codesOf = append(codesOf, codes.Code(d.(*p4.Error).GetCanonicalCode()))
			}
			assert.Equal(t, append(slices.Repeat([]codes.Code{codes.Aborted}, len(tc.batch)), codes.NotFound), codesOf, "the code of each update")
			for _, w := range tc.want {
				got := readBack(t, r, w)
				if assert.Len(t, got, 1, "%v", w) {
					assert.True(t, sameEntity(t, w, got[0]), "want %v, got %v", w, got[0])
				}
			}
			for _, g := range tc.gone {
				assert.Empty(t, readBack(t, r, g), "%v", g)
			}
			assertEntries(t, append(baseTables(), tc.tables...), readTable(t, r, 0, ""))
			// Packet 1 is the only packet before the failed Write.
			wantKeys := baseKeys(t)
			for i, k := range wantKeys {
				if k.dir == dpv1.PspSaDirection_PSP_SA_DIRECTION_RX && k.spi == spiA1In {
					wantKeys[i].packets, wantKeys[i].seq = 1, 1
				}
			}
			assert.ElementsMatch(t, wantKeys, readKeys(t, r), "the keys entries")
			if tc.next != nil {
				require.NoError(t, write(t.Context(), r, tc.next...))
				assertEntries(t, append(baseTables(), tc.after...), readTable(t, r, 0, ""))
			}
			r.receive(addrA1, toA2(2))
			r.receive(addrA1, toA2(1))
			var seqs []uint32
			for _, s := range r.sent {
				h, err := psp.ParseTrunkHeader(s.b)
				require.NoError(t, err)
				assert.Equal(t, addrA2, s.to)
				assert.Equal(t, uint32(spiA2Out), h.SPI)
				seqs = append(seqs, h.Seq)
			}
			assert.Equal(t, tc.sent, seqs, "the sequence numbers to A2")
			assert.Equal(t, tc.drops, counts(t, r, dp.CounterDrops))
		})
	}
}

// TestMeterRead writes meter configs and reads them back with Read: each meter index by itself,
// and all configured indices. An index has the last config, or no config after a MODIFY with no
// config. A Write of one index does not change the other indices.
func TestMeterRead(t *testing.T) {
	cfg := func(rate, burst int64) *p4.MeterConfig {
		return &p4.MeterConfig{Cir: rate, Cburst: burst, Pir: rate, Pburst: burst}
	}
	type mk struct{ id, index uint32 }
	port, lane, punt, port51 := mk{dp.MeterPort, 50}, mk{dp.MeterLane, 50}, mk{dp.MeterPunt, 50}, mk{dp.MeterPort, 51}
	set := func(k mk, c *p4.MeterConfig) *p4.Update { return meterUpdate(k.id, k.index, c) }
	cases := []struct {
		name   string
		writes [][]*p4.Update         // Each Write must pass.
		want   map[mk]*p4.MeterConfig // A nil config: the index has no config.
	}{
		{name: "a port meter", writes: [][]*p4.Update{{set(port, cfg(1e6, 1<<16))}}, want: map[mk]*p4.MeterConfig{port: cfg(1e6, 1<<16)}},
		{name: "a lane meter", writes: [][]*p4.Update{{set(lane, cfg(2e6, 1<<17))}}, want: map[mk]*p4.MeterConfig{lane: cfg(2e6, 1<<17)}},
		{name: "a punt meter", writes: [][]*p4.Update{{set(punt, cfg(3e6, 1<<18))}}, want: map[mk]*p4.MeterConfig{punt: cfg(3e6, 1<<18)}},
		{name: "a new config", writes: [][]*p4.Update{
			{set(port, cfg(1e6, 1<<16))}, {set(port, cfg(5e6, 1<<20))},
		}, want: map[mk]*p4.MeterConfig{port: cfg(5e6, 1<<20)}},
		{name: "two configs of an index in one Write", writes: [][]*p4.Update{
			{set(port, cfg(1e6, 1<<16)), set(port, cfg(5e6, 1<<20))},
		}, want: map[mk]*p4.MeterConfig{port: cfg(5e6, 1<<20)}},
		{name: "no config after a config", writes: [][]*p4.Update{
			{set(port, cfg(1e6, 1<<16))}, {set(port, nil)},
		}, want: map[mk]*p4.MeterConfig{port: nil}},
		{name: "a MODIFY with no config of an index with no config", writes: [][]*p4.Update{{set(port, nil)}}, want: map[mk]*p4.MeterConfig{port: nil}},
		{name: "no Write", want: map[mk]*p4.MeterConfig{port: nil}},
		{name: "four indices, then a change of one and no config for one", writes: [][]*p4.Update{
			{set(port, cfg(1e6, 1<<16)), set(lane, cfg(2e6, 1<<17)), set(punt, cfg(3e6, 1<<18)), set(port51, cfg(4e6, 1<<19))},
			{set(port, cfg(5e6, 1<<20)), set(lane, nil)},
		}, want: map[mk]*p4.MeterConfig{port: cfg(5e6, 1<<20), lane: nil, punt: cfg(3e6, 1<<18), port51: cfg(4e6, 1<<19)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t)
			for _, w := range tc.writes {
				require.NoError(t, write(t.Context(), r, w...))
			}
			configured := map[mk]*p4.MeterConfig{}
			for k, want := range tc.want {
				got := readBack(t, r, set(k, nil).GetEntity())
				require.Len(t, got, 1)
				me := got[0].GetMeterEntry()
				assert.Equal(t, k, mk{me.GetMeterId(), uint32(me.GetIndex().GetIndex())})
				if want == nil {
					assert.Nil(t, me.GetConfig(), "%v has no config", k)
					continue
				}
				configured[k] = want
				assert.True(t, proto.Equal(want, me.GetConfig()), "%v: want %v, got %v", k, want, me.GetConfig())
			}
			// A Read of all meters gives only the configured indices.
			all := map[mk]*p4.MeterConfig{}
			for _, e := range readBack(t, r, &p4.Entity{Entity: &p4.Entity_MeterEntry{MeterEntry: &p4.MeterEntry{}}}) {
				me := e.GetMeterEntry()
				all[mk{me.GetMeterId(), uint32(me.GetIndex().GetIndex())}] = me.GetConfig()
			}
			assert.Len(t, all, len(configured))
			for k, want := range configured {
				assert.True(t, proto.Equal(want, all[k]), "%v in a Read of all meters", k)
			}
		})
	}
}

// TestCounterWrite writes counter values and reads them back with Read: each index by itself, and
// all indices that are not zero. An index has the last value of the Writes.
func TestCounterWrite(t *testing.T) {
	type ck struct {
		id    uint32
		index int64
	}
	cell7, cell9, drop4, portDrop := ck{dp.CounterCells, 7}, ck{dp.CounterCells, 9}, ck{dp.CounterDrops, 4}, ck{dp.CounterPortDrops, pd(1, 2)}
	set := func(k ck, packets, bytes int64) *p4.Update {
		return &p4.Update{Type: p4.Update_MODIFY, Entity: counterEntity(k.id, k.index, packets, bytes)}
	}
	cases := []struct {
		name   string
		writes [][]*p4.Update  // Each Write must pass.
		want   map[ck][2]int64 // Packets and bytes.
	}{
		{name: "a value for each counter", writes: [][]*p4.Update{{set(cell7, 3, 300), set(drop4, 5, 500), set(portDrop, 6, 600)}},
			want: map[ck][2]int64{cell7: {3, 300}, drop4: {5, 500}, portDrop: {6, 600}}},
		{name: "two values of an index in one Write", writes: [][]*p4.Update{{set(cell7, 3, 300), set(cell7, 4, 400)}},
			want: map[ck][2]int64{cell7: {4, 400}}},
		{name: "a new value in a second Write", writes: [][]*p4.Update{{set(cell7, 3, 300), set(cell9, 1, 10)}, {set(cell7, 8, 800)}},
			want: map[ck][2]int64{cell7: {8, 800}, cell9: {1, 10}}},
		{name: "a value of zero", writes: [][]*p4.Update{{set(cell7, 3, 300), set(cell9, 1, 10)}, {set(cell7, 0, 0)}},
			want: map[ck][2]int64{cell7: {0, 0}, cell9: {1, 10}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t)
			for _, w := range tc.writes {
				require.NoError(t, write(t.Context(), r, w...))
			}
			nonZero := map[ck][2]int64{}
			for k, want := range tc.want {
				got := readBack(t, r, counterEntity(k.id, k.index, 0, 0))
				require.Len(t, got, 1)
				assert.True(t, proto.Equal(counterEntity(k.id, k.index, want[0], want[1]), got[0]), "%v: got %v", k, got[0])
				if want != [2]int64{} {
					nonZero[k] = want
				}
			}
			// A Read of all counters gives only the indices that are not zero.
			all := map[ck][2]int64{}
			for _, e := range readBack(t, r, &p4.Entity{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{}}}) {
				c := e.GetCounterEntry()
				all[ck{c.GetCounterId(), c.GetIndex().GetIndex()}] = [2]int64{c.GetData().GetPacketCount(), c.GetData().GetByteCount()}
			}
			assert.Equal(t, nonZero, all)
		})
	}
}

// TestKeysRead writes RX and TX entries and reads all keys entries back with Read: each entry has
// its direction, SPI, port session and lane, and no key. A DELETE of a TX lane keeps the other
// lanes, and a port session can get TX entries again after the DELETE of its last lane.
func TestKeysRead(t *testing.T) {
	const (
		rxDir = dpv1.PspSaDirection_PSP_SA_DIRECTION_RX
		txDir = dpv1.PspSaDirection_PSP_SA_DIRECTION_TX
	)
	ke := func(dir dpv1.PspSaDirection, spi uint32, lane uint32) keyEntry {
		return keyEntry{dir: dir, spi: spi, port: 50, session: 1, lane: lane}
	}
	delTx := func(spi uint32) *p4.Update {
		return keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: txDir, Spi: spi, Port: 50, Session: 1})
	}
	delRx := func(spi uint32) *p4.Update {
		return keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: rxDir, Spi: spi})
	}
	threeLanes := []*p4.Update{tx(0x501, 50, 1, 0), tx(0x502, 50, 1, 1), tx(0x503, 50, 1, 3)}
	cases := []struct {
		name   string
		writes [][]*p4.Update // Each Write must pass.
		want   []keyEntry     // The entries of port 50, after those of base.
	}{
		{name: "an RX entry of a lane", writes: [][]*p4.Update{{rx(0x5a1, 50, 1, 2)}}, want: []keyEntry{ke(rxDir, 0x5a1, 2)}},
		{name: "an RX DELETE", writes: [][]*p4.Update{{rx(0x5a1, 50, 1, 0), rx(0x5a2, 50, 1, 1)}, {delRx(0x5a1)}}, want: []keyEntry{ke(rxDir, 0x5a2, 1)}},
		{name: "TX entries of three lanes", writes: [][]*p4.Update{threeLanes},
			want: []keyEntry{ke(txDir, 0x501, 0), ke(txDir, 0x502, 1), ke(txDir, 0x503, 3)}},
		{name: "a DELETE of a lane keeps the other lanes", writes: [][]*p4.Update{threeLanes, {delTx(0x502)}},
			want: []keyEntry{ke(txDir, 0x501, 0), ke(txDir, 0x503, 3)}},
		{name: "a DELETE of the last lane", writes: [][]*p4.Update{{tx(0x501, 50, 1, 2)}, {delTx(0x501)}}},
		{name: "a new entry after the DELETE of the last lane", writes: [][]*p4.Update{{tx(0x501, 50, 1, 0)}, {delTx(0x501)}, {tx(0x504, 50, 1, 1)}},
			want: []keyEntry{ke(txDir, 0x504, 1)}},
		{name: "a DELETE of the only lane and a new entry in one Write", writes: [][]*p4.Update{{tx(0x501, 50, 1, 0)}, {delTx(0x501), tx(0x506, 50, 1, 2)}},
			want: []keyEntry{ke(txDir, 0x506, 2)}},
		{name: "a DELETE and an INSERT of a lane in one Write", writes: [][]*p4.Update{{tx(0x501, 50, 1, 0), tx(0x502, 50, 1, 1)}, {delTx(0x501), tx(0x505, 50, 1, 0)}},
			want: []keyEntry{ke(txDir, 0x505, 0), ke(txDir, 0x502, 1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t)
			for _, w := range tc.writes {
				require.NoError(t, write(t.Context(), r, w...))
			}
			assert.ElementsMatch(t, append(baseKeys(t), tc.want...), readKeys(t, r))
		})
	}
}

// TestTxLaneSeq sends packets of 32 flows from A1 to A2, whose port session has TX entries in
// three lanes, before and after a DELETE of one lane and an INSERT in that lane. The other TX
// entries keep their sequence numbers: the packets of each SPI have the sequence numbers 0, 1, 2
// and so on, with no number two times.
func TestTxLaneSeq(t *testing.T) {
	const lane1, lane2, lane1New = 0x2a1, 0x2a2, 0x2a3
	r := newRelay(t, tx(lane1, 2, 1, 1), tx(lane2, 2, 1, 2))
	seqs := map[uint32][]uint32{} // The sequence numbers of each SPI, in the order of the packets.
	in := uint32(0)
	send := func() map[uint32]bool {
		spis := map[uint32]bool{}
		from := len(r.sent)
		for flow := range 32 {
			in++
			r.receive(addrA1, seal(spiA1In, vniA, in, ipv4("100.64.1."+strconv.Itoa(flow+1), "100.64.2.5", 100)))
		}
		require.Len(t, r.sent, from+32)
		for _, s := range r.sent[from:] {
			h, err := psp.ParseTrunkHeader(s.b)
			require.NoError(t, err)
			assert.Equal(t, addrA2, s.to)
			seqs[h.SPI] = append(seqs[h.SPI], h.Seq)
			spis[h.SPI] = true
		}
		return spis
	}
	del := keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, Spi: lane1, Port: 2, Session: 1})
	// keysWith returns the keys entries of base, the A1 RX entry after in packets, and the TX
	// entries of A2 in the lanes of spis.
	keysWith := func(spis map[uint32]uint32) []keyEntry {
		out := baseKeys(t)
		for i, k := range out {
			if k.dir == dpv1.PspSaDirection_PSP_SA_DIRECTION_RX && k.spi == spiA1In {
				out[i].packets, out[i].seq = uint64(in), in
			}
		}
		for spi, lane := range spis {
			out = append(out, keyEntry{dir: dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, spi: spi, port: 2, session: 1, lane: lane})
		}
		return out
	}
	assert.Equal(t, map[uint32]bool{spiA2Out: true, lane1: true, lane2: true}, send(), "the lanes before the DELETE")
	require.NoError(t, write(t.Context(), r, del))
	assert.ElementsMatch(t, keysWith(map[uint32]uint32{lane2: 2}), readKeys(t, r), "the keys after the DELETE")
	assert.Equal(t, map[uint32]bool{spiA2Out: true, lane2: true}, send(), "the lanes after the DELETE")
	require.NoError(t, write(t.Context(), r, tx(lane1New, 2, 1, 1)))
	assert.ElementsMatch(t, keysWith(map[uint32]uint32{lane2: 2, lane1New: 1}), readKeys(t, r), "the keys after the INSERT")
	assert.Equal(t, map[uint32]bool{spiA2Out: true, lane2: true, lane1New: true}, send(), "the lanes after the INSERT")
	for spi, got := range seqs {
		want := make([]uint32, len(got))
		for i := range want {
			want[i] = uint32(i)
		}
		assert.Equal(t, want, got, "the sequence numbers of SPI %#x", spi)
	}
}

// TestMeterWriteKeepsState checks the port meter of A1 after a meter Write. Packet 1 of A1 uses the
// allowance of the meter, then a Write changes a meter, then packets 2 to 4 of A1 go or drop at the
// meter. A Write of another index keeps the used allowance. A MODIFY of the index gives it a full
// bucket of the new config, or no limit when it has no config.
func TestMeterWriteKeepsState(t *testing.T) {
	onePacket := &p4.MeterConfig{Cir: 1, Cburst: 200, Pir: 1, Pburst: 200}  // 140 bytes go, the next 140 do not.
	twoPackets := &p4.MeterConfig{Cir: 1, Cburst: 300, Pir: 1, Pburst: 300} // Two packets of 140 bytes go.
	other := &p4.MeterConfig{Cir: 1e9, Cburst: 1 << 20, Pir: 1e9, Pburst: 1 << 20}
	cases := []struct {
		name  string
		write *p4.Update
		want  map[uint32]*p4.MeterConfig // The config of port meter indices 1 and 2, or nil.
		goes  []bool                     // Packets 2 to 4: go, or drop at the meter.
	}{
		{
			name:  "a Write of another index",
			write: meterUpdate(dp.MeterPort, 2, other),
			want:  map[uint32]*p4.MeterConfig{1: onePacket, 2: other},
			goes:  []bool{false, false, false},
		},
		{
			name:  "a MODIFY with the same config",
			write: meterUpdate(dp.MeterPort, 1, onePacket),
			want:  map[uint32]*p4.MeterConfig{1: onePacket, 2: nil},
			goes:  []bool{true, false, false},
		},
		{
			name:  "a MODIFY with a larger burst",
			write: meterUpdate(dp.MeterPort, 1, twoPackets),
			want:  map[uint32]*p4.MeterConfig{1: twoPackets, 2: nil},
			goes:  []bool{true, true, false},
		},
		{
			name:  "a MODIFY with no config",
			write: meterUpdate(dp.MeterPort, 1, nil),
			want:  map[uint32]*p4.MeterConfig{1: nil, 2: nil},
			goes:  []bool{true, true, true},
		},
	}
	pkt := func(seq uint32) []byte { return seal(spiA1In, vniA, seq, ipv4("100.64.1.5", "100.64.2.5", 100)) }
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t, meterUpdate(dp.MeterPort, 1, onePacket))
			r.receive(addrA1, pkt(1))
			require.Len(t, r.sent, 1, "packet 1 goes")
			require.NoError(t, write(t.Context(), r, tc.write))
			for index, want := range tc.want {
				got := readBack(t, r, meterUpdate(dp.MeterPort, index, nil).GetEntity())
				wantEntity := meterUpdate(dp.MeterPort, index, want).GetEntity()
				if assert.Len(t, got, 1) {
					assert.True(t, proto.Equal(wantEntity, got[0]), "port meter %d: want %v, got %v", index, wantEntity, got[0])
				}
			}
			var goes []bool
			drops := map[int64]int64{}
			for i := range tc.goes {
				from := len(r.sent)
				r.receive(addrA1, pkt(uint32(i+2)))
				goes = append(goes, len(r.sent) > from)
				if !goes[i] {
					drops[int64(dp.ReasonMeter)]++
				}
			}
			assert.Equal(t, tc.goes, goes, "packets 2 to 4")
			assert.Equal(t, drops, counts(t, r, dp.CounterDrops))
		})
	}
}

// churn inserts the ports entry of port 100 and deletes it again, one Write at a time, until stop
// or the end of the test. After each Write it reads port 100 back: the full entry after an INSERT,
// and no entry after a DELETE. ran reports whether n Writes passed this check, or one failed. stop
// ends the churn and returns the first error, or an error when fewer than n Writes ran.
func churn(t *testing.T, tg dp.Target, n int) (ran func() bool, stop func() error) {
	quit, reached, errc := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		e := access(100, netip.MustParseAddrPort("192.0.2.100:4000"), 100, 0)
		port100 := &p4.ReadRequest{Entities: []*p4.Entity{insert(dp.PortsKey{Port: 100}.Entry(nil)).GetEntity()}}
		fail := func(i int, err error) {
			if i < n {
				close(reached) // The caller stops its wait.
			}
			errc <- err
		}
		for i := 0; ; i++ {
			if i == n {
				close(reached)
			}
			select {
			case <-quit:
				errc <- nil
				return
			default:
			}
			u, want := insert(e), []*p4.TableEntry{e}
			if i%2 == 1 {
				u, want = remove(e), nil
			}
			if err := write(context.Background(), tg, u); err != nil {
				fail(i, err)
				return
			}
			var got []*p4.TableEntry
			if err := tg.Read(context.Background(), port100, func(x *p4.Entity) { got = append(got, x.GetTableEntry()) }); err != nil {
				fail(i, err)
				return
			}
			if !slices.EqualFunc(want, got, func(a, b *p4.TableEntry) bool { return proto.Equal(a, b) }) {
				fail(i, fmt.Errorf("port 100 after Write %d: want %v, got %v", i, want, got))
				return
			}
		}
	}()
	ran = func() bool {
		select {
		case <-reached:
			return true
		default:
			return false
		}
	}
	stop = sync.OnceValue(func() error {
		close(quit)
		if err := <-errc; err != nil {
			return err
		}
		if !ran() {
			return fmt.Errorf("the churn stopped after fewer than %d Writes", n)
		}
		return nil
	})
	t.Cleanup(func() { _ = stop() })
	return ran, stop
}

// cellData returns the packets and bytes of a cells index.
func cellData(t *testing.T, tg dp.Target, i int64) [2]int64 {
	t.Helper()
	var got [2]int64
	req := &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{CounterId: dp.CounterCells, Index: &p4.Index{Index: i}}}}}}
	require.NoError(t, tg.Read(t.Context(), req, func(e *p4.Entity) {
		got = [2]int64{e.GetCounterEntry().GetData().GetPacketCount(), e.GetCounterEntry().GetData().GetByteCount()}
	}))
	return got
}

// TestFinalCountWrites checks the final count while packets and other Writes run. Each packet of A1
// counts one time: in its cell, or as old_session after the Write that deletes its entries. After
// that Write returns, the cell does not change. The packets go until 20 Writes of churn passed.
func TestFinalCountWrites(t *testing.T) {
	r := newRelay(t)
	const after = 500 // The packets of A1 after the Write that deletes its entries.
	var n atomic.Int64
	var deleted, churned atomic.Bool
	done := make(chan struct{})
	ctx := t.Context() // Done at the end of the test, also after a failure.
	go func() {
		defer close(done)
		left := after
		for seq := uint32(1); (left > 0 || !churned.Load()) && ctx.Err() == nil; seq++ {
			if deleted.Load() && left > 0 {
				left--
			}
			r.receive(addrA1, seal(spiA1In, vniA, seq, ipv4("100.64.1.5", "100.64.2.5", 100)))
			n.Add(1)
		}
	}()
	t.Cleanup(func() { <-done })
	require.Eventually(t, func() bool { return n.Load() >= 500 }, 10*time.Second, time.Millisecond)
	ran, stop := churn(t, r, 20)
	require.NoError(t, write(t.Context(), r, remove(dp.PortsKey{Port: 1}.Entry(nil)), remove(dp.ClassifyKey{Port: 1, Session: 1}.Entry(nil))))
	for _, gone := range []*p4.TableEntry{dp.PortsKey{Port: 1}.Entry(nil), dp.ClassifyKey{Port: 1, Session: 1}.Entry(nil)} {
		assert.Empty(t, readBack(t, r, insert(gone).GetEntity()), "%v after its DELETE", gone)
	}
	final := cellData(t, r, 2)
	deleted.Store(true)
	require.Eventually(t, ran, 10*time.Second, time.Millisecond)
	churned.Store(true)
	<-done
	require.NoError(t, stop())

	assert.Equal(t, final, cellData(t, r, 2), "the cell after the Write")
	assert.GreaterOrEqual(t, final[0], int64(500))
	assert.Equal(t, 100*final[0], final[1], "the bytes of the cell")
	drops := counts(t, r, dp.CounterDrops)
	assert.Equal(t, n.Load(), final[0]+drops[int64(dp.ReasonOldSession)], "each packet counts one time")
	assert.Len(t, drops, 1, "only old_session")
	assert.Equal(t, final[0], counts(t, r, dp.CounterCells)[2*32+1], "the out cell of A2")
	assert.Len(t, r.sent, int(final[0]))
}

// TestFrameWriterWrites changes the frame writer of port 3 while other Writes run. Each FRAME out
// goes to the frame writer that was set last: no change is lost. The packets go until 20 Writes of
// churn passed.
func TestFrameWriterWrites(t *testing.T) {
	r := newRelay(t)
	ran, stop := churn(t, r, 20)
	var got [2]int
	writer := func(i int) func([]byte) error {
		return func([]byte) error {
			got[i]++
			return nil
		}
	}
	steps := []int{0, 1, -1, 1, 0, -1} // The frame writer of each packet: 0, 1, or none.
	noTarget := int64(0)
	for i := 0; i < 50*len(steps) || !ran(); i++ {
		w := steps[i%len(steps)]
		want := got
		if w < 0 {
			r.SetFrameWriter(3, nil)
			noTarget++
		} else {
			r.SetFrameWriter(3, writer(w))
			want[w]++
		}
		r.receive(addrA1, seal(spiA1In, vniA, uint32(i+1), ipv4("100.64.1.5", "100.64.3.5", 100)))
		require.Equal(t, want, got, "packet %d", i)
		require.Equal(t, noTarget, counts(t, r, dp.CounterDrops)[int64(dp.ReasonNoTarget)], "packet %d", i)
	}
	require.NoError(t, stop())
}

// TestModifyContext changes the context of A1 to cell 9 and sends a packet of A1 to A2: it goes in
// the VPC of the new context and counts in its cell. VPC B has no route to A2, so the packet goes to
// the root.
func TestModifyContext(t *testing.T) {
	cases := []struct {
		name     string
		vpc      string
		sent, in int
	}{
		{name: "the same VPC", vpc: vpcA, sent: 1},
		{name: "another VPC", vpc: vpcB, in: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t)
			require.NoError(t, write(t.Context(), r, modify(context_(1, 1, 0, tc.vpc, vniA, 9))))
			want := context_(1, 1, 0, tc.vpc, vniA, 9)
			got := readBack(t, r, insert(dp.ClassifyKey{Port: 1, Session: 1}.Entry(nil)).GetEntity())
			if assert.Len(t, got, 1) {
				assert.True(t, proto.Equal(want, got[0].GetTableEntry()), "the context after the MODIFY: %v", got[0])
			}
			r.receive(addrA1, seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)))
			assert.Len(t, r.sent, tc.sent)
			assert.Len(t, r.in, tc.in)
			assert.Empty(t, counts(t, r, dp.CounterDrops))
			assert.Equal(t, int64(1), counts(t, r, dp.CounterCells)[2*9], "the receive cell of the new context")
		})
	}
}

// readRx returns the packets and seq of each RX entry, and checks that no key comes back.
func readRx(t *testing.T, tg dp.Target) map[uint32][2]uint64 {
	t.Helper()
	got := map[uint32][2]uint64{}
	req := &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_ExternEntry{ExternEntry: &p4.ExternEntry{ExternTypeId: dp.ExternPspSa, ExternId: dp.ExternKeys}}}}}
	require.NoError(t, tg.Read(t.Context(), req, func(e *p4.Entity) {
		x := &dpv1.PspSaEntry{}
		require.NoError(t, e.GetExternEntry().GetEntry().UnmarshalTo(x))
		assert.Empty(t, x.GetKey())
		if x.GetDirection() == dpv1.PspSaDirection_PSP_SA_DIRECTION_RX && x.GetPort() == 1 {
			got[x.GetSpi()] = [2]uint64{x.GetPackets(), uint64(x.GetSeq())}
		}
	}))
	return got
}

// TestRxRekey keeps the old RX entry while the new SPI comes in, then deletes it.
func TestRxRekey(t *testing.T) {
	const spiNew = 0x102
	r := newRelay(t, rx(spiNew, 1, 1, 0))
	pkt := func(spi, seq uint32) []byte { return seal(spi, vniA, seq, ipv4("100.64.1.5", "100.64.2.5", 100)) }

	steps := []struct {
		name  string
		del   bool // Delete the old RX entry first.
		spi   uint32
		seq   uint32
		sent  int
		drops map[int64]int64
		rx    map[uint32][2]uint64
	}{
		{name: "old SPI", spi: spiA1In, seq: 5, sent: 1, drops: map[int64]int64{}, rx: map[uint32][2]uint64{spiA1In: {1, 5}, spiNew: {0, 0}}},
		{name: "new SPI", spi: spiNew, seq: 1, sent: 2, drops: map[int64]int64{}, rx: map[uint32][2]uint64{spiA1In: {1, 5}, spiNew: {1, 1}}},
		{name: "replay of the old SPI", spi: spiA1In, seq: 5, sent: 2, drops: map[int64]int64{int64(dp.ReasonOpen): 1}, rx: map[uint32][2]uint64{spiA1In: {1, 5}, spiNew: {1, 1}}},
		{name: "old SPI after its delete", del: true, spi: spiA1In, seq: 6, sent: 2, drops: map[int64]int64{int64(dp.ReasonOpen): 1, int64(dp.ReasonUnknownSPI): 1}, rx: map[uint32][2]uint64{spiNew: {1, 1}}},
		{name: "new SPI after the delete", spi: spiNew, seq: 2, sent: 3, drops: map[int64]int64{int64(dp.ReasonOpen): 1, int64(dp.ReasonUnknownSPI): 1}, rx: map[uint32][2]uint64{spiNew: {2, 2}}},
	}
	for _, s := range steps {
		if s.del {
			require.NoError(t, write(t.Context(), r, keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: spiA1In})))
		}
		r.receive(addrA1, pkt(s.spi, s.seq))
		assert.Len(t, r.sent, s.sent, s.name)
		assert.Equal(t, s.drops, counts(t, r, dp.CounterDrops), s.name)
		assert.Equal(t, s.rx, readRx(t, r), s.name)
	}
}

// TestRxWindowWrite checks that a Write of other RX entries keeps the replay window of A1. Packets
// 1, 2 and 4 of A1 go before the Write. After it, the replays of 2 and 4 drop, and 3 and 5 go.
func TestRxWindowWrite(t *testing.T) {
	const rxDir = dpv1.PspSaDirection_PSP_SA_DIRECTION_RX
	const spiNew = 0x1a1 // A new RX entry in lane 1 of A1.
	newRx := keyEntry{dir: rxDir, spi: spiNew, port: 1, session: 1, lane: 1}
	delA2 := keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: rxDir, Spi: spiA2In})
	cases := []struct {
		name  string
		write []*p4.Update
		add   []keyEntry // The keys entries after the Write, other than those of base.
		gone  uint32     // The RX entry of base that the Write deletes, or 0.
	}{
		{name: "an RX INSERT in the port session of A1", write: []*p4.Update{rx(spiNew, 1, 1, 1)}, add: []keyEntry{newRx}},
		{name: "an RX DELETE of A2", write: []*p4.Update{delA2}, gone: spiA2In},
		{name: "an RX INSERT and DELETE in one Write", write: []*p4.Update{rx(spiNew, 1, 1, 1), delA2}, add: []keyEntry{newRx}, gone: spiA2In},
	}
	pkt := func(seq uint32) []byte { return seal(spiA1In, vniA, seq, ipv4("100.64.1.5", "100.64.2.5", 100)) }
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// want returns the keys entries after the Write, with the packets and the highest
			// sequence number of the A1 RX entry.
			want := func(packets uint64, seq uint32) []keyEntry {
				var out []keyEntry
				for _, k := range baseKeys(t) {
					switch {
					case k.dir == rxDir && k.spi == tc.gone:
						continue
					case k.dir == rxDir && k.spi == spiA1In:
						k.packets, k.seq = packets, seq
					}
					out = append(out, k)
				}
				return append(out, tc.add...)
			}
			r := newRelay(t)
			for _, seq := range []uint32{1, 2, 4} {
				r.receive(addrA1, pkt(seq))
			}
			require.Len(t, r.sent, 3)
			require.NoError(t, write(t.Context(), r, tc.write...))
			assert.ElementsMatch(t, want(3, 4), readKeys(t, r), "the keys after the Write")
			var goes []bool
			for _, seq := range []uint32{2, 3, 4, 5} {
				from := len(r.sent)
				r.receive(addrA1, pkt(seq))
				goes = append(goes, len(r.sent) > from)
			}
			assert.Equal(t, []bool{false, true, false, true}, goes, "packets 2, 3, 4 and 5 after the Write")
			assert.Equal(t, map[int64]int64{int64(dp.ReasonOpen): 2}, counts(t, r, dp.CounterDrops))
			assert.ElementsMatch(t, want(5, 5), readKeys(t, r), "the keys after the packets")
		})
	}
}

// TestRxCount checks that open moves seq and that check_in counts a packet only after the meters.
func TestRxCount(t *testing.T) {
	red := &p4.MeterConfig{Cir: 1, Cburst: 64, Pir: 1, Pburst: 64}
	cases := []struct {
		name  string
		extra []*p4.Update
		from  netip.AddrPort
		dst   string
		drop  uint8
		rx    [2]uint64 // packets, seq
	}{
		{name: "pass", from: addrA1, dst: "100.64.2.5", rx: [2]uint64{1, 3}},
		{name: "a drop after check_in counts", from: addrA1, dst: "100.64.4.5", drop: dp.ReasonNoTarget, rx: [2]uint64{1, 3}},
		{name: "unknown_source", from: netip.MustParseAddrPort("192.0.2.99:4000"), dst: "100.64.2.5", drop: dp.ReasonUnknownSource, rx: [2]uint64{0, 3}},
		{name: "lane meter", extra: []*p4.Update{meterUpdate(dp.MeterLane, 4, red)}, from: addrA1, dst: "100.64.2.5", drop: dp.ReasonMeter, rx: [2]uint64{0, 3}},
		{name: "port meter", extra: []*p4.Update{meterUpdate(dp.MeterPort, 1, red)}, from: addrA1, dst: "100.64.2.5", drop: dp.ReasonMeter, rx: [2]uint64{0, 3}},
		{name: "old_session", extra: []*p4.Update{remove(dp.PortsKey{Port: 1}.Entry(nil))}, from: addrA1, dst: "100.64.2.5", drop: dp.ReasonOldSession, rx: [2]uint64{0, 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t, tc.extra...)
			r.receive(tc.from, seal(spiA1In, vniA, 3, ipv4("100.64.1.5", tc.dst, 100)))
			want := map[int64]int64{}
			if tc.drop != 0 {
				want[int64(tc.drop)] = 1
			}
			assert.Equal(t, want, counts(t, r, dp.CounterDrops))
			assert.Equal(t, tc.rx, readRx(t, r)[spiA1In])
		})
	}
}

// TestSchema reads each object of the built-in schema.
func TestSchema(t *testing.T) {
	info, err := dp.P4Info()
	require.NoError(t, err)
	var reads []*p4.Entity
	for _, x := range info.GetTables() {
		reads = append(reads, &p4.Entity{Entity: &p4.Entity_TableEntry{TableEntry: &p4.TableEntry{TableId: x.GetPreamble().GetId()}}})
	}
	for _, x := range info.GetCounters() {
		reads = append(reads, &p4.Entity{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{CounterId: x.GetPreamble().GetId()}}})
	}
	for _, x := range info.GetMeters() {
		reads = append(reads, &p4.Entity{Entity: &p4.Entity_MeterEntry{MeterEntry: &p4.MeterEntry{MeterId: x.GetPreamble().GetId()}}})
	}
	for _, x := range info.GetExterns() {
		for _, i := range x.GetInstances() {
			reads = append(reads, &p4.Entity{Entity: &p4.Entity_ExternEntry{ExternEntry: &p4.ExternEntry{ExternTypeId: x.GetExternTypeId(), ExternId: i.GetPreamble().GetId()}}})
		}
	}
	require.Len(t, reads, 4+3+3+1)
	r := newRelay(t)
	for _, e := range reads {
		assert.NoError(t, r.Read(t.Context(), &p4.ReadRequest{Entities: []*p4.Entity{e}}, func(*p4.Entity) {}), "%v", e)
	}
}

// TestParallelWriters runs writers in parallel with packets. Each writer ends with its own entry.
func TestParallelWriters(t *testing.T) {
	r := newRelay(t)
	const writers, rounds, packets = 8, 50, 200
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := range writers {
		wg.Go(func() {
			port := uint64(100 + w)
			e := withMetadata(access(port, netip.AddrPortFrom(netip.MustParseAddr("192.0.2.100"), uint16(port)), uint32(port), 0), "p/"+strconv.Itoa(int(port)))
			for range rounds {
				if err := write(t.Context(), r, insert(e)); err != nil {
					errs <- err
					return
				}
				if err := write(t.Context(), r, remove(e)); err != nil {
					errs <- err
					return
				}
			}
			errs <- write(t.Context(), r, insert(e))
		})
	}
	for seq := uint32(1); seq <= packets; seq++ {
		r.receive(addrA1, seal(spiA1In, vniA, seq, ipv4("100.64.1.5", "100.64.2.5", 100)))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Len(t, r.sent, packets)
	for w := range writers {
		assert.Len(t, readTable(t, r, dp.TablePorts, "p/"+strconv.Itoa(100+w)), 1)
	}
}
