// SPDX-License-Identifier: AGPL-3.0-only

package dp_test

import (
	"context"
	"net/netip"
	"strconv"
	"sync"
	"testing"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

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
