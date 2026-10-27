// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"slices"
	"testing"
	"time"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// TestPlacement checks the least-load placement of new port sessions. The load of a worker is the
// sum of the receive rates of its port sessions, from two samples of the same receive cells; a port
// session with no rate yet counts the rate of its port meter, else 5 Gbps (625e6 bytes per second).
// Equal loads go to the lowest worker, a rekey keeps the worker, and a failed Write changes nothing.
// After each Write that passes, a Read gives back each of its updates.
func TestPlacement(t *testing.T) {
	// Port session k is port k, session 1, with cell k and meter index k.
	conn := func(k uint64, spi uint32) []*p4.Update {
		return []*p4.Update{
			tableUpdate(PortsKey{Port: k}.Entry(PortAction{Session: 1, MeterIndex: uint32(k)})),
			tableUpdate(ClassifyKey{Port: k, Session: 1}.Entry(ContextAction{VPC: "uid-a/1", VNI: 100, Cell: uint32(k)})),
			rxKeys(spi, k),
		}
	}
	table := func(typ p4.Update_Type, e *p4.TableEntry) *p4.Update {
		return &p4.Update{Type: typ, Entity: &p4.Entity{Entity: &p4.Entity_TableEntry{TableEntry: e}}}
	}
	// tags writes the three tags of the trunk at port k, with one cell.
	tags := func(typ p4.Update_Type, k uint64) []*p4.Update {
		var us []*p4.Update
		for tag := uint32(1); tag <= 3; tag++ {
			us = append(us, table(typ, ClassifyKey{Port: k, Session: 1, Tag: tag}.Entry(ContextAction{VPC: "uid-a/1", VNI: 100, Cell: uint32(k)})))
		}
		return us
	}
	trunk := func(k uint64, spi uint32) []*p4.Update {
		us := []*p4.Update{tableUpdate(PortsKey{Port: k}.Entry(PortAction{Trunk: true, Session: 1, MeterIndex: uint32(k)}))}
		return append(append(us, tags(p4.Update_INSERT, k)...), rxKeys(spi, k))
	}
	// cells sets the receive bytes of cell k to bytes, for each pair k, bytes.
	cells := func(kv ...int64) []*p4.Update {
		var us []*p4.Update
		for i := 0; i < len(kv); i += 2 {
			us = append(us, &p4.Update{Type: p4.Update_MODIFY, Entity: &p4.Entity{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{
				CounterId: CounterCells, Index: &p4.Index{Index: 2 * kv[i]}, Data: &p4.CounterData{ByteCount: kv[i+1]},
			}}}})
		}
		return us
	}
	meter := func(k uint32, rate int64) *p4.Update {
		return &p4.Update{Type: p4.Update_MODIFY, Entity: &p4.Entity{Entity: &p4.Entity_MeterEntry{MeterEntry: &p4.MeterEntry{
			MeterId: MeterPort, Index: &p4.Index{Index: int64(k)}, Config: &p4.MeterConfig{Cir: rate, Cburst: 1 << 20, Pir: rate, Pburst: 1 << 20},
		}}}}
	}
	bad := keysUpdate(p4.Update_DELETE, dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, 0x999, 9)
	del := func(spi uint32) *p4.Update {
		return keysUpdate(p4.Update_DELETE, dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, spi, 0)
	}
	join := func(uss ...[]*p4.Update) []*p4.Update {
		var out []*p4.Update
		for _, us := range uss {
			out = append(out, us...)
		}
		return out
	}

	// A step is a Write. With no updates, the step samples the load at start.Add(at).
	type step struct {
		write []*p4.Update
		fail  bool
		at    time.Duration
		want  steerMap // The map after the step; nil: no check.
	}
	sample := func(at time.Duration) step { return step{at: at} }
	cases := []struct {
		name    string
		workers int
		steps   []step
	}{
		{name: "the least load from the receive rates", workers: 2, steps: []step{
			{write: join(conn(1, 0x101), conn(2, 0x201)), want: steerMap{0x101: 0, 0x201: 1}},
			sample(0),
			{write: cells(1, 1e9, 2, 1e8)},
			sample(time.Second),
			// The loads are 1e9 and 1e8, then 1e9 and 1e8 + 625e6.
			{write: conn(3, 0x301), want: steerMap{0x101: 0, 0x201: 1, 0x301: 1}},
			{write: conn(4, 0x401), want: steerMap{0x101: 0, 0x201: 1, 0x301: 1, 0x401: 1}},
			{write: conn(5, 0x501), want: steerMap{0x101: 0, 0x201: 1, 0x301: 1, 0x401: 1, 0x501: 0}},
		}},
		{name: "a rate is the bytes between two samples over their time", workers: 2, steps: []step{
			{write: join(conn(1, 0x101), cells(1, 4e9)), want: steerMap{0x101: 0}},
			sample(0),
			{write: cells(1, 5e9)},
			sample(2 * time.Second),
			// Port session 1 has rate 5e8, and port session 2 counts 625e6.
			{write: conn(2, 0x201), want: steerMap{0x101: 0, 0x201: 1}},
			{write: conn(3, 0x301), want: steerMap{0x101: 0, 0x201: 1, 0x301: 0}},
		}},
		{name: "with no rate, the rate of the port meter", workers: 2, steps: []step{
			{write: join([]*p4.Update{meter(1, 1e6), meter(3, 1e6)}, conn(1, 0x101), conn(2, 0x201)), want: steerMap{0x101: 0, 0x201: 1}},
			{write: conn(3, 0x301), want: steerMap{0x101: 0, 0x201: 1, 0x301: 0}},
			{write: conn(4, 0x401), want: steerMap{0x101: 0, 0x201: 1, 0x301: 0, 0x401: 0}},
		}},
		{name: "a port meter of rate 0 counts 0", workers: 2, steps: []step{
			{write: join([]*p4.Update{meter(1, 0)}, conn(1, 0x101)), want: steerMap{0x101: 0}},
			{write: conn(2, 0x201), want: steerMap{0x101: 0, 0x201: 0}},
		}},
		{name: "no rate before the second sample", workers: 2, steps: []step{
			{write: join(conn(1, 0x101), conn(2, 0x201), cells(1, 1e9)), want: steerMap{0x101: 0, 0x201: 1}},
			sample(0),
			{write: conn(3, 0x301), want: steerMap{0x101: 0, 0x201: 1, 0x301: 0}},
			// The cells do not change: the rates are 0, and port session 3 still counts 625e6.
			sample(time.Second),
			{write: conn(4, 0x401), want: steerMap{0x101: 0, 0x201: 1, 0x301: 0, 0x401: 1}},
		}},
		{name: "equal loads go to the lowest worker", workers: 3, steps: []step{
			{write: join(conn(1, 0x101), conn(2, 0x201), conn(3, 0x301)), want: steerMap{0x101: 0, 0x201: 1, 0x301: 2}},
			sample(0),
			{write: cells(1, 5e8, 2, 5e8, 3, 5e8)},
			sample(time.Second),
			{write: conn(4, 0x401), want: steerMap{0x101: 0, 0x201: 1, 0x301: 2, 0x401: 0}},
			{write: conn(5, 0x501), want: steerMap{0x101: 0, 0x201: 1, 0x301: 2, 0x401: 0, 0x501: 1}},
		}},
		{name: "the cell of a trunk counts one time", workers: 2, steps: []step{
			{write: join(trunk(1, 0x101), conn(2, 0x201)), want: steerMap{0x101: 0, 0x201: 1}},
			sample(0),
			{write: cells(1, 3e8, 2, 5e8)},
			sample(time.Second),
			{write: conn(3, 0x301), want: steerMap{0x101: 0, 0x201: 1, 0x301: 0}},
		}},
		{name: "a new cell gives no rate for that sample", workers: 2, steps: []step{
			{write: join(conn(1, 0x101), conn(2, 0x201), cells(9, 1e11)), want: steerMap{0x101: 0, 0x201: 1}},
			sample(0),
			{write: append(cells(2, 1e9), table(p4.Update_MODIFY, ClassifyKey{Port: 1, Session: 1}.Entry(ContextAction{VPC: "uid-a/1", VNI: 100, Cell: 9})))},
			sample(time.Second),
			// Port session 1 counts 625e6, not the old bytes of cell 9. Port session 2 has rate 1e9.
			{write: conn(3, 0x301), want: steerMap{0x101: 0, 0x201: 1, 0x301: 0}},
		}},
		{name: "a trunk that gets its tags back has no rate for that sample", workers: 2, steps: []step{
			{write: join(trunk(1, 0x101), conn(2, 0x201), cells(1, 1e11)), want: steerMap{0x101: 0, 0x201: 1}},
			sample(0),
			{write: tags(p4.Update_DELETE, 1)},
			sample(time.Second),
			{write: append(tags(p4.Update_INSERT, 1), cells(2, 1e9)...)},
			sample(2 * time.Second),
			// Port session 1 counts 625e6, not the bytes of its cell. Port session 2 has rate 1e9.
			{write: conn(3, 0x301), want: steerMap{0x101: 0, 0x201: 1, 0x301: 0}},
		}},
		{name: "a cell that goes down gives no rate", workers: 2, steps: []step{
			{write: join(conn(1, 0x101), conn(2, 0x201), cells(1, 2e9)), want: steerMap{0x101: 0, 0x201: 1}},
			sample(0),
			{write: cells(1, 0, 2, 1e9)},
			sample(time.Second),
			// Port session 1 counts 625e6, not a rate from the counter that went down.
			{write: conn(3, 0x301), want: steerMap{0x101: 0, 0x201: 1, 0x301: 0}},
		}},
		{name: "a cell that goes down gives no rate when another cell grows", workers: 2, steps: []step{
			// The trunk at port 1 has tag 1 with cell 1 and tag 2 with cell 11.
			{write: join([]*p4.Update{
				tableUpdate(PortsKey{Port: 1}.Entry(PortAction{Trunk: true, Session: 1, MeterIndex: 1})),
				tableUpdate(ClassifyKey{Port: 1, Session: 1, Tag: 1}.Entry(ContextAction{VPC: "uid-a/1", VNI: 100, Cell: 1})),
				tableUpdate(ClassifyKey{Port: 1, Session: 1, Tag: 2}.Entry(ContextAction{VPC: "uid-a/1", VNI: 100, Cell: 11})),
				rxKeys(0x101, 1),
			}, conn(2, 0x201), cells(1, 1e9)), want: steerMap{0x101: 0, 0x201: 1}},
			sample(0),
			{write: cells(1, 0, 11, 1.5e9, 2, 5.5e8)},
			sample(time.Second),
			// Port session 1 counts 625e6, not 5e8 from the sum of its cells. Port session 2 has rate 5.5e8.
			{write: conn(3, 0x301), want: steerMap{0x101: 0, 0x201: 1, 0x301: 1}},
		}},
		{name: "a rekey keeps the worker", workers: 2, steps: []step{
			{write: join(conn(1, 0x101), conn(2, 0x201)), want: steerMap{0x101: 0, 0x201: 1}},
			sample(0),
			{write: cells(1, 1e8, 2, 1e9)},
			sample(time.Second),
			{write: []*p4.Update{rxKeys(0x202, 2)}, want: steerMap{0x101: 0, 0x201: 1, 0x202: 1}},
			{write: []*p4.Update{del(0x201)}, want: steerMap{0x101: 0, 0x202: 1}},
			{write: []*p4.Update{del(0x202), rxKeys(0x203, 2)}, want: steerMap{0x101: 0, 0x203: 1}},
		}},
		{name: "a failed Write changes nothing", workers: 2, steps: []step{
			{write: conn(1, 0x101), want: steerMap{0x101: 0}},
			{write: append(conn(2, 0x201), bad), fail: true, want: steerMap{0x101: 0}},
			{write: conn(3, 0x301), want: steerMap{0x101: 0, 0x301: 1}},
			sample(0),
			{write: append(cells(1, 1e9), bad), fail: true, want: steerMap{0x101: 0, 0x301: 1}},
			sample(time.Second),
			// Port sessions 1 and 3 have rate 0: the failed Write did not set the cell.
			{write: conn(4, 0x401), want: steerMap{0x101: 0, 0x301: 1, 0x401: 0}},
		}},
		{name: "a failed Write makes no choice", workers: 2, steps: []step{
			{write: conn(1, 0x101), want: steerMap{0x101: 0}},
			{write: append(conn(2, 0x201), bad), fail: true, want: steerMap{0x101: 0}},
			sample(0),
			{write: cells(1, 1e8)},
			sample(time.Second),
			// Port session 1 has rate 1e8. Port session 2 is new: it gets worker 1 and counts 625e6.
			{write: join(conn(2, 0x201), conn(3, 0x301)), want: steerMap{0x101: 0, 0x201: 1, 0x301: 0}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New(nil, goAEAD{})
			p.setWorkers(tc.workers)
			start := time.Unix(1e9, 0)
			var applied []*p4.Update // The updates of the Writes that passed.
			for i, s := range tc.steps {
				var err error
				if s.write == nil {
					p.SampleLoad(start.Add(s.at))
				} else {
					err = writeAll(t, p, s.write...)
					require.Equal(t, s.fail, err != nil, "step %d: %v", i, err)
					if err == nil {
						applied = append(applied, s.write...)
						for _, u := range s.write {
							readWritten(t, p, i, u)
						}
					}
				}
				if s.fail {
					// Each update before bad is aborted, and bad is not found.
					st := status.Convert(err)
					assert.Equal(t, codes.Unknown, st.Code(), "step %d", i)
					var got []codes.Code
					for _, d := range st.Details() {
						got = append(got, codes.Code(d.(*p4.Error).GetCanonicalCode()))
					}
					want := append(slices.Repeat([]codes.Code{codes.Aborted}, len(s.write)-1), codes.NotFound)
					assert.Equal(t, want, got, "step %d: the code of each update", i)
					// The tables and the keys are those of the Writes that passed: in these cases they
					// only insert. No step before a failed Write sets a counter.
					var tables, keys []string
					for _, u := range applied {
						if e := u.GetEntity().GetTableEntry(); e != nil {
							tables = append(tables, marshal(t, e))
						}
						if x := u.GetEntity().GetExternEntry(); x != nil {
							e := &dpv1.PspSaEntry{}
							require.NoError(t, x.GetEntry().UnmarshalTo(e))
							e.Key = nil // A Read gives no key.
							keys = append(keys, marshal(t, e))
						}
					}
					var gotTables, gotKeys []string
					for _, e := range readAll(t, p, &p4.Entity{Entity: &p4.Entity_TableEntry{TableEntry: &p4.TableEntry{}}}) {
						gotTables = append(gotTables, marshal(t, e.GetTableEntry()))
					}
					for _, e := range readAll(t, p, &p4.Entity{Entity: &p4.Entity_ExternEntry{ExternEntry: &p4.ExternEntry{ExternTypeId: ExternPspSa, ExternId: ExternKeys}}}) {
						x := &dpv1.PspSaEntry{}
						require.NoError(t, e.GetExternEntry().GetEntry().UnmarshalTo(x))
						gotKeys = append(gotKeys, marshal(t, x))
					}
					assert.ElementsMatch(t, tables, gotTables, "step %d: the table entries after a failed Write", i)
					assert.ElementsMatch(t, keys, gotKeys, "step %d: the keys entries after a failed Write", i)
					assert.Empty(t, readAll(t, p, &p4.Entity{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{}}}), "step %d: the counters", i)
				}
				if s.want != nil {
					require.NotNil(t, p.steering.Load(), "step %d", i)
					assert.Equal(t, s.want, *p.steering.Load(), "step %d", i)
				}
			}
		})
	}
}

// readWritten checks the update u of the Write of step i that passed: a Read with the entity of u as
// the filter gives that entity, or nothing after a DELETE. A keys entry comes back with no key, and
// with no packets or sequence number, as no packet goes in these steps. No step writes one key two
// times.
func readWritten(t *testing.T, p *Pipeline, i int, u *p4.Update) {
	t.Helper()
	want := u.GetEntity()
	got := readAll(t, p, want)
	if u.GetType() == p4.Update_DELETE {
		assert.Empty(t, got, "step %d: %v after its DELETE", i, want)
		return
	}
	if !assert.Len(t, got, 1, "step %d: %v", i, want) {
		return
	}
	if x := want.GetExternEntry(); x != nil {
		w, g := &dpv1.PspSaEntry{}, &dpv1.PspSaEntry{}
		require.NoError(t, x.GetEntry().UnmarshalTo(w))
		require.NoError(t, got[0].GetExternEntry().GetEntry().UnmarshalTo(g))
		w.Key = nil
		assert.True(t, proto.Equal(w, g), "step %d: want %v, got %v", i, w, g)
		return
	}
	assert.True(t, proto.Equal(want, got[0]), "step %d: want %v, got %v", i, want, got[0])
}

// readAll returns the entities of p that match e.
func readAll(t *testing.T, p *Pipeline, e *p4.Entity) []*p4.Entity {
	t.Helper()
	var out []*p4.Entity
	require.NoError(t, p.Read(t.Context(), &p4.ReadRequest{Entities: []*p4.Entity{e}}, func(e *p4.Entity) { out = append(out, e) }))
	return out
}

// marshal returns m as deterministic bytes, to compare two messages.
func marshal(t *testing.T, m proto.Message) string {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	require.NoError(t, err)
	return string(b)
}
