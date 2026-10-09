// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The sizes of the README. The tests do not use the constants of the relay, so
// that a change of a limit fails a test.
const (
	testPart  = 1 << 20
	testLimit = 64 << 20
)

// snapshotHost is the host of a test relay: the bytes that its hook gives, and
// the number of calls of the hook.
type snapshotHost struct {
	data  atomic.Pointer[[]byte]
	calls atomic.Int32
}

func (h *snapshotHost) snapshot() []byte {
	h.calls.Add(1)
	if b := h.data.Load(); b != nil {
		return *b
	}
	return nil
}

// readSnapshot reads the parts of a Snapshot call on c: the size and the
// total_size of each part, and all the bytes. With first, it reads one part only.
func readSnapshot(ctx context.Context, c dp.MeshClient, first bool) (sizes []int, totals []uint64, data []byte, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := c.Snapshot(ctx, &dp.SnapshotRequest{})
	if err != nil {
		return nil, nil, nil, err
	}
	for {
		part, err := st.Recv()
		if err == io.EOF {
			return sizes, totals, data, nil
		}
		if err != nil {
			return sizes, totals, data, err
		}
		sizes, totals = append(sizes, len(part.GetData())), append(totals, part.GetTotalSize())
		if first {
			return sizes, totals, nil, nil
		}
		data = append(data, part.GetData()...)
	}
}

// TestMeshSnapshotServe checks the answer of a relay to the Snapshot call of a
// member, by the bytes that its host gives, and what FetchSnapshot makes of it.
func TestMeshSnapshotServe(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	a, b := newMeshNode(t, ca, "relay-a"), newMeshNode(t, ca, "relay-b")
	// Only relay-b has a host with the hook.
	host := &snapshotHost{}
	b.m.cfg.Snapshot = host.snapshot
	a.m.SetMembers([]MeshMember{b.member()})
	b.m.SetMembers([]MeshMember{a.member()})
	b.start(t)
	a.start(t)
	require.Equal(t, MeshChange{Name: "relay-b", Up: true}, a.change(t, 10*time.Second))
	require.Equal(t, MeshChange{Name: "relay-a", Up: true}, b.change(t, 10*time.Second))
	sa, sb := a.session(t), b.session(t)

	cases := []struct {
		name   string
		noHook bool     // The call goes to relay-a.
		size   int      // Bytes that the host of relay-b gives. -1 is a nil slice.
		first  bool     // The test reads the first part only: the whole snapshot takes too long.
		parts  []int    // Size of each part.
		code   rpc.Code // Error of the call.
	}{
		{name: "relay with no hook", noHook: true, code: rpc.NotFound},
		{name: "host gives nil", size: -1, code: rpc.NotFound},
		{name: "host gives no bytes", size: 0, code: rpc.NotFound},
		{name: "one byte", size: 1, parts: []int{1}},
		{name: "one byte less than a part", size: testPart - 1, parts: []int{testPart - 1}},
		{name: "one full part", size: testPart, parts: []int{testPart}},
		{name: "one byte more than a part", size: testPart + 1, parts: []int{testPart, 1}},
		{name: "three parts and five bytes", size: 3*testPart + 5, parts: []int{testPart, testPart, testPart, 5}},
		{name: "the size limit", size: testLimit, first: true, parts: []int{testPart}},
		{name: "one byte more than the size limit", size: testLimit + 1, code: rpc.ResourceExhausted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var want []byte
			if tc.size >= 0 {
				want = make([]byte, tc.size)
				if tc.size <= 4*testPart {
					_, _ = rand.Read(want)
				}
			}
			host.data.Store(&want)
			host.calls.Store(0)
			client, asker := sa.Client(), a
			if tc.noHook {
				client, asker = sb.Client(), b
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			sizes, totals, got, err := readSnapshot(ctx, client, tc.first)
			require.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
			assert.Equal(t, tc.parts, sizes, "size of each part")
			// Only the first part has the size of the whole snapshot.
			var wantTotals []uint64
			for i := range tc.parts {
				wantTotals = append(wantTotals, 0)
				if i == 0 {
					wantTotals[0] = uint64(tc.size)
				}
			}
			assert.Equal(t, wantTotals, totals, "total_size of each part")
			if !tc.noHook {
				assert.EqualValues(t, 1, host.calls.Load(), "the relay calls the hook one time for a call")
			}
			if tc.first {
				return
			}
			if tc.code == rpc.OK {
				assert.True(t, bytes.Equal(want, got), "the caller gets the bytes of the host")
			}

			// The relay that asks gets the same bytes, or NotFound for each refusal.
			data, from, err := asker.m.FetchSnapshot(ctx)
			if tc.code != rpc.OK {
				assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "error: %v", err)
				assert.Nil(t, data)
				assert.Empty(t, from)
				return
			}
			require.NoError(t, err)
			assert.True(t, bytes.Equal(want, data), "FetchSnapshot gives the bytes of the host")
			assert.Equal(t, "relay-b", from)
		})
	}
}

// TestMeshSnapshotCaller checks that only the open session of a member gets the
// snapshot: for each other connection, the relay does not call the hook of the host.
func TestMeshSnapshotCaller(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cert    string // Name in the certificate of the dialer.
		otherCA bool   // The certificate is from another CA, as that of an agent is.
		open    string // Name in the Open call. Empty is no Open call.
		gets    bool   // The dialer gets the snapshot.
	}{
		{name: "member after Open", cert: "relay-a", open: "relay-a", gets: true},
		{name: "certificate of a member, no Open call", cert: "relay-a"},
		{name: "certificate of another CA, no Open call", cert: "relay-a", otherCA: true},
		{name: "certificate of another CA, Open with the name of a member", cert: "relay-a", otherCA: true, open: "relay-a"},
		{name: "certificate of a member, Open with another name", cert: "relay-a", open: "relay-x"},
		{name: "certificate of a relay that is not a member", cert: "relay-x", open: "relay-x"},
		{name: "member with a higher name, which must not dial", cert: "relay-z", open: "relay-z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca := newCA(t)
			n := newMeshNode(t, ca, "relay-m")
			want := []byte("snapshot of relay-m")
			host := &snapshotHost{}
			host.data.Store(&want)
			n.m.cfg.Snapshot = host.snapshot
			// The members do not listen, so the relay opens no session itself.
			n.m.SetMembers([]MeshMember{
				{Name: "relay-a", Addr: netip.MustParseAddrPort("127.0.0.1:1")},
				{Name: "relay-z", Addr: netip.MustParseAddrPort("127.0.0.1:2")},
			})
			n.listen(t)

			certCA := ca
			if tc.otherCA {
				certCA = newCA(t)
			}
			client := dp.NewMeshClient(rpc.NewConn(n.rawDial(t, certCA.meshCert(t, tc.cert)), nil))
			if tc.open != "" {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, err := client.Open(ctx, &dp.MeshOpenRequest{Version: dp.LocalVersion("test"), Name: tc.open})
				cancel()
				require.Equal(t, tc.gets, err == nil, "Open: %v", err)
			}
			// A call before Open waits for it, so the deadline ends the call.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			sizes, _, got, err := readSnapshot(ctx, client, false)
			if tc.gets {
				require.NoError(t, err)
				assert.Equal(t, want, got)
				assert.EqualValues(t, 1, host.calls.Load())
				return
			}
			assert.Error(t, err)
			assert.Empty(t, sizes, "the dialer gets no part")
			// The relay ends a call a moment after the dialer does, so the count gets some time.
			assert.Never(t, func() bool { return host.calls.Load() != 0 }, 300*time.Millisecond, 10*time.Millisecond,
				"the relay does not call the hook")
		})
	}
}

// TestMeshSnapshotOldRelay checks a member from before the Snapshot call: it
// answers Unimplemented, and FetchSnapshot does not take it as an error of the mesh.
func TestMeshSnapshotOldRelay(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	old := &dp.Version{Revision: 13}
	addr, _ := listenFake(t, ca.meshCert(t, "relay-z"), fakeMesh{res: &dp.MeshOpenResponse{Version: old, Name: "relay-z"}})
	n := newMeshNode(t, ca, "relay-m")
	n.m.SetMembers([]MeshMember{{Name: "relay-z", Addr: addr}})
	n.start(t)
	require.Equal(t, MeshChange{Name: "relay-z", Up: true}, n.change(t, 10*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, _, err := readSnapshot(ctx, n.session(t).Client(), false)
	assert.Equal(t, rpc.Unimplemented, rpc.CodeOf(err), "error: %v", err)
	_, _, err = n.m.FetchSnapshot(ctx)
	assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "error: %v", err)
}

// snapPeer is one member in the tests of the relay that asks, and what its
// Snapshot call does.
type snapPeer struct {
	name  string
	rev   uint32             // Revision in Open. Zero is 14.
	down  bool               // The member has no open session.
	ended bool               // The session of the member ended.
	wait  time.Duration      // Time before each answer.
	parts []*dp.SnapshotPart // Parts that the member sends.
	err   error              // Answer after the parts. Nil is the end of the stream.
}

// snapCall is one Snapshot call that a member got.
type snapCall struct {
	name  string
	limit time.Duration // Time to the deadline of the call.
	ctx   context.Context
	st    *snapStream
}

// snapClient is the mesh client of a session to a snapPeer. calls has each call
// of the relay, in order.
type snapClient struct {
	dp.MeshClient
	p     snapPeer
	calls *[]snapCall
}

func (c snapClient) Snapshot(ctx context.Context, _ *dp.SnapshotRequest) (rpc.ServerStreamClient[dp.SnapshotPart], error) {
	// The client of a real session makes no call with a context that ended.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	call := snapCall{name: c.p.name, ctx: ctx, st: &snapStream{ctx: ctx, p: c.p}}
	if d, ok := ctx.Deadline(); ok {
		call.limit = time.Until(d)
	}
	*c.calls = append(*c.calls, call)
	return call.st, nil
}

// snapStream is the calling side of the Snapshot call to a snapPeer.
type snapStream struct {
	ctx   context.Context
	p     snapPeer
	next  int
	reads int // Number of Recv calls.
}

func (s *snapStream) Recv() (*dp.SnapshotPart, error) {
	s.reads++
	t := time.NewTimer(s.p.wait)
	defer t.Stop()
	select {
	case <-t.C:
	case <-s.ctx.Done():
		return nil, rpc.Errorf(rpc.DeadlineExceeded, "%v", s.ctx.Err())
	}
	if s.next < len(s.p.parts) {
		s.next++
		return s.p.parts[s.next-1], nil
	}
	if s.p.err != nil {
		return nil, s.p.err
	}
	return nil, io.EOF
}

// TestFetchSnapshot checks which members FetchSnapshot asks, in which order and
// for how long, and which answers it takes.
func TestFetchSnapshot(t *testing.T) {
	part := func(total uint64, data string) *dp.SnapshotPart {
		return &dp.SnapshotPart{TotalSize: total, Data: []byte(data)}
	}
	has := func(name, data string) snapPeer {
		return snapPeer{name: name, parts: []*dp.SnapshotPart{part(uint64(len(data)), data)}}
	}
	none := func(name string) snapPeer {
		return snapPeer{name: name, err: rpc.Errorf(rpc.NotFound, "relay host has no snapshot")}
	}
	slow := func(name string) snapPeer {
		p := has(name, "late")
		p.wait = time.Hour
		return p
	}
	// full has a snapshot of size bytes in parts of 1 MiB, with claim as its total_size.
	full := func(name string, size int, claim uint64) snapPeer {
		p := snapPeer{name: name}
		one := bytes.Repeat([]byte{7}, testPart)
		for rest := size; rest > 0; rest -= testPart {
			p.parts = append(p.parts, &dp.SnapshotPart{Data: one[:min(rest, testPart)]})
		}
		p.parts[0].TotalSize = claim
		return p
	}
	cases := []struct {
		name    string
		peers   []snapPeer
		caller  time.Duration // Time to the deadline of the caller. Zero is no deadline.
		want    string        // Bytes of the snapshot. Empty with size is no snapshot.
		size    int           // The snapshot is this number of bytes with the value 7.
		from    string
		err     error // Error of the context of the caller. Nil with no snapshot is NotFound.
		asked   []string
		reads   int // Answers that the relay read from the first member that it asked. Zero is no check.
		elapsed time.Duration
	}{
		{name: "mesh with no member"},
		{name: "one member with a snapshot", peers: []snapPeer{has("relay-a", "one")}, want: "one", from: "relay-a", asked: []string{"relay-a"}},
		{
			name:  "snapshot in three parts",
			peers: []snapPeer{{name: "relay-a", parts: []*dp.SnapshotPart{part(9, "one"), part(0, "two"), part(0, "end")}}},
			want:  "onetwoend", from: "relay-a", asked: []string{"relay-a"},
		},
		{
			name:  "the first member in name order wins",
			peers: []snapPeer{has("relay-c", "c"), has("relay-a", "a"), has("relay-b", "b")},
			want:  "a", from: "relay-a", asked: []string{"relay-a"},
		},
		{
			name:  "member with no snapshot, then the next member",
			peers: []snapPeer{has("relay-c", "c"), none("relay-a"), has("relay-b", "b")},
			want:  "b", from: "relay-b", asked: []string{"relay-a", "relay-b"},
		},
		{
			name:  "member with no Snapshot call, then the next member",
			peers: []snapPeer{{name: "relay-a", err: rpc.Errorf(rpc.Unimplemented, "unknown method")}, has("relay-b", "b")},
			want:  "b", from: "relay-b", asked: []string{"relay-a", "relay-b"},
		},
		{
			name:  "no member has a snapshot",
			peers: []snapPeer{none("relay-a"), none("relay-b"), none("relay-c")},
			asked: []string{"relay-a", "relay-b", "relay-c"},
		},

		// A member that cannot answer costs no call.
		{
			name:  "member one revision before the call is not asked",
			peers: []snapPeer{{name: "relay-a", rev: 13, parts: has("", "old").parts}, has("relay-b", "b")},
			want:  "b", from: "relay-b", asked: []string{"relay-b"},
		},
		{name: "only a member before the call", peers: []snapPeer{{name: "relay-a", rev: 13, parts: has("", "old").parts}}},
		{
			name:  "member at a later revision",
			peers: []snapPeer{{name: "relay-a", rev: 15, parts: has("", "new").parts}},
			want:  "new", from: "relay-a", asked: []string{"relay-a"},
		},
		{
			name:  "member with no session is not asked",
			peers: []snapPeer{{name: "relay-a", down: true}, has("relay-b", "b")},
			want:  "b", from: "relay-b", asked: []string{"relay-b"},
		},
		{
			name:  "member whose session ended is not asked",
			peers: []snapPeer{{name: "relay-a", ended: true}, has("relay-b", "b")},
			want:  "b", from: "relay-b", asked: []string{"relay-b"},
		},

		// The time limit for one member.
		{
			name:  "slow member, then the next member",
			peers: []snapPeer{slow("relay-a"), has("relay-b", "b")},
			want:  "b", from: "relay-b", asked: []string{"relay-a", "relay-b"}, elapsed: 10 * time.Second,
		},
		{
			name: "member that stops after one part",
			peers: []snapPeer{
				{name: "relay-a", wait: 6 * time.Second, parts: []*dp.SnapshotPart{part(6, "one"), part(0, "two")}},
				has("relay-b", "b"),
			},
			want: "b", from: "relay-b", asked: []string{"relay-a", "relay-b"}, elapsed: 10 * time.Second,
		},
		{
			name:  "member that answers one moment before the limit",
			peers: []snapPeer{{name: "relay-a", wait: 5*time.Second - time.Nanosecond, parts: has("", "late").parts}, has("relay-b", "b")},
			want:  "late", from: "relay-a", asked: []string{"relay-a"}, elapsed: 10*time.Second - 2*time.Nanosecond,
		},
		{
			name:  "two slow members",
			peers: []snapPeer{slow("relay-a"), slow("relay-b")},
			asked: []string{"relay-a", "relay-b"}, elapsed: 20 * time.Second,
		},
		{
			name:  "deadline of the caller in the call to a slow member",
			peers: []snapPeer{slow("relay-a"), has("relay-b", "b")}, caller: 3 * time.Second,
			err: context.DeadlineExceeded, asked: []string{"relay-a"}, elapsed: 3 * time.Second,
		},

		// The size checks of the relay that asks.
		{
			// The relay refuses the size before it reads the bytes.
			name:  "size of one byte more than the limit",
			peers: []snapPeer{full("relay-a", 3*testPart, testLimit+1), has("relay-b", "b")},
			want:  "b", from: "relay-b", asked: []string{"relay-a", "relay-b"}, reads: 1,
		},
		{name: "size at the limit", peers: []snapPeer{full("relay-a", testLimit, testLimit)}, size: testLimit, from: "relay-a", asked: []string{"relay-a"}},
		{
			name:  "first part with no size",
			peers: []snapPeer{{name: "relay-a", parts: []*dp.SnapshotPart{part(0, "one"), part(6, "two")}}, has("relay-b", "b")},
			want:  "b", from: "relay-b", asked: []string{"relay-a", "relay-b"},
		},
		{
			// The relay stops at the part that passes the size, and reads no more.
			name: "one byte more than the size",
			peers: []snapPeer{
				{name: "relay-a", parts: []*dp.SnapshotPart{part(5, "one"), part(0, "two"), part(0, "end")}},
				has("relay-b", "b"),
			},
			want: "b", from: "relay-b", asked: []string{"relay-a", "relay-b"}, reads: 2,
		},
		{
			name:  "one byte less than the size",
			peers: []snapPeer{{name: "relay-a", parts: []*dp.SnapshotPart{part(7, "one"), part(0, "two")}}, has("relay-b", "b")},
			want:  "b", from: "relay-b", asked: []string{"relay-a", "relay-b"},
		},
		{
			name:  "size with no bytes",
			peers: []snapPeer{{name: "relay-a", parts: []*dp.SnapshotPart{part(3, "")}}, has("relay-b", "b")},
			want:  "b", from: "relay-b", asked: []string{"relay-a", "relay-b"},
		},
		{name: "stream with no part", peers: []snapPeer{{name: "relay-a"}}, asked: []string{"relay-a"}},
		{
			name: "member that fails after one part",
			peers: []snapPeer{
				{name: "relay-a", parts: []*dp.SnapshotPart{part(3, "one")}, err: rpc.Errorf(rpc.Unavailable, "session closed")},
				has("relay-b", "b"),
			},
			want: "b", from: "relay-b", asked: []string{"relay-a", "relay-b"},
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m, err := NewMesh("relay-m", cfg)
				require.NoError(t, err)
				var members []MeshMember
				for i, p := range tc.peers {
					members = append(members, MeshMember{Name: p.name, Addr: netip.AddrPortFrom(trunkRigAddr.Addr(), uint16(7000+i))})
				}
				m.SetMembers(members)
				var calls []snapCall
				for _, p := range tc.peers {
					if p.down {
						continue
					}
					conn := newStubConn()
					s := m.newSession(conn, false)
					s.client = snapClient{p: p, calls: &calls}
					require.True(t, m.track(s))
					rev := p.rev
					if rev == 0 {
						rev = 14
					}
					require.NoError(t, m.admit(s, p.name, nil, &dp.Version{Revision: rev}, nil))
					if p.ended {
						conn.cancel(&quic.IdleTimeoutError{})
						synctest.Wait()
					}
				}
				ctx := t.Context()
				if tc.caller > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tc.caller)
					defer cancel()
				}

				start := time.Now()
				data, from, err := m.FetchSnapshot(ctx)
				assert.Equal(t, tc.elapsed, time.Since(start), "time of the call")
				want := []byte(tc.want)
				if tc.size > 0 {
					want = bytes.Repeat([]byte{7}, tc.size)
				}
				switch {
				case len(want) > 0:
					require.NoError(t, err)
					assert.True(t, bytes.Equal(want, data), "bytes of the snapshot")
				case tc.err != nil:
					assert.ErrorIs(t, err, tc.err)
					assert.Nil(t, data)
				default:
					assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "error: %v", err)
					assert.Nil(t, data)
				}
				assert.Equal(t, tc.from, from)
				var asked []string
				for _, c := range calls {
					asked = append(asked, c.name)
					// The member gets the limit in the call, and the call ends on the two sides.
					limit := 10 * time.Second
					if tc.caller > 0 {
						limit = tc.caller
					}
					assert.Equal(t, limit, c.limit, "time limit of the call to %s", c.name)
					assert.Error(t, c.ctx.Err(), "the call to %s ended", c.name)
				}
				assert.Equal(t, tc.asked, asked, "members that got a call")
				if tc.reads > 0 {
					assert.Equal(t, tc.reads, calls[0].st.reads, "answers that the relay read from %s", calls[0].name)
				}
			})
		})
	}
}
