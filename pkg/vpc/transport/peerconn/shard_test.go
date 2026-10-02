// SPDX-License-Identifier: AGPL-3.0-only

package peerconn

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shardQC is a shard. It counts the frames sent on it. Its reader ends when
// gone closes.
type shardQC struct {
	quic.Connection
	sent atomic.Int64
	gone chan struct{}
}

func newShardQC() *shardQC { return &shardQC{gone: make(chan struct{})} }

func (f *shardQC) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.gone:
		return nil, net.ErrClosed
	}
}

func (f *shardQC) SendDatagram([]byte) error {
	f.sent.Add(1)
	return nil
}

// flowPacket returns an IPv4 UDP packet of flow id with seq in its payload.
func flowPacket(id uint16, seq uint32) []byte {
	p := ipPacket(netip.MustParseAddr("10.0.0.1"), 32)
	p[9] = 17
	copy(p[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(p[20:], id)
	binary.BigEndian.PutUint16(p[22:], 443)
	binary.BigEndian.PutUint32(p[28:], seq)
	return p
}

func flowFrame(id uint16) []byte { return EncodeData(nil, testVNI, flowPacket(id, 0)) }

// shardOf sends frame on c and returns the index of the shard that took it.
func shardOf(t *testing.T, c *Conn, qcs []*shardQC, frame []byte) int {
	t.Helper()
	before := make([]int64, len(qcs))
	for i, qc := range qcs {
		before[i] = qc.sent.Load()
	}
	require.NoError(t, c.SendData(frame))
	for i, qc := range qcs {
		if qc.sent.Load() != before[i] {
			return i
		}
	}
	t.Fatal("no shard took the frame")
	return -1
}

func newShards(t *testing.T, n int) (*Conn, []*shardQC) {
	t.Helper()
	qcs := make([]*shardQC, n)
	for i := range qcs {
		qcs[i] = newShardQC()
	}
	c := New(qcs[0], testSrc)
	t.Cleanup(func() { _ = c.Close() })
	for i := 1; i < n; i++ {
		require.NoError(t, c.SetShard(i, qcs[i]))
	}
	return c, qcs
}

func TestSendData(t *testing.T) {
	const flows = 256
	cases := []struct {
		name string
		n    int   // Shards, with the session.
		down []int // Shards removed with SetShard.
		gone []int // Shards whose connection closed.
	}{
		{name: "session only", n: 1},
		{name: "two shards", n: 2},
		{name: "four shards", n: 4},
		{name: "shard removed", n: 4, down: []int{2}},
		{name: "shard closed", n: 4, gone: []int{3}},
		{name: "two shards down", n: 4, down: []int{1}, gone: []int{2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, qcs := newShards(t, tc.n)
			before := make([]int, flows)
			used := make([]int, tc.n)
			for id := range uint16(flows) {
				before[id] = shardOf(t, c, qcs, flowFrame(id))
				used[before[id]]++
			}
			for i, n := range used {
				assert.NotZero(t, n, "shard %d got no flow", i)
			}

			for _, i := range tc.down {
				require.NoError(t, c.SetShard(i, nil))
			}
			for _, i := range tc.gone {
				close(qcs[i].gone)
				require.Eventually(t, func() bool { return c.shards.Load().conns[i] == nil }, 5*time.Second, time.Millisecond)
			}
			off := append(slices.Clone(tc.down), tc.gone...)
			for id := range uint16(flows) {
				got := shardOf(t, c, qcs, flowFrame(id))
				assert.Equal(t, got, shardOf(t, c, qcs, flowFrame(id)), "flow %d changed shard", id)
				assert.NotContains(t, off, got, "flow %d", id)
				if !slices.Contains(off, before[id]) {
					assert.Equal(t, before[id], got, "flow %d moved from a live shard", id)
				}
			}
		})
	}
}

func TestSendDataSession(t *testing.T) {
	c, qcs := newShards(t, 4)
	assert.Equal(t, 0, shardOf(t, c, qcs, EncodeData(nil, testVNI, nil)), "frame with no packet")
	assert.Equal(t, 0, shardOf(t, c, qcs, []byte{TypeData}), "short frame")

	// A new session drops the shards of the old one.
	next := newShardQC()
	c.SetConn(next)
	all := append(qcs, next)
	for id := range uint16(64) {
		require.Equal(t, 4, shardOf(t, c, all, flowFrame(id)))
	}
	require.NoError(t, c.Close())
	assert.ErrorIs(t, c.SendData(flowFrame(1)), net.ErrClosed)
}

func TestSetShard(t *testing.T) {
	c, _ := newShards(t, 1)
	for _, i := range []int{-1, 0, MaxShards} {
		assert.ErrorIs(t, c.SetShard(i, newShardQC()), ErrShard, "index %d", i)
	}
	require.NoError(t, c.Close())
	assert.ErrorIs(t, c.SetShard(1, newShardQC()), net.ErrClosed)
}

// TestShardsQUIC sends flows on four QUIC connections from one socket to a
// relay in this process, and data frames back on each connection.
func TestShardsQUIC(t *testing.T) {
	const (
		flows   = 64
		packets = 20
		back    = 25
	)
	p := newPKI(t)
	ln, err := newTransport(t).Listen(&tls.Config{
		Certificates: []tls.Certificate{p.issue(t, "relay.test")},
		NextProtos:   []string{alpnRelay},
	}, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)

	type got struct {
		shard int
		seq   uint32
	}
	var mu sync.Mutex
	seen := map[uint16][]got{}
	var total atomic.Int64
	server := make([]quic.Connection, MaxShards)
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for i := range server {
			qc, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			server[i] = qc
			go func() {
				for {
					b, err := qc.ReceiveDatagram(qc.Context())
					if err != nil {
						return
					}
					_, inner, err := DecodeData(b)
					if err != nil {
						continue
					}
					id := binary.BigEndian.Uint16(inner[20:])
					mu.Lock()
					seen[id] = append(seen[id], got{i, binary.BigEndian.Uint32(inner[28:])})
					mu.Unlock()
					total.Add(1)
				}
			}()
		}
	}()

	tr := newTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tc := &tls.Config{RootCAs: p.pool, ServerName: "relay.test", NextProtos: []string{alpnRelay}}
	qcs := make([]quic.Connection, MaxShards)
	for i := range qcs {
		qcs[i], err = tr.Dial(ctx, ln.Addr(), tc, &quic.Config{EnableDatagrams: true})
		require.NoError(t, err)
		t.Cleanup(func() { _ = qcs[i].CloseWithError(0, "") })
	}
	<-accepted
	c := New(qcs[0], testSrc)
	defer c.Close()
	for i := 1; i < MaxShards; i++ {
		require.NoError(t, c.SetShard(i, qcs[i]))
	}
	var handled atomic.Int64
	c.HandleData(func([]byte) { handled.Add(1) })

	// One round of flows at a time, so that no socket buffer fills.
	for seq := range uint32(packets) {
		for id := range uint16(flows) {
			require.NoError(t, c.SendData(EncodeData(nil, testVNI, flowPacket(id, seq))))
		}
		want := int64(flows) * int64(seq+1)
		require.Eventually(t, func() bool { return total.Load() == want }, 5*time.Second, time.Millisecond, "round %d", seq)
	}
	for _, sc := range server {
		for range back {
			require.NoError(t, sc.SendDatagram(flowFrame(1)))
		}
	}
	require.Eventually(t, func() bool { return handled.Load() == MaxShards*back }, 5*time.Second, time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	perShard := make([]int, MaxShards)
	for id, gs := range seen {
		for j, g := range gs {
			require.Equal(t, gs[0].shard, g.shard, "flow %d is on two connections", id)
			require.Equal(t, uint32(j), g.seq, "flow %d is out of order", id)
		}
		perShard[gs[0].shard]++
	}
	t.Logf("Flows on each connection: %v", perShard)
	for i, n := range perShard {
		assert.NotZero(t, n, "connection %d got no flow", i)
	}
}

func BenchmarkSendData(b *testing.B) {
	qcs := make([]*shardQC, MaxShards)
	for i := range qcs {
		qcs[i] = newShardQC()
	}
	c := New(qcs[0], testSrc)
	defer c.Close()
	for i := 1; i < MaxShards; i++ {
		if err := c.SetShard(i, qcs[i]); err != nil {
			b.Fatal(err)
		}
	}
	frame := EncodeData(nil, testVNI, flowPacket(7, 0))
	b.SetBytes(int64(len(frame)))
	b.ReportAllocs()
	for b.Loop() {
		if err := c.SendData(frame); err != nil {
			b.Fatal(err)
		}
	}
}
