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

// fakeConn is a connection of a relay session. It counts the frames sent on
// it, and its reader gets the frames on in. Its reader ends when gone closes.
type fakeConn struct {
	quic.Connection
	sent atomic.Int64
	in   chan []byte
	gone chan struct{}
}

func newFakeConn() *fakeConn { return &fakeConn{in: make(chan []byte, 4), gone: make(chan struct{})} }

func (f *fakeConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-f.in:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.gone:
		return nil, net.ErrClosed
	}
}

func (f *fakeConn) SendDatagram([]byte) error {
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

// connOf sends frame on c and returns the index of the connection that took it.
func connOf(t *testing.T, c *Conn, qcs []*fakeConn, frame []byte) int {
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
	t.Fatal("no connection took the frame")
	return -1
}

func newConns(t *testing.T, n int) (*Conn, []*fakeConn) {
	t.Helper()
	qcs := make([]*fakeConn, n)
	for i := range qcs {
		qcs[i] = newFakeConn()
	}
	c := New(qcs[0])
	t.Cleanup(func() { _ = c.Close() })
	for i := 1; i < n; i++ {
		require.NoError(t, c.SetExtra(i, qcs[i]))
	}
	return c, qcs
}

func TestSendData(t *testing.T) {
	const flows = 256
	cases := []struct {
		name string
		n    int   // Connections, with the session.
		down []int // Extra connections removed with SetExtra.
	}{
		{name: "session only", n: 1},
		{name: "two connections", n: 2},
		{name: "four connections", n: 4},
		{name: "extra connection removed", n: 4, down: []int{2}},
		{name: "two extra connections down", n: 4, down: []int{1, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, qcs := newConns(t, tc.n)
			before := make([]int, flows)
			used := make([]int, tc.n)
			for id := range uint16(flows) {
				before[id] = connOf(t, c, qcs, flowFrame(id))
				used[before[id]]++
			}
			for i, n := range used {
				assert.NotZero(t, n, "connection %d got no flow", i)
			}

			for _, i := range tc.down {
				require.NoError(t, c.SetExtra(i, nil))
			}
			off := tc.down
			for id := range uint16(flows) {
				got := connOf(t, c, qcs, flowFrame(id))
				assert.Equal(t, got, connOf(t, c, qcs, flowFrame(id)), "flow %d changed connection", id)
				assert.NotContains(t, off, got, "flow %d", id)
				if !slices.Contains(off, before[id]) {
					assert.Equal(t, before[id], got, "flow %d moved from a live connection", id)
				}
			}
		})
	}
}

func TestSendDataSession(t *testing.T) {
	c, qcs := newConns(t, 4)
	assert.Equal(t, 0, connOf(t, c, qcs, EncodeData(nil, testVNI, nil)), "frame with no packet")
	assert.Equal(t, 0, connOf(t, c, qcs, []byte{TypeData}), "short frame")

	require.NoError(t, c.Close())
	assert.ErrorIs(t, c.SendData(flowFrame(1)), net.ErrClosed)
}

func TestSetExtra(t *testing.T) {
	c, _ := newConns(t, 1)
	for _, i := range []int{-1, 0, MaxConns} {
		assert.ErrorIs(t, c.SetExtra(i, newFakeConn()), ErrExtraIndex, "index %d", i)
	}
	require.NoError(t, c.Close())
	assert.ErrorIs(t, c.SetExtra(1, newFakeConn()), net.ErrClosed)
}

// TestConnsQUIC sends flows on four QUIC connections from one socket to a
// relay in this process, and data frames back on each connection.
func TestConnsQUIC(t *testing.T) {
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
		conn int
		seq  uint32
	}
	var mu sync.Mutex
	seen := map[uint16][]got{}
	var total atomic.Int64
	server := make([]quic.Connection, MaxConns)
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
	qcs := make([]quic.Connection, MaxConns)
	for i := range qcs {
		qcs[i], err = tr.Dial(ctx, ln.Addr(), tc, &quic.Config{EnableDatagrams: true})
		require.NoError(t, err)
		t.Cleanup(func() { _ = qcs[i].CloseWithError(0, "") })
	}
	<-accepted
	c := New(qcs[0])
	defer c.Close()
	for i := 1; i < MaxConns; i++ {
		require.NoError(t, c.SetExtra(i, qcs[i]))
		go c.Receive(ctx, qcs[i])
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
	require.Eventually(t, func() bool { return handled.Load() == MaxConns*back }, 5*time.Second, time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	perConn := make([]int, MaxConns)
	for id, gs := range seen {
		for j, g := range gs {
			require.Equal(t, gs[0].conn, g.conn, "flow %d is on two connections", id)
			require.Equal(t, uint32(j), g.seq, "flow %d is out of order", id)
		}
		perConn[gs[0].conn]++
	}
	t.Logf("Flows on each connection: %v", perConn)
	for i, n := range perConn {
		assert.NotZero(t, n, "connection %d got no flow", i)
	}
}

func BenchmarkSendData(b *testing.B) {
	qcs := make([]*fakeConn, MaxConns)
	for i := range qcs {
		qcs[i] = newFakeConn()
	}
	c := New(qcs[0])
	defer c.Close()
	for i := 1; i < MaxConns; i++ {
		if err := c.SetExtra(i, qcs[i]); err != nil {
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
