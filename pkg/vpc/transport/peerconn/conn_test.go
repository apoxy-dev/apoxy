// SPDX-License-Identifier: AGPL-3.0-only

package peerconn

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testSrc = netip.MustParseAddr("fd00::1")

func TestWriteTo(t *testing.T) {
	ip := netip.MustParseAddr
	pkt := []byte("hello")
	cases := []struct {
		name  string
		prep  func(c *Conn, qc *fakeQC)
		addr  net.Addr
		frame []byte // The frame on the relay session; nil if none.
		err   error
		drops uint64
	}{
		{name: "IPv6", addr: udpAddr("fd00::2"), frame: EncodeToRelay(nil, ip("fd00::2"), testSrc, pkt)},
		{name: "IPv4", addr: udpAddr("10.0.0.2"), frame: EncodeToRelay(nil, ip("10.0.0.2"), testSrc, pkt)},
		{name: "IPv4 in 16 B", addr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2)}, frame: EncodeToRelay(nil, ip("10.0.0.2"), testSrc, pkt)},
		{
			name:  "relay session does not take it",
			prep:  func(_ *Conn, qc *fakeQC) { qc.err = errors.New("session closed") },
			addr:  udpAddr("fd00::2"),
			drops: 1,
		},
		{name: "not UDP", addr: &net.IPAddr{IP: net.ParseIP("fd00::2")}, err: ErrAddr},
		{name: "no IP", addr: &net.UDPAddr{}, err: ErrAddr},
		{name: "closed", prep: func(c *Conn, _ *fakeQC) { _ = c.Close() }, addr: udpAddr("fd00::2"), err: net.ErrClosed},
		{
			name: "deadline passed",
			prep: func(c *Conn, _ *fakeQC) { _ = c.SetWriteDeadline(time.Now()) },
			addr: udpAddr("fd00::2"),
			err:  os.ErrDeadlineExceeded,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qc := newFakeQC()
			c := New(qc, testSrc).(*Conn)
			defer c.Close()
			if tc.prep != nil {
				tc.prep(c, qc)
			}
			n, err := c.WriteTo(pkt, tc.addr)
			require.ErrorIs(t, err, tc.err)
			if tc.err == nil {
				assert.Equal(t, len(pkt), n)
			}
			if tc.frame != nil {
				assert.Equal(t, tc.frame, <-qc.sent)
			}
			assert.Empty(t, qc.sent)
			assert.Equal(t, Stats{WriteDrops: tc.drops}, c.Stats())
		})
	}
}

func TestReadFrom(t *testing.T) {
	ip := netip.MustParseAddr
	marker := EncodeFromRelay(nil, ip("fd00::9"), []byte("next"))
	cases := []struct {
		name  string
		frame []byte
		src   netip.Addr // Invalid if c drops the frame.
		pkt   string
	}{
		{"IPv6", EncodeFromRelay(nil, ip("fd00::2"), []byte("hi")), ip("fd00::2"), "hi"},
		{"IPv4", EncodeFromRelay(nil, ip("10.0.0.2"), []byte("hi")), ip("10.0.0.2"), "hi"},
		{"empty packet", EncodeFromRelay(nil, ip("fd00::2"), nil), ip("fd00::2"), ""},
		{"probe frame", append([]byte{TypeProbe}, marker[1:]...), netip.Addr{}, ""},
		{"data frame and no handler", EncodeData(nil, testVNI, []byte("hi")), netip.Addr{}, ""},
		{"short", marker[:FromRelayLen-1], netip.Addr{}, ""},
		{"empty", []byte{}, netip.Addr{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qc := newFakeQC()
			c := New(qc, testSrc)
			defer c.Close()
			require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
			qc.in <- tc.frame
			qc.in <- marker
			buf := make([]byte, 100)
			if tc.src.IsValid() {
				n, addr, err := c.ReadFrom(buf)
				require.NoError(t, err)
				assert.Equal(t, tc.pkt, string(buf[:n]))
				assert.Equal(t, netip.AddrPortFrom(tc.src, 0), addr.(*net.UDPAddr).AddrPort())
			}
			n, addr, err := c.ReadFrom(buf)
			require.NoError(t, err)
			assert.Equal(t, "next", string(buf[:n]))
			assert.Equal(t, udpAddr("fd00::9"), addr)
			want := Stats{}
			if !tc.src.IsValid() {
				want.OtherDrops = 1
			}
			assert.Equal(t, want, c.(*Conn).Stats())
		})
	}
}

// TestHandleData checks that the reader gives data frames to the handler and
// peer frames to ReadFrom.
func TestHandleData(t *testing.T) {
	qc := newFakeQC()
	c := New(qc, testSrc).(*Conn)
	defer c.Close()
	got := make(chan []byte, 4)
	c.HandleData(func(b []byte) { got <- b })
	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	data := EncodeData(nil, testVNI, []byte("data"))
	peer := EncodeFromRelay(nil, netip.MustParseAddr("fd00::2"), []byte("peer"))
	buf := make([]byte, 100)

	qc.in <- data
	qc.in <- peer
	n, _, err := c.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "peer", string(buf[:n]))
	assert.Equal(t, data, <-got)

	c.HandleData(nil)
	qc.in <- data
	qc.in <- peer
	_, _, err = c.ReadFrom(buf)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Equal(t, Stats{OtherDrops: 1}, c.Stats())
}

// TestReadEnds checks that Close and deadlines end a blocked ReadFrom.
func TestReadEnds(t *testing.T) {
	cases := []struct {
		name string
		end  func(c *Conn)
		err  error
	}{
		{"Close", func(c *Conn) { _ = c.Close() }, net.ErrClosed},
		{"read deadline now", func(c *Conn) { _ = c.SetReadDeadline(time.Now()) }, os.ErrDeadlineExceeded},
		{"deadline in the past", func(c *Conn) { _ = c.SetDeadline(time.Now().Add(-time.Hour)) }, os.ErrDeadlineExceeded},
		{"read deadline soon", func(c *Conn) { _ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)) }, os.ErrDeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(newFakeQC(), testSrc).(*Conn)
			defer c.Close()
			errc := make(chan error, 1)
			go func() {
				_, _, err := c.ReadFrom(make([]byte, 10))
				errc <- err
			}()
			tc.end(c)
			select {
			case err := <-errc:
				assert.ErrorIs(t, err, tc.err)
			case <-time.After(5 * time.Second):
				t.Fatal("ReadFrom did not end")
			}
		})
	}
}

// TestDeadlineReset does what quic.Transport.Close does: a past read
// deadline, then no deadline.
func TestDeadlineReset(t *testing.T) {
	qc := newFakeQC()
	c := New(qc, testSrc)
	defer c.Close()
	require.NoError(t, c.SetReadDeadline(time.Now()))
	_, _, err := c.ReadFrom(nil)
	var ne net.Error
	require.ErrorAs(t, err, &ne)
	assert.True(t, ne.Timeout())

	require.NoError(t, c.SetReadDeadline(time.Time{}))
	qc.in <- EncodeFromRelay(nil, netip.MustParseAddr("fd00::2"), []byte("hi"))
	n, _, err := c.ReadFrom(make([]byte, 10))
	require.NoError(t, err)
	assert.Equal(t, 2, n)
}

// TestReadDrops fills the read queue. c counts the packets that do not fit
// and keeps the order of the others.
func TestReadDrops(t *testing.T) {
	qc := newFakeQC()
	c := New(qc, testSrc).(*Conn)
	defer c.Close()
	const extra = 10
	for i := range uint32(queueLen + extra) {
		qc.in <- EncodeFromRelay(nil, netip.MustParseAddr("fd00::2"), binary.BigEndian.AppendUint32(nil, i))
	}
	require.Eventually(t, func() bool { return c.Stats().ReadDrops == extra }, 5*time.Second, time.Millisecond)
	buf := make([]byte, 10)
	for i := range uint32(queueLen) {
		n, _, err := c.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, i, binary.BigEndian.Uint32(buf[:n]))
	}
	assert.Equal(t, Stats{ReadDrops: extra}, c.Stats())
}

func TestSetConn(t *testing.T) {
	q1, q2, q3 := newFakeQC(), newFakeQC(), newFakeQC()
	c := New(q1, testSrc).(*Conn)
	c.SetConn(q2)

	_, err := c.WriteTo([]byte("hi"), udpAddr("fd00::2"))
	require.NoError(t, err)
	assert.Equal(t, EncodeToRelay(nil, netip.MustParseAddr("fd00::2"), testSrc, []byte("hi")), <-q2.sent)
	assert.Empty(t, q1.sent)

	q2.in <- EncodeFromRelay(nil, netip.MustParseAddr("fd00::2"), []byte("hi"))
	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, _, err := c.ReadFrom(make([]byte, 10))
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	require.NoError(t, c.Close())
	assert.ErrorIs(t, c.Close(), net.ErrClosed)
	c.SetConn(q3) // Does nothing after Close.
	assert.Same(t, q2, c.sess.Load().qc)
	_, err = c.WriteTo([]byte("hi"), udpAddr("fd00::2"))
	assert.ErrorIs(t, err, net.ErrClosed)
}

func BenchmarkWriteTo(b *testing.B) {
	qc := newFakeQC()
	qc.sent = nil
	c := New(qc, testSrc)
	defer c.Close()
	pkt, addr := make([]byte, 1200), udpAddr("fd00::2")
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.WriteTo(pkt, addr); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReadFrom moves one packet at a time through the reader.
func BenchmarkReadFrom(b *testing.B) {
	qc := newFakeQC()
	c := New(qc, testSrc)
	defer c.Close()
	frame := EncodeFromRelay(nil, netip.MustParseAddr("fd00::2"), make([]byte, 1200))
	buf := make([]byte, 1500)
	b.SetBytes(1200)
	b.ReportAllocs()
	for b.Loop() {
		qc.in <- frame
		if _, _, err := c.ReadFrom(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHandleData moves one data frame at a time through the reader to a
// handler that checks it.
func BenchmarkHandleData(b *testing.B) {
	qc := newFakeQC()
	c := New(qc, testSrc).(*Conn)
	defer c.Close()
	src := netip.MustParseAddr("10.0.0.2")
	sources := func(a netip.Addr) bool { return a == src }
	got := make(chan error, 1)
	c.HandleData(func(f []byte) {
		_, err := OpenData(f, testVNI, sources)
		got <- err
	})
	frame := EncodeData(nil, testVNI, ipPacket(src, 1280))
	b.SetBytes(1280)
	b.ReportAllocs()
	for b.Loop() {
		qc.in <- frame
		if err := <-got; err != nil {
			b.Fatal(err)
		}
	}
}
