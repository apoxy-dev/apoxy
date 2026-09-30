package main

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

func TestIsGeneve(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want bool
	}{
		{"geneve ipv4", []byte{0, 0, 0x08, 0x00, 0, 0, 1, 0}, true},
		{"geneve ipv6", []byte{0, 0, 0x86, 0xdd, 0, 0, 1, 0}, true},
		{"geneve management", []byte{0, 0, 0, 0, 0, 0, 1, 0}, true},
		{"short", []byte{0, 0, 0x08, 0x00}, false},
		{"version 1", []byte{0x40, 0, 0x08, 0x00, 0, 0, 1, 0}, false},
		{"other protocol", []byte{0, 0, 0x65, 0x58, 0, 0, 1, 0}, false},
		{"quic short header", []byte{0x40, 0, 0x08, 0x00, 1, 2, 3, 4}, false},
		{"quic long header", []byte{0xc0, 0, 0, 0, 1, 0, 0, 0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isGeneve(tc.b); got != tc.want {
				t.Fatalf("isGeneve(%x) = %v, want %v", tc.b, got, tc.want)
			}
		})
	}
}

func TestAddrKey(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4", "10.0.0.1:443", "10.0.0.1:443"},
		{"ipv4-mapped", "[::ffff:10.0.0.1]:443", "10.0.0.1:443"},
		{"ipv6", "[2001:db8::1]:443", "[2001:db8::1]:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := addrKey(netip.MustParseAddrPort(tc.in)).String(); got != tc.want {
				t.Fatalf("addrKey(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestDemuxRoute(t *testing.T) {
	quicPkt := []byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8}
	genevePkt := []byte{0, 0, 0x08, 0x00, 0, 0, 1, 0, 0x45}
	cases := []struct {
		name     string
		payload  []byte
		fromOpen bool // Send from the remote that has a flow.
		withAny  bool
		want     string // "open", "any", "geneve" or "drop".
	}{
		{"quic from open remote", quicPkt, true, false, "open"},
		{"quic from open remote with any", quicPkt, true, true, "open"},
		{"quic from other remote", quicPkt, false, false, "drop"},
		{"quic from other remote with any", quicPkt, false, true, "any"},
		{"geneve", genevePkt, true, true, "geneve"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDemux(mustListen(t))
			t.Cleanup(func() { d.Close() })
			open, other := mustListen(t), mustListen(t)
			flows := map[string]*flow{
				"open":   d.Open(open.LocalAddr().(*net.UDPAddr).AddrPort()),
				"geneve": d.Geneve(),
			}
			if tc.withAny {
				flows["any"] = d.Any()
			}
			from := other
			if tc.fromOpen {
				from = open
			}
			if _, err := from.WriteTo(tc.payload, d.uc.LocalAddr()); err != nil {
				t.Fatal(err)
			}

			if tc.want == "drop" {
				waitFor(t, func() bool { return d.drops.Load() == 1 })
				return
			}
			f := flows[tc.want]
			_ = f.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 64)
			n, addr, err := f.ReadFrom(buf)
			if err != nil {
				t.Fatalf("read from %s flow: %v", tc.want, err)
			}
			if !bytes.Equal(buf[:n], tc.payload) {
				t.Fatalf("got %x, want %x", buf[:n], tc.payload)
			}
			if got, want := addrKey(addr.(*net.UDPAddr).AddrPort()), addrKey(from.LocalAddr().(*net.UDPAddr).AddrPort()); got != want {
				t.Fatalf("got address %s, want %s", got, want)
			}
		})
	}
}

func TestFlowReadBatch(t *testing.T) {
	f := newFlow(&demux{})
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443}
	var batch []*packet
	for i := range 3 {
		p := packetPool.Get().(*packet)
		p.n = copy(p.buf, []byte{byte(i), 0xaa})
		p.nn = copy(p.oob, []byte{byte(i)})
		p.addr = addr
		batch = append(batch, p)
	}
	f.ch <- batch

	for _, want := range []int{2, 1} {
		ms := make([]ipv4.Message, 2)
		for i := range ms {
			ms[i].Buffers = [][]byte{make([]byte, 16)}
			ms[i].OOB = make([]byte, 16)
		}
		n, err := f.ReadBatch(ms, 0)
		if err != nil || n != want {
			t.Fatalf("ReadBatch() = %d, %v, want %d, nil", n, err, want)
		}
		for _, m := range ms[:n] {
			if m.N != 2 || m.NN != 1 || m.Buffers[0][1] != 0xaa || m.Buffers[0][0] != m.OOB[0] || m.Addr != addr {
				t.Fatalf("bad message: %+v", m)
			}
		}
	}
}

func TestFlowReadErrors(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(f *flow)
		wantErr error
		minWait time.Duration
	}{
		{"past deadline", func(f *flow) { _ = f.SetReadDeadline(time.Now().Add(-time.Millisecond)) }, os.ErrDeadlineExceeded, 0},
		{"future deadline", func(f *flow) { _ = f.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) }, os.ErrDeadlineExceeded, 50 * time.Millisecond},
		{"closed flow", func(f *flow) { _ = f.Close() }, net.ErrClosed, 0},
		{"closed socket", func(f *flow) { _ = f.d.Close() }, net.ErrClosed, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDemux(mustListen(t))
			t.Cleanup(func() { d.Close() })
			f := d.Open(netip.MustParseAddrPort("127.0.0.1:9"))
			start := time.Now()
			tc.setup(f)
			_, _, err := f.ReadFrom(make([]byte, 16))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ReadFrom() error = %v, want %v", err, tc.wantErr)
			}
			if waited := time.Since(start); waited < tc.minWait {
				t.Fatalf("ReadFrom() returned after %s, want at least %s", waited, tc.minWait)
			}
		})
	}
}

func mustListen(t *testing.T) *net.UDPConn {
	t.Helper()
	uc, err := listenUDP("127.0.0.1:0", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	return uc
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
