package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewResult(t *testing.T) {
	cases := []struct {
		name     string
		rep      report
		sent     uint64
		sentFor  time.Duration
		size     int
		wantPPS  float64
		wantBPS  float64
		wantLost float64
	}{
		{"no loss", report{2, counters{Packets: 200}}, 200, 2 * time.Second, 1000, 100, 800_000, 0},
		{"half lost", report{1, counters{Packets: 50}}, 100, time.Second, 1000, 50, 400_000, 50},
		{"more received than sent", report{1, counters{Packets: 110}}, 100, time.Second, 10, 110, 8800, 0},
		{"empty report", report{}, 100, time.Second, 10, 0, 0, 100},
		{"nothing sent", report{1, counters{Packets: 5}}, 0, 0, 10, 5, 400, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newResult(tc.rep, tc.sent, tc.sentFor, tc.size)
			if r.PacketsPerSecond != tc.wantPPS || r.BitsPerSecond != tc.wantBPS || math.Abs(r.LostPercent-tc.wantLost) > 1e-9 {
				t.Fatalf("got pps=%v bps=%v lost=%v, want pps=%v bps=%v lost=%v",
					r.PacketsPerSecond, r.BitsPerSecond, r.LostPercent, tc.wantPPS, tc.wantBPS, tc.wantLost)
			}
			if r.Seconds != tc.rep.Seconds || r.Size != tc.size {
				t.Fatalf("got seconds=%v size=%d", r.Seconds, r.Size)
			}
		})
	}
}

func TestSNMPValue(t *testing.T) {
	const snmp = `Ip: Forwarding DefaultTTL
Ip: 1 64
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
Udp: 100 2 3 50 42 0
UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
UdpLite: 0 0 0 0 7 0
`
	cases := []struct {
		name   string
		data   string
		proto  string
		field  string
		want   uint64
		wantOK bool
	}{
		{"udp rcvbuf errors", snmp, "Udp", "RcvbufErrors", 42, true},
		{"udp in datagrams", snmp, "Udp", "InDatagrams", 100, true},
		{"udplite is another proto", snmp, "UdpLite", "RcvbufErrors", 7, true},
		{"unknown field", snmp, "Udp", "Nope", 0, false},
		{"unknown proto", snmp, "Tcp", "InSegs", 0, false},
		{"no values line", "Udp: InDatagrams RcvbufErrors\n", "Udp", "RcvbufErrors", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := snmpValue(tc.data, tc.proto, tc.field)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("snmpValue() = %d, %v, want %d, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestServeControl(t *testing.T) {
	cases := []struct {
		name       string
		cmds       []string
		wantReport bool
		wantErr    bool
	}{
		{"start and stop", []string{"start", "stop"}, true, false},
		{"stop before start", []string{"stop"}, false, true},
		{"unknown command", []string{"go"}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			// Each snapshot is 7 packets and 1 drop more than the last.
			var n atomic.Uint64
			snap := func() counters {
				k := n.Add(1)
				return counters{Packets: 7 * k, QUICDrops: k, KernelDrops: 2 * k}
			}
			errc := make(chan error, 1)
			go func() { errc <- serveControl(context.Background(), ln, snap) }()

			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			for _, cmd := range tc.cmds {
				fmt.Fprintln(c, cmd)
			}
			if tc.wantReport {
				var rep report
				if err := json.NewDecoder(bufio.NewReader(c)).Decode(&rep); err != nil {
					t.Fatal(err)
				}
				if want := (counters{Packets: 7, QUICDrops: 1, KernelDrops: 2}); rep.counters != want || rep.Seconds <= 0 {
					t.Fatalf("got report %+v, want %+v", rep, want)
				}
			}
			c.Close()
			if err := <-errc; (err != nil) != tc.wantErr {
				t.Fatalf("serveControl() error = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

func TestQUICPaths(t *testing.T) {
	cases := []struct {
		path string
		gso  bool
	}{
		{pathRaw, true},
		{pathRaw, false},
		{pathWrapped, true},
		{pathOOB, true},
		{pathOOB, false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s gso=%v", tc.path, tc.gso), func(t *testing.T) {
			if !tc.gso {
				t.Setenv("QUIC_GO_DISABLE_GSO", "true")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			suc, err := listenUDP("127.0.0.1:0", 0)
			if err != nil {
				t.Fatal(err)
			}
			var drops atomic.Uint64
			ln, closeLn, err := listenQUIC(tc.path, suc, &drops)
			if err != nil {
				t.Fatal(err)
			}
			defer closeLn()
			var received atomic.Uint64
			go acceptDatagrams(ctx, ln, &received)

			cuc, err := listenUDP("127.0.0.1:0", 0)
			if err != nil {
				t.Fatal(err)
			}
			conns, closeConns, err := dialQUIC(ctx, tc.path, cuc, suc.LocalAddr().(*net.UDPAddr), 2)
			if err != nil {
				t.Fatal(err)
			}
			defer closeConns()

			// quic-go turns on GSO only for an OOB-capable conn on Linux.
			wantGSO := tc.gso && tc.path != pathWrapped && runtime.GOOS == "linux"
			if got := conns[0].ConnectionState().GSO; got != wantGSO {
				t.Fatalf("GSO = %v, want %v", got, wantGSO)
			}
			p := make([]byte, 1285)
			waitFor(t, func() bool {
				for _, c := range conns {
					if err := c.SendDatagram(p); err != nil {
						t.Fatal(err)
					}
				}
				return received.Load() >= 20
			})
		})
	}
}

func TestBlastUDP(t *testing.T) {
	for _, gso := range []bool{false, true} {
		t.Run(fmt.Sprintf("gso=%v", gso), func(t *testing.T) {
			if gso && runtime.GOOS != "linux" {
				t.Skip("UDP GSO needs Linux")
			}
			dst := mustListen(t)
			var received, sent atomic.Uint64
			go func() { _ = receiveUDP(dst, &received) }()

			ctx, cancel := context.WithCancel(context.Background())
			errc := make(chan error, 1)
			go func() { errc <- blastUDP(ctx, mustListen(t), dst.LocalAddr().(*net.UDPAddr), 1285, gso, &sent) }()
			waitFor(t, func() bool { return received.Load() >= 100 })
			cancel()
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
			if sent.Load() < received.Load() {
				t.Fatalf("sent %d packets, but received %d", sent.Load(), received.Load())
			}
		})
	}
}
