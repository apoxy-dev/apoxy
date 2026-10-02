// SPDX-License-Identifier: AGPL-3.0-only

package hostcheck

import (
	"net"
	"slices"
	"testing"
	"testing/fstest"
)

// host returns the sysctl files of a host. An empty value has no file.
func host(rmem, wmem, cc string) fstest.MapFS {
	files := fstest.MapFS{}
	for path, v := range map[string]string{
		"net/ipv4/tcp_rmem":               rmem,
		"net/ipv4/tcp_wmem":               wmem,
		"net/ipv4/tcp_congestion_control": cc,
	} {
		if v != "" {
			files[path] = &fstest.MapFile{Data: []byte(v + "\n")}
		}
	}
	return files
}

func TestCheck(t *testing.T) {
	const (
		// Socket buffer sizes that the kernel reports.
		dflt = 2 * 212992
		full = 2 * udpBuf
	)
	var (
		stock = host("4096\t131072\t6291456", "4096\t16384\t4194304", "cubic")
		tuned = host("4096\t131072\t67108864", "4096\t16384\t67108864", "bbr")

		udpDefault = Warning{
			Problem: "net.core.rmem_max limits the tunnel UDP receive buffer to 212992 B and net.core.wmem_max limits the tunnel UDP send buffer to 212992 B. The agent asks for 16777216 B. With small buffers, the kernel drops tunnel packets at high rates.",
			Fix:     "sudo sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216",
		}
		tcpStock = Warning{
			Problem: "At 20 ms RTT, net.ipv4.tcp_rmem (max 6291456 B) limits one TCP flow to near 1.3 Gbps and net.ipv4.tcp_wmem (max 4194304 B) limits one TCP flow to near 1.7 Gbps.",
			Fix:     `sudo sysctl -w net.ipv4.tcp_rmem="4096 131072 67108864" net.ipv4.tcp_wmem="4096 16384 67108864"`,
		}
		cubic = Warning{
			Problem: "The host uses cubic TCP congestion control. Cubic fills the tunnel buffers until they drop packets, and this adds delay. bbr sends at the rate of the path.",
			Fix:     "sudo sysctl -w net.core.default_qdisc=fq net.ipv4.tcp_congestion_control=bbr",
		}
	)
	cases := []struct {
		name     string
		sys      fstest.MapFS
		rcv, snd int
		tun      bool
		want     []Warning
	}{
		{name: "tuned host", sys: tuned, rcv: full, snd: full, tun: true},
		{name: "stock host, tun", sys: stock, rcv: dflt, snd: dflt, tun: true, want: []Warning{udpDefault, tcpStock, cubic}},
		{name: "stock host, netstack", sys: stock, rcv: dflt, snd: dflt, want: []Warning{udpDefault}},
		{name: "forced socket buffers", sys: stock, rcv: full, snd: full},
		{name: "socket buffers not known", sys: tuned, tun: true},
		{name: "receive buffer only", sys: tuned, rcv: dflt, snd: full, tun: true, want: []Warning{{
			Problem: "net.core.rmem_max limits the tunnel UDP receive buffer to 212992 B. The agent asks for 16777216 B. With small buffers, the kernel drops tunnel packets at high rates.",
			Fix:     "sudo sysctl -w net.core.rmem_max=16777216",
		}}},
		{name: "8 MiB limit", sys: tuned, rcv: 2 * 8388608, snd: 2 * 8388608, tun: true, want: []Warning{{
			Problem: "net.core.rmem_max limits the tunnel UDP receive buffer to 8388608 B and net.core.wmem_max limits the tunnel UDP send buffer to 8388608 B. The agent asks for 16777216 B. With small buffers, the kernel drops tunnel packets at high rates.",
			Fix:     "sudo sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216",
		}}},
		{name: "send buffer max only", sys: host("4096 131072 67108864", "4096 16384 4194304", "bbr"), rcv: full, snd: full, tun: true, want: []Warning{{
			Problem: "At 20 ms RTT, net.ipv4.tcp_wmem (max 4194304 B) limits one TCP flow to near 1.7 Gbps.",
			Fix:     `sudo sysctl -w net.ipv4.tcp_wmem="4096 16384 67108864"`,
		}}},
		{name: "TCP max at the target", sys: host("4096 131072 11000000", "4096 16384 5500000", "bbr"), rcv: full, snd: full, tun: true},
		{name: "TCP max below the target", sys: host("4096 131072 10999998", "4096 16384 5500000", "bbr"), rcv: full, snd: full, tun: true, want: []Warning{{
			Problem: "At 20 ms RTT, net.ipv4.tcp_rmem (max 10999998 B) limits one TCP flow to near 2.2 Gbps.",
			Fix:     `sudo sysctl -w net.ipv4.tcp_rmem="4096 131072 67108864" net.ipv4.tcp_wmem="4096 16384 67108864"`,
		}}},
		{name: "no sysctl files", sys: host("", "", ""), rcv: dflt, snd: dflt, tun: true, want: []Warning{udpDefault}},
		{name: "bad TCP values", sys: host("4096 131072", "4096 16384 lots", "cubic"), rcv: full, snd: full, tun: true, want: []Warning{cubic}},
		{name: "other congestion control", sys: host("4096 131072 67108864", "4096 16384 67108864", "reno"), rcv: full, snd: full, tun: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := check(tc.sys, tc.rcv, tc.snd, tc.tun)
			if !slices.Equal(got, tc.want) {
				t.Errorf("check() =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}

func TestSockBufs(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetReadBuffer(64 << 10); err != nil {
		t.Fatal(err)
	}
	if err := c.SetWriteBuffer(32 << 10); err != nil {
		t.Fatal(err)
	}
	// The kernel reports twice the size that the socket asks for.
	if rcv, snd := sockBufs(c); rcv != 128<<10 || snd != 64<<10 {
		t.Errorf("sockBufs() = %d, %d, want %d, %d", rcv, snd, 128<<10, 64<<10)
	}
}
