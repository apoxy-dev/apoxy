// SPDX-License-Identifier: AGPL-3.0-only

package hostcheck

import (
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// udpBuf is the socket buffer size that the agent asks for.
	udpBuf = 16 << 20

	// One TCP flow must get targetRate at targetRTT.
	targetRate = 2.2e9 // bits per second
	targetRTT  = 0.020 // seconds
	tcpWindow  = int(targetRate * targetRTT / 8)

	// tcpTuned is the TCP buffer max of a tuned host.
	tcpTuned = 64 << 20
)

// Check returns the host settings that limit the tunnel. conn is the UDP socket
// of the agent after it set its buffers. Set tun for the kernel TUN driver.
func Check(conn syscall.Conn, tun bool) []Warning {
	rcv, snd := sockBufs(conn)
	return check(os.DirFS("/proc/sys"), rcv, snd, tun)
}

// check reads the sysctls from sys. rcv and snd are the socket buffer sizes
// that the kernel reports, or 0 when they are not known.
func check(sys fs.FS, rcv, snd int, tun bool) []Warning {
	var ws []Warning
	if w, ok := udpWarning(rcv, snd); ok {
		ws = append(ws, w)
	}
	// In netstack mode, host TCP does not carry tunnel traffic.
	if !tun {
		return ws
	}
	if w, ok := tcpWarning(sys); ok {
		ws = append(ws, w)
	}
	if w, ok := ccWarning(sys); ok {
		ws = append(ws, w)
	}
	return ws
}

// sockBufs returns the socket buffer sizes that the kernel reports, or zeros.
func sockBufs(conn syscall.Conn) (rcv, snd int) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return 0, 0
	}
	var rerr, serr error
	if err := rc.Control(func(fd uintptr) {
		rcv, rerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		snd, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); err != nil || rerr != nil || serr != nil {
		return 0, 0
	}
	return rcv, snd
}

// udpWarning finds the socket buffers that the kernel made smaller than the
// request. The kernel reports twice the size that it allowed.
func udpWarning(rcv, snd int) (Warning, bool) {
	var low, fix []string
	for _, b := range []struct {
		key, dir string
		size     int
	}{
		{"net.core.rmem_max", "receive", rcv / 2},
		{"net.core.wmem_max", "send", snd / 2},
	} {
		if b.size > 0 && b.size < udpBuf {
			low = append(low, fmt.Sprintf("%s limits the tunnel UDP %s buffer to %d B", b.key, b.dir, b.size))
			fix = append(fix, fmt.Sprintf("%s=%d", b.key, udpBuf))
		}
	}
	if len(low) == 0 {
		return Warning{}, false
	}
	return Warning{
		Problem: fmt.Sprintf("%s. The agent asks for %d B. With small buffers, the kernel drops tunnel packets at high rates.",
			strings.Join(low, " and "), udpBuf),
		Fix: "sudo sysctl -w " + strings.Join(fix, " "),
	}, true
}

// tcpWarning finds TCP buffer limits that keep one flow below targetRate.
// The receive window is about half of tcp_rmem.
func tcpWarning(sys fs.FS) (Warning, bool) {
	var low, fix []string
	for _, b := range []struct {
		key string
		div int
	}{
		{"net.ipv4.tcp_rmem", 2},
		{"net.ipv4.tcp_wmem", 1},
	} {
		f, err := sysctl(sys, b.key)
		if err != nil || len(f) != 3 {
			continue
		}
		lim, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		if win := lim / b.div; win < tcpWindow {
			low = append(low, fmt.Sprintf("%s (max %d B) limits one TCP flow to near %.1f Gbps",
				b.key, lim, float64(win)*8/targetRTT/1e9))
		}
		if lim < tcpTuned {
			fix = append(fix, fmt.Sprintf("%s=%q", b.key, f[0]+" "+f[1]+" "+strconv.Itoa(tcpTuned)))
		}
	}
	if len(low) == 0 {
		return Warning{}, false
	}
	return Warning{
		Problem: fmt.Sprintf("At 20 ms RTT, %s.", strings.Join(low, " and ")),
		Fix:     "sudo sysctl -w " + strings.Join(fix, " "),
	}, true
}

// ccWarning finds cubic TCP congestion control.
func ccWarning(sys fs.FS) (Warning, bool) {
	f, err := sysctl(sys, "net.ipv4.tcp_congestion_control")
	if err != nil || len(f) != 1 || f[0] != "cubic" {
		return Warning{}, false
	}
	return Warning{
		Problem: "The host uses cubic TCP congestion control. Cubic fills the tunnel buffers until they drop packets, and this adds delay. bbr sends at the rate of the path.",
		Fix:     "sudo sysctl -w net.core.default_qdisc=fq net.ipv4.tcp_congestion_control=bbr",
	}, true
}

// sysctl returns the fields of a sysctl value.
func sysctl(sys fs.FS, key string) ([]string, error) {
	b, err := fs.ReadFile(sys, strings.ReplaceAll(key, ".", "/"))
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(b)), nil
}
