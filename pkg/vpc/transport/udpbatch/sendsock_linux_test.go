// SPDX-License-Identifier: AGPL-3.0-only

package udpbatch

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// listen opens the two sockets of Listen, and closes them when the test ends.
func listen(t testing.TB, network string, laddr *net.UDPAddr) (*net.UDPConn, *SendSocket) {
	t.Helper()
	uc, s, err := Listen(network, laddr)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.Close()
		_ = uc.Close()
	})
	return uc, s
}

// rawFD returns the descriptor of uc.
func rawFD(t testing.TB, uc *net.UDPConn) int {
	t.Helper()
	rc, err := uc.SyscallConn()
	require.NoError(t, err)
	var fd int
	require.NoError(t, rc.Control(func(f uintptr) { fd = int(f) }))
	return fd
}

// drain reads the datagrams in the receive queue of fd and returns their count.
func drain(fd int) int {
	var buf [64]byte
	for n := 0; ; n++ {
		if _, _, err := unix.Recvfrom(fd, buf[:], unix.MSG_DONTWAIT); err != nil {
			return n
		}
	}
}

// sockopt returns the value of an option of fd, or -1 when fd does not have it.
func sockopt(fd, level, name int) int {
	v, err := unix.GetsockoptInt(fd, level, name)
	if err != nil {
		return -1
	}
	return v
}

// TestListen sends datagrams from many addresses and ports to the address of
// Listen. The read socket must get each one, and the send socket none.
func TestListen(t *testing.T) {
	const (
		sources = 36
		rounds  = 336 // 12 096 datagrams.
	)
	var v4 []netip.Addr
	for i := range 8 {
		v4 = append(v4, netip.AddrFrom4([4]byte{127, 0, 0, byte(1 + i)}))
	}
	v6 := []netip.Addr{netip.IPv6Loopback()}
	cases := []struct {
		name    string
		network string
		laddr   *net.UDPAddr
		srcs    []netip.Addr
	}{
		{"IPv4 address", "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, v4},
		{"IPv4 wildcard", "udp4", &net.UDPAddr{IP: net.IPv4zero}, v4},
		{"IPv6 address", "udp", &net.UDPAddr{IP: net.IPv6loopback}, v6},
		{"IPv6 wildcard with no IPv4", "udp6", &net.UDPAddr{IP: net.IPv6unspecified}, v6},
		{"IPv6 wildcard with IPv4", "udp", &net.UDPAddr{IP: net.IPv6unspecified}, slices.Concat(v4, v6)},
		{"no address", "udp", nil, slices.Concat(v4, v6)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uc, s := listen(t, tc.network, tc.laddr)
			port := uc.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			rfd := rawFD(t, uc)
			want, err := unix.Getsockname(rfd)
			require.NoError(t, err)
			got, err := unix.Getsockname(s.fd)
			require.NoError(t, err)
			require.Equal(t, want, got, "the send socket has the address and the port of the read socket")
			for _, fd := range []int{rfd, s.fd} {
				_, err := unix.Getpeername(fd)
				require.ErrorIs(t, err, unix.ENOTCONN, "no socket of the group is connected")
			}

			// Each source is a socket with its own port. The addresses repeat.
			srcs := make([]*net.UDPConn, sources)
			dsts := make([]*net.UDPAddr, sources)
			index := map[netip.AddrPort]int{}
			for i := range srcs {
				a := tc.srcs[i%len(tc.srcs)]
				src, err := net.ListenUDP("udp", &net.UDPAddr{IP: a.AsSlice()})
				require.NoError(t, err)
				defer src.Close()
				srcs[i], index[netip.AddrPortFrom(a, src.LocalAddr().(*net.UDPAddr).AddrPort().Port())] = src, i
				// A wildcard socket gets the datagrams to the loopback address.
				to := netip.IPv6Loopback()
				if a.Is4() {
					to = netip.AddrFrom4([4]byte{127, 0, 0, 1})
				}
				dsts[i] = net.UDPAddrFromAddrPort(netip.AddrPortFrom(to, port))
			}

			buf := make([]byte, 64)
			round := func(r int) {
				for i, src := range srcs {
					// An empty datagram must go to the read socket too.
					var p []byte
					if i%6 != 0 {
						p = binary.BigEndian.AppendUint32(nil, uint32(r*sources+i))
					}
					_, err := src.WriteToUDP(p, dsts[i])
					require.NoError(t, err)
				}
				var seen [sources]bool
				require.NoError(t, uc.SetReadDeadline(time.Now().Add(5*time.Second)))
				for range srcs {
					n, from, err := uc.ReadFromUDPAddrPort(buf)
					require.NoError(t, err, "round %d", r)
					i, ok := index[netip.AddrPortFrom(from.Addr().Unmap(), from.Port())]
					require.True(t, ok, "datagram from %v", from)
					require.False(t, seen[i], "round %d: two datagrams from source %d", r, i)
					seen[i] = true
					if n > 0 {
						require.Equal(t, uint32(r*sources+i), binary.BigEndian.Uint32(buf[:n]))
					}
				}
			}
			for r := range rounds / 3 {
				round(r)
			}
			require.Zero(t, drain(s.fd), "datagrams on the send socket")

			// A packet from the send socket has the port of the read socket.
			bt := NewSend(s, 8)
			bt.Add([]byte{1, 2, 3}, srcs[0].LocalAddr().(*net.UDPAddr).AddrPort())
			sent, dropped, err := bt.Flush()
			require.NoError(t, err)
			require.Equal(t, [2]int{1, 0}, [2]int{sent, dropped}, "sent and dropped")
			require.NoError(t, srcs[0].SetReadDeadline(time.Now().Add(5*time.Second)))
			n, from, err := srcs[0].ReadFromUDPAddrPort(buf)
			require.NoError(t, err)
			assert.Equal(t, []byte{1, 2, 3}, buf[:n])
			assert.Equal(t, port, from.Port())
			for r := rounds / 3; r < 2*rounds/3; r++ {
				round(r)
			}
			require.Zero(t, drain(s.fd), "datagrams on the send socket after it sent")

			require.NoError(t, s.Close())
			for r := 2 * rounds / 3; r < rounds; r++ {
				round(r)
			}
		})
	}
}

// TestListenFlood opens the sockets many times on a port that gets datagrams all
// the time. The send socket must get none, also while it binds.
func TestListenFlood(t *testing.T) {
	const opens = 300
	uc, s, err := Listen("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	laddr := uc.LocalAddr().(*net.UDPAddr)
	require.NoError(t, s.Close())
	require.NoError(t, uc.Close())

	stop := make(chan struct{})
	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(stop)
	for i := range 4 {
		src, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, byte(2+i))})
		require.NoError(t, err)
		wg.Go(func() {
			defer src.Close()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = src.WriteToUDP([]byte{1}, laddr)
				}
			}
		})
	}
	buf := make([]byte, 64)
	for i := range opens {
		uc, s, err := Listen("udp4", laddr)
		require.NoError(t, err)
		// The read socket gets datagrams while the two sockets are open.
		require.NoError(t, uc.SetReadDeadline(time.Now().Add(5*time.Second)))
		for range 16 {
			_, err := uc.Read(buf)
			require.NoError(t, err)
		}
		got := drain(s.fd)
		require.NoError(t, s.Close())
		require.NoError(t, uc.Close())
		require.Zero(t, got, "open %d: datagrams on the send socket", i)
	}
}

// TestListenError checks that Listen leaves no socket open when it fails.
func TestListenError(t *testing.T) {
	cases := []struct {
		name  string
		laddr *net.UDPAddr
		// oneFD leaves one free descriptor: the read socket opens, and the send
		// socket does not.
		oneFD bool
	}{
		{name: "address that is not local", laddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)}},
		{name: "no descriptor for the send socket", laddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, oneFD: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := openFDs(t)
			restore := func() {}
			if tc.oneFD {
				restore = limitFDs(t, 1)
			}
			uc, s, err := Listen("udp4", tc.laddr)
			restore()
			require.Error(t, err)
			assert.Nil(t, uc)
			assert.Nil(t, s)
			if tc.oneFD {
				assert.ErrorIs(t, err, unix.EMFILE)
			}
			assert.Equal(t, before, openFDs(t))
		})
	}
}

// openFDs returns the count of open descriptors of the process.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	return len(ents)
}

// limitFDs leaves free descriptors for new files of the process. The returned
// function removes the limit.
func limitFDs(t *testing.T, free int) (restore func()) {
	t.Helper()
	// The net package opens sockets at its first use, to find the IP families.
	c, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	require.NoError(t, c.Close())
	var lim unix.Rlimit
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_NOFILE, &lim))
	low := lim
	low.Cur = min(lim.Cur, 256)
	require.NoError(t, unix.Setrlimit(unix.RLIMIT_NOFILE, &low))
	var held []int
	for {
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			break
		}
		held = append(held, fd)
	}
	var once sync.Once
	restore = func() {
		once.Do(func() {
			for _, fd := range held {
				_ = unix.Close(fd)
			}
			_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &lim)
		})
	}
	t.Cleanup(restore)
	require.Greater(t, len(held), free)
	for _, fd := range held[:free] {
		_ = unix.Close(fd)
	}
	held = held[free:]
	return restore
}

// TestSendSocket sends GSO messages on a send socket. The receiver gets each
// packet alone and in order, from the port of the read socket.
func TestSendSocket(t *testing.T) {
	lo4, lo6 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &net.UDPAddr{IP: net.IPv6loopback}
	cases := []struct {
		name    string
		network string
		laddr   *net.UDPAddr
		dst     *net.UDPAddr
	}{
		{"IPv4", "udp4", lo4, lo4},
		{"IPv6", "udp", lo6, lo6},
		{"IPv6 wildcard to IPv4", "udp", nil, lo4},
		{"IPv6 wildcard to IPv6", "udp", nil, lo6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink, err := net.ListenUDP("udp", tc.dst)
			require.NoError(t, err)
			defer sink.Close()
			uc, s := listen(t, tc.network, tc.laddr)
			bt := NewSend(s, 64)
			require.True(t, bt.gso, "the send socket has UDP_SEGMENT")
			sizes := []int{1200, 1200, 1200, 600, 1200, 900}
			for i, size := range sizes {
				p := make([]byte, size)
				p[0] = byte(i)
				bt.Add(p, sink.LocalAddr().(*net.UDPAddr).AddrPort())
			}
			assert.Equal(t, 2, bt.Messages())
			sent, dropped, err := bt.Flush()
			require.NoError(t, err)
			assert.Equal(t, [2]int{len(sizes), 0}, [2]int{sent, dropped}, "sent and dropped")

			buf := make([]byte, 2048)
			require.NoError(t, sink.SetReadDeadline(time.Now().Add(5*time.Second)))
			for i, size := range sizes {
				n, from, err := sink.ReadFromUDPAddrPort(buf)
				require.NoError(t, err)
				assert.Equal(t, [2]int{size, i}, [2]int{n, int(buf[0])}, "size and number of packet %d", i)
				assert.Equal(t, uc.LocalAddr().(*net.UDPAddr).AddrPort().Port(), from.Port())
				assert.True(t, from.Addr().Unmap().IsLoopback(), "from %v", from)
			}
		})
	}
}

// TestSync checks that the send socket has the send options of the read socket
// after Listen, and gets their new values with Sync.
func TestSync(t *testing.T) {
	opts := []struct {
		name            string
		level, opt, val int
	}{
		{"SO_SNDBUF", unix.SOL_SOCKET, unix.SO_SNDBUF, 32 << 10},
		{"SO_BROADCAST", unix.SOL_SOCKET, unix.SO_BROADCAST, 0},
		{"IP_MTU_DISCOVER", unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE},
		{"IPV6_MTU_DISCOVER", unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE},
		{"UDP_GRO", unix.IPPROTO_UDP, unix.UDP_GRO, 1},
	}
	cases := []struct {
		name    string
		network string
		laddr   *net.UDPAddr
	}{
		{"IPv4", "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}},
		{"IPv6", "udp", &net.UDPAddr{IP: net.IPv6loopback}},
		{"IPv6 wildcard with IPv4", "udp", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uc, s := listen(t, tc.network, tc.laddr)
			rfd := rawFD(t, uc)
			assert.Less(t, sockopt(s.fd, unix.SOL_SOCKET, unix.SO_RCVBUF), 8<<10, "the send socket has a small receive buffer")
			first := make([]int, len(opts))
			for i, o := range opts {
				first[i] = sockopt(s.fd, o.level, o.opt)
				assert.Equal(t, sockopt(rfd, o.level, o.opt), first[i], "%s after Listen", o.name)
			}
			for _, o := range opts {
				// An IPv4 socket does not have the IPv6 option.
				if sockopt(rfd, o.level, o.opt) >= 0 {
					require.NoError(t, unix.SetsockoptInt(rfd, o.level, o.opt, o.val), o.name)
				}
			}
			require.NoError(t, s.Sync())
			for i, o := range opts {
				got := sockopt(s.fd, o.level, o.opt)
				assert.Equal(t, sockopt(rfd, o.level, o.opt), got, "%s after Sync", o.name)
				if got >= 0 {
					assert.NotEqual(t, first[i], got, "%s has a new value", o.name)
				}
			}
			require.NoError(t, s.Close())
			assert.ErrorIs(t, s.Sync(), net.ErrClosed)
			assert.ErrorIs(t, s.Close(), net.ErrClosed)
		})
	}
}

// TestNoPoller checks that no epoll instance of the process has the send socket.
// The epoll instance of the Go poller has the read socket.
func TestNoPoller(t *testing.T) {
	uc, s := listen(t, "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	polled := map[int]bool{}
	ents, err := os.ReadDir("/proc/self/fdinfo")
	require.NoError(t, err)
	for _, e := range ents {
		// The file of an epoll instance has a "tfd:" line for each descriptor in it.
		b, err := os.ReadFile("/proc/self/fdinfo/" + e.Name())
		if err != nil {
			continue
		}
		for line := range strings.Lines(string(b)) {
			if v, ok := strings.CutPrefix(line, "tfd:"); ok {
				fd, err := strconv.Atoi(strings.Fields(v)[0])
				require.NoError(t, err)
				polled[fd] = true
			}
		}
	}
	assert.True(t, polled[rawFD(t, uc)], "the read socket")
	assert.False(t, polled[s.fd], "the send socket")
}

// TestSendAllocs checks that a batch on a send socket allocates nothing.
func TestSendAllocs(t *testing.T) {
	cases := []struct {
		name    string
		network string
		addr    *net.UDPAddr
	}{
		{"IPv4", "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}},
		{"IPv6", "udp", &net.UDPAddr{IP: net.IPv6loopback}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The sink reads nothing, so the kernel drops the packets.
			sink, err := net.ListenUDP(tc.network, tc.addr)
			require.NoError(t, err)
			defer sink.Close()
			dst := sink.LocalAddr().(*net.UDPAddr).AddrPort()
			_, s := listen(t, tc.network, tc.addr)
			bt := NewSend(s, 64)
			pkt, short := make([]byte, 1200), make([]byte, 600)
			var total int
			allocs := testing.AllocsPerRun(100, func() {
				for range 31 {
					bt.Add(pkt, dst)
				}
				bt.Add(short, dst)
				bt.Add(pkt, dst)
				sent, _, _ := bt.Flush()
				total += sent
			})
			assert.Zero(t, allocs)
			assert.Equal(t, 101*33, total)
		})
	}
}

// TestZoneIndex checks the interface index that a send to an IPv6 zone gets.
func TestZoneIndex(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	require.NoError(t, err)
	cases := []struct {
		zone string
		want uint32
	}{
		{"", 0},
		{"lo", uint32(lo.Index)},
		{"7", 7},
		{"no-such-link", 0},
		{"lo", uint32(lo.Index)},
	}
	w := &sendWriter{}
	for _, tc := range cases {
		assert.Equal(t, tc.want, w.zoneIndex(tc.zone), "zone %q", tc.zone)
	}
}

// blockNS is a netns with a veth link that has 10.99.0.1/24. No host has
// 10.99.0.2, so the packets to it stay in the send buffer of their socket.
type blockNS struct{ work chan func() }

func newBlockNS(t *testing.T) *blockNS {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ns := &blockNS{work: make(chan func())}
	errc := make(chan error, 1)
	go func() {
		// The thread stays in the new netns, so it must exit with the goroutine.
		runtime.LockOSThread()
		err := setupBlockLink()
		errc <- err
		if err != nil {
			return
		}
		for fn := range ns.work {
			fn()
		}
	}()
	if err := <-errc; err != nil {
		t.Skipf("cannot set up the test netns: %v", err)
	}
	t.Cleanup(func() { close(ns.work) })
	return ns
}

func setupBlockLink() error {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return err
	}
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "bl0"}, PeerName: "bl1"}); err != nil {
		return err
	}
	var link netlink.Link
	for _, name := range []string{"bl1", "bl0"} {
		var err error
		if link, err = netlink.LinkByName(name); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
	}
	a, _ := netlink.ParseAddr("10.99.0.1/24")
	if err := netlink.AddrAdd(link, a); err != nil {
		return err
	}
	// The kernel keeps the packets while it asks for the address of 10.99.0.2.
	return os.WriteFile("/proc/sys/net/ipv4/neigh/bl0/mcast_solicit", []byte("1000"), 0o644)
}

// do runs fn on the thread of ns.
func (ns *blockNS) do(fn func()) {
	done := make(chan struct{})
	ns.work <- func() {
		defer close(done)
		fn()
	}
	<-done
}

// stalls waits until count does not change for 100 ms.
func stalls(t *testing.T, count *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for last := int64(-1); ; {
		n := count.Load()
		if n == last {
			return
		}
		require.True(t, time.Now().Before(deadline), "the count changes")
		last = n
		time.Sleep(100 * time.Millisecond)
	}
}

// listenBlocked opens the two sockets of Listen in a new netns, with the smallest
// send buffer. It returns the send socket and an address that keeps its packets.
func listenBlocked(t *testing.T) (*SendSocket, netip.AddrPort) {
	t.Helper()
	var uc *net.UDPConn
	var s *SendSocket
	var err error
	ns := newBlockNS(t)
	ns.do(func() { uc, s, err = Listen("udp4", &net.UDPAddr{IP: net.IPv4(10, 99, 0, 1)}) })
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.Close()
		_ = uc.Close()
	})
	// The smallest send buffer has space for one message.
	require.NoError(t, uc.SetWriteBuffer(1))
	require.NoError(t, s.Sync())
	return s, netip.MustParseAddrPort("10.99.0.2:9")
}

// startSender sends messages of 16 packets on s to dst until a send fails. It
// returns the count of the sends, and a channel that gets the error.
func startSender(s *SendSocket, dst netip.AddrPort) (*atomic.Int64, <-chan error) {
	bt := NewSend(s, 64)
	flushes := &atomic.Int64{}
	stopped := make(chan error, 1)
	go func() {
		pkt := make([]byte, 1200)
		for {
			for range 16 {
				bt.Add(pkt, dst)
			}
			if _, _, err := bt.Flush(); err != nil {
				stopped <- err
				return
			}
			flushes.Add(1)
		}
	}()
	return flushes, stopped
}

// wmem returns the send memory of fd as SO_MEMINFO gives it.
func wmem(t *testing.T, fd int) int {
	t.Helper()
	var mi [unix.SK_MEMINFO_VARS]uint32
	n := uint32(unsafe.Sizeof(mi))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_MEMINFO,
		uintptr(unsafe.Pointer(&mi[0])), uintptr(unsafe.Pointer(&n)), 0)
	require.Zero(t, errno)
	return int(mi[unix.SK_MEMINFO_WMEM_ALLOC])
}

// TestQueued checks the bytes that a send socket reports for its send path. They
// are the send memory of the socket, and 0 after Close.
func TestQueued(t *testing.T) {
	cases := []struct {
		name string
		// waits is true when a sender waits in the kernel for send buffer space.
		waits bool
	}{
		{"socket that sent nothing", false},
		{"socket with a sender that waits for send buffer space", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s *SendSocket
			if tc.waits {
				var dst netip.AddrPort
				s, dst = listenBlocked(t)
				flushes, _ := startSender(s, dst)
				stalls(t, flushes)
			} else {
				_, s = listen(t, "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			}
			q := s.Queued()
			assert.Equal(t, wmem(t, s.fd), q, "the send memory of the socket")
			if tc.waits {
				// A sender waits only when the send memory is the send buffer size or more.
				assert.GreaterOrEqual(t, q, sockopt(s.fd, unix.SOL_SOCKET, unix.SO_SNDBUF))
			} else {
				assert.Zero(t, q)
			}
			require.NoError(t, s.Close())
			assert.Zero(t, s.Queued(), "after Close")
		})
	}
}

// TestCloseSender closes a send socket while a goroutine sends on it. Close must
// return at once, and the sender must stop with net.ErrClosed.
func TestCloseSender(t *testing.T) {
	cases := []struct {
		name string
		// waits is true when the sender waits in the kernel for send buffer space.
		waits bool
	}{
		{"sender that waits for send buffer space", true},
		{"sender that sends", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s *SendSocket
			var dst netip.AddrPort
			if tc.waits {
				s, dst = listenBlocked(t)
			} else {
				_, s = listen(t, "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				dst = listenLoopback(t).LocalAddr().(*net.UDPAddr).AddrPort()
			}
			flushes, stopped := startSender(s, dst)
			if tc.waits {
				stalls(t, flushes)
			} else {
				require.Eventually(t, func() bool { return flushes.Load() > 100 }, 5*time.Second, time.Millisecond)
			}
			select {
			case err := <-stopped:
				t.Fatalf("The sender stopped before the close: %v", err)
			default:
			}

			start := time.Now()
			closed := make(chan error, 1)
			go func() { closed <- s.Close() }()
			select {
			case err := <-closed:
				require.NoError(t, err)
				assert.Less(t, time.Since(start), time.Second, "the time of Close")
			case <-time.After(5 * time.Second):
				t.Fatal("Close waits for the sender.")
			}
			select {
			case err := <-stopped:
				assert.ErrorIs(t, err, net.ErrClosed)
			case <-time.After(5 * time.Second):
				t.Fatal("The sender did not stop after the close.")
			}
		})
	}
}

// BenchmarkSend sends packets from some sockets at the same time, each on its
// own goroutine. The batches use no GSO, so the kernel frees each packet alone,
// and calls the Go poller for each packet of a socket that the poller has.
func BenchmarkSend(b *testing.B) {
	kinds := []struct {
		name string
		open func(b *testing.B) *Batch
	}{
		{"socket of the Go poller", func(b *testing.B) *Batch { return New(listenLoopback(b), 64) }},
		{"send socket", func(b *testing.B) *Batch {
			_, s := listen(b, "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			return NewSend(s, 64)
		}},
	}
	for _, sockets := range []int{1, 4, 15} {
		for _, k := range kinds {
			b.Run(fmt.Sprintf("%d sockets/%s", sockets, k.name), func(b *testing.B) {
				dst := listenLoopback(b).LocalAddr().(*net.UDPAddr).AddrPort()
				bts := make([]*Batch, sockets)
				for i := range bts {
					bts[i] = k.open(b)
					bts[i].gso = false
				}
				pkt := make([]byte, 1200)
				var wg sync.WaitGroup
				b.ResetTimer()
				// One operation is one packet.
				for _, bt := range bts {
					wg.Go(func() {
						for left := b.N / sockets; left > 0; left -= 64 {
							for range min(left, 64) {
								bt.Add(pkt, dst)
							}
							_, _, _ = bt.Flush()
						}
					})
				}
				wg.Wait()
			})
		}
	}
}
