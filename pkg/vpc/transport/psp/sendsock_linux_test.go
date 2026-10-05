// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"context"
	"encoding/binary"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// noSendSocket is the warning of a lane that sends on its read socket.
const noSendSocket = "Failed to open a send socket for a lane, so the lane sends on its read socket"

// TestLaneSend sends 64 flows on 3 lanes. A lane sends on its send socket, from
// the port and with the options of its lane socket. A lane with no send socket
// sends on its lane socket, and the binding logs one warning.
func TestLaneSend(t *testing.T) {
	const (
		lanes = 3
		flows = 64
	)
	cases := []struct {
		name string
		// noFD leaves no descriptor for the send socket of a lane.
		noFD bool
	}{
		{name: "send sockets"},
		{name: "no descriptor for a send socket", noFD: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPairLanes(t, 0, lanes)
			logs := warnings(t)
			if tc.noFD {
				// A lane gets one free descriptor. Its two sockets do not open, and then
				// its lane socket opens alone.
				lim := limitFDs(t)
				lim.free(1)
				require.Len(t, a.b.OpenLanes(2), 1)
				lim.free(1)
				require.Len(t, a.b.OpenLanes(3), 2)
				lim.end()
			}
			offer(t, time.Now(), a, b)
			require.NoError(t, a.b.ReadLanes())
			require.Len(t, a.b.LaneConns(), lanes-1)
			laneOf := map[uint16]int{addrOf(a.tr).Port(): 0}
			for i := 1; i < lanes; i++ {
				c := a.b.laneConn(byte(i))
				laneOf[c.LocalAddr().(*net.UDPAddr).AddrPort().Port()] = i
				rfd, sfd := rawFD(t, c), sendFD(t, c)
				if tc.noFD {
					require.Nil(t, a.b.laneSends[i].Load(), "lane %d", i)
					require.Equal(t, -1, sfd, "lane %d has one socket", i)
					continue
				}
				require.NotNil(t, a.b.laneSends[i].Load(), "lane %d", i)
				require.GreaterOrEqual(t, sfd, 0, "lane %d has a second socket on its port", i)
				// The read loop of the lane set the path MTU discovery mode.
				assert.Equal(t, unix.IP_PMTUDISC_PROBE, sockopt(rfd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER))
				for _, o := range [][2]int{
					{unix.SOL_SOCKET, unix.SO_SNDBUF}, {unix.IPPROTO_IP, unix.IP_MTU_DISCOVER}, {unix.IPPROTO_UDP, unix.UDP_GRO},
				} {
					assert.Equal(t, sockopt(rfd, o[0], o[1]), sockopt(sfd, o[0], o[1]), "lane %d, option %v", i, o)
				}
				// A send on the lane socket fails now, so the frames must go on the send socket.
				assert.ErrorIs(t, unix.Shutdown(rfd, unix.SHUT_WR), unix.ENOTCONN)
			}

			sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer sink.Close()
			_ = sink.SetReadBuffer(1 << 20)
			a.peer.SetAddr(sink.LocalAddr().(*net.UDPAddr).AddrPort())
			d := newDriver(a.b, nil)
			frames := make([][]byte, flows)
			for i := range frames {
				frames[i] = seal(a, packet(a.v4, b.v4, 17, uint16(1000+i), 9, 200))
			}
			n, err := d.WriteFrames(frames)
			require.NoError(t, err)
			require.Equal(t, flows, n)

			got := make([]uint64, lanes)
			buf := make([]byte, 2048)
			require.NoError(t, sink.SetReadDeadline(time.Now().Add(5*time.Second)))
			for range flows {
				_, from, err := sink.ReadFromUDPAddrPort(buf)
				require.NoError(t, err)
				lane, ok := laneOf[from.Port()]
				require.True(t, ok, "port %d", from.Port())
				got[lane]++
			}
			assert.Equal(t, got, lanePacketsAt(t, a.b, flows))
			assert.NotContains(t, got, uint64(0), "each lane sends")
			assert.Zero(t, a.b.Stats().TxDrops)
			exits(t, d)

			want := 0
			if tc.noFD {
				want = 1
			}
			assert.Equal(t, want, logs.count(noSendSocket))
		})
	}
}

// rawFD returns the descriptor of c.
func rawFD(t *testing.T, c *net.UDPConn) int {
	t.Helper()
	rc, err := c.SyscallConn()
	require.NoError(t, err)
	var fd int
	require.NoError(t, rc.Control(func(f uintptr) { fd = int(f) }))
	return fd
}

// sendFD returns the descriptor of the send socket of the lane socket c: the
// other UDP socket of the process on the port of c. It returns -1 for none.
func sendFD(t *testing.T, c *net.UDPConn) int {
	t.Helper()
	own, port := rawFD(t, c), c.LocalAddr().(*net.UDPAddr).Port
	ents, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	for _, e := range ents {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd == own || sockopt(fd, unix.SOL_SOCKET, unix.SO_TYPE) != unix.SOCK_DGRAM {
			continue
		}
		if sa, _ := unix.Getsockname(fd); sa != nil {
			if in, ok := sa.(*unix.SockaddrInet4); ok && in.Port == port {
				return fd
			}
		}
	}
	return -1
}

// sockopt returns the value of an option of fd, or -1 when fd does not have it.
func sockopt(fd, level, name int) int {
	v, err := unix.GetsockoptInt(fd, level, name)
	if err != nil {
		return -1
	}
	return v
}

// warnLog keeps the messages of the warnings that the process logs.
type warnLog struct {
	mu   sync.Mutex
	msgs []string
}

// warnings sends the log of the process to a warnLog until the test ends.
func warnings(t *testing.T) *warnLog {
	w := &warnLog{}
	// SetDefault changes the output of the log package too.
	old, out, flags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(w))
	t.Cleanup(func() {
		slog.SetDefault(old)
		log.SetOutput(out)
		log.SetFlags(flags)
	})
	return w
}

func (w *warnLog) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelWarn }

func (w *warnLog) Handle(_ context.Context, r slog.Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msgs = append(w.msgs, r.Message)
	return nil
}

func (w *warnLog) WithAttrs([]slog.Attr) slog.Handler { return w }

func (w *warnLog) WithGroup(string) slog.Handler { return w }

// count returns the number of warnings with the message msg.
func (w *warnLog) count(msg string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, m := range w.msgs {
		if m == msg {
			n++
		}
	}
	return n
}

// fdLimit holds all free descriptors of the process.
type fdLimit struct {
	lim  unix.Rlimit
	held []int
	once sync.Once
}

// limitFDs takes all free descriptors of the process until end, or until the
// test ends.
func limitFDs(t *testing.T) *fdLimit {
	t.Helper()
	l := &fdLimit{}
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_NOFILE, &l.lim))
	low := l.lim
	low.Cur = min(l.lim.Cur, 256)
	require.NoError(t, unix.Setrlimit(unix.RLIMIT_NOFILE, &low))
	t.Cleanup(l.end)
	for {
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			break
		}
		l.held = append(l.held, fd)
	}
	require.Greater(t, len(l.held), 2)
	return l
}

// free gives n descriptors back to the process.
func (l *fdLimit) free(n int) {
	for _, fd := range l.held[:n] {
		_ = unix.Close(fd)
	}
	l.held = l.held[n:]
}

// end removes the limit.
func (l *fdLimit) end() {
	l.once.Do(func() {
		l.free(len(l.held))
		_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &l.lim)
	})
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

// blockedLane opens a binding with lane 1 in a new netns, and sends on the lane
// until its sender waits in the kernel for send buffer space. It returns the
// binding, its driver, and a channel that gets the error that stops the driver.
func blockedLane(t *testing.T) (*Binding, *driver, <-chan error) {
	t.Helper()
	ns := newBlockNS(t)
	dm := &Demux{}
	var uc *net.UDPConn
	var tr *quic.Transport
	var b *Binding
	var ports []uint16
	var err error
	ns.do(func() {
		if uc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 99, 0, 1)}); err != nil {
			return
		}
		tr = &quic.Transport{Conn: uc, NonQUICPacketHandler: dm.Handle, NonQUICBatchEnd: dm.BatchEnd}
		if b, err = New(Config{Transport: tr, Demux: dm, VNI: testVNI}); err == nil {
			ports = b.OpenLanes(2)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = b.Close()
		_ = tr.Close()
		_ = uc.Close()
	})
	require.Len(t, ports, 1)
	s := b.laneSends[1].Load()
	require.NotNil(t, s)
	// The smallest send buffer has space for one message.
	require.NoError(t, b.laneConn(1).SetWriteBuffer(1))
	require.NoError(t, s.Sync())

	// A send frame is the address, the port and the lane, then the packet.
	frame := make([]byte, addrLen+1000)
	dst := netip.MustParseAddr("10.99.0.2").As16()
	copy(frame, dst[:])
	binary.BigEndian.PutUint16(frame[16:], 9)
	frame[laneOff] = 1
	d := newDriver(b, nil)
	_, err = d.WriteFrames([][]byte{frame})
	require.NoError(t, err)
	require.NotNil(t, d.lanes[1], "lane 1 has a sender")

	var calls atomic.Int64
	stopped := make(chan error, 1)
	go func() {
		frames := repeat(frame, laneFrames)
		for {
			if _, err := d.WriteFrames(frames); err != nil {
				stopped <- err
				return
			}
			calls.Add(1)
		}
	}()
	// The driver waits when the queue of the lane is full, and the queue stays
	// full when the sender waits in the kernel.
	deadline := time.Now().Add(10 * time.Second)
	for last := int64(-1); calls.Load() != last; time.Sleep(100 * time.Millisecond) {
		require.True(t, time.Now().Before(deadline), "the driver does not wait")
		last = calls.Load()
	}
	return b, d, stopped
}

// TestLaneSendQueue checks that the send queue of a binding has the bytes of its
// lane send sockets, and that it is 0 after Close.
func TestLaneSendQueue(t *testing.T) {
	cases := []struct {
		name string
		// waits is true when the sender of lane 1 waits for send buffer space.
		waits bool
	}{
		{name: "lanes that sent nothing"},
		{name: "lane with a sender that waits for send buffer space", waits: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b *Binding
			if tc.waits {
				b, _, _ = blockedLane(t)
			} else {
				a, _ := newPairLanes(t, 0, 3)
				b = a.b
				require.Len(t, b.OpenLanes(3), 2)
			}
			s := b.laneSends[1].Load()
			require.NotNil(t, s)
			q := b.LaneSendQueue()
			if tc.waits {
				// A sender waits only when the send memory is the send buffer size or more.
				sfd := sendFD(t, b.laneConn(1))
				assert.GreaterOrEqual(t, q, sockopt(sfd, unix.SOL_SOCKET, unix.SO_SNDBUF))
				assert.Equal(t, s.Queued(), q, "only lane 1 has packets")
			} else {
				assert.Zero(t, q)
			}
			require.NoError(t, b.Close())
			assert.Zero(t, b.LaneSendQueue(), "after Close")
		})
	}
}

// TestCloseBlockedLane closes a binding while the sender of lane 1 waits in the
// kernel for send buffer space. Close must return at once, and the senders stop.
func TestCloseBlockedLane(t *testing.T) {
	b, d, stopped := blockedLane(t)
	senders := []*laneSender{d.lanes[0], d.lanes[1]}
	select {
	case <-senders[1].exited:
		t.Fatal("The sender of lane 1 stopped before the close.")
	default:
	}

	start := time.Now()
	closed := make(chan error, 1)
	go func() { closed <- b.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
		assert.Less(t, time.Since(start), time.Second, "the time of Close")
	case <-time.After(5 * time.Second):
		t.Fatal("Close waits for the sender of lane 1.")
	}
	for i, l := range senders {
		select {
		case <-l.exited:
		case <-time.After(5 * time.Second):
			t.Fatalf("The sender of lane %d did not stop.", i)
		}
	}
	select {
	case err := <-stopped:
		assert.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("The driver did not stop.")
	}
}
