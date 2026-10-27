// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"
	"unsafe"

	xdp "github.com/atoonk/go-afxdp"
	"github.com/atoonk/packetio"
	"github.com/atoonk/packetio/afxdp"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// OpenDevice opens the dedicated interface ifc with AF_XDP on all its queues, with aead for the PSP
// packets. It takes all packets: the kernel gets no packet of the interface. The relay XDP program
// drops the packets that the impair map tells it to drop. A send only publishes with
// TransmitNoKick; the kicker of each TX queue kicks. OpenDevice sets the link up if it is down; Run
// does not set it down. OpenDevice places the queue interrupts and the relay threads on the CPUs of
// ifc.CPUs, or of the CPU set of the process; Run puts the interrupts back when it stops.
func OpenDevice(ifc Interface, aead AEAD) (*Device, error) {
	cpus, err := relayCPUs(ifc.CPUs)
	if err != nil {
		return nil, err
	}
	link, err := netlink.LinkByName(ifc.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to find the relay interface: %w", err)
	}
	// The host does not set the dedicated interface up. Set it up before AF_XDP binds its queues,
	// because ENA sets up its queues again when the link goes up.
	if link.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(link); err != nil {
			return nil, fmt.Errorf("failed to set the relay interface up: %w", err)
		}
		slog.Info("Set the relay interface up", "link", ifc.Name)
	}
	impair, err := openImpairMap()
	if err != nil {
		return nil, err
	}
	xdpOpts := append(modeOptions(ifc.ZeroCopy), frameOptions()...)
	// The relay places its threads and the queue interrupts itself, so go-afxdp does neither.
	xdpOpts = append(xdpOpts, xdp.WithoutAffinity())
	xdpOpts = append(xdpOpts, xdp.WithProgram(func(sockets, queues *ebpf.Map) (*ebpf.Program, error) {
		return loadRelayXDP(sockets, queues, impair)
	}))
	xdpOpt := afxdp.WithXDP(xdpOpts...)
	// The kernel frees the queues of a stopped relay some milliseconds later, so a relay that
	// restarts can get EBUSY. It tries again with a backoff of 10 ms to 1 s, for at most 30 s.
	dev, err := afxdp.Open(ifc.Name, xdpOpt)
	deadline := time.Now().Add(30 * time.Second)
	for wait := 10 * time.Millisecond; errors.Is(err, unix.EBUSY) && time.Now().Add(wait).Before(deadline); wait = min(2*wait, time.Second) {
		time.Sleep(wait)
		dev, err = afxdp.Open(ifc.Name, xdpOpt)
	}
	if err != nil {
		impair.Close()
		return nil, fmt.Errorf("failed to open %s with AF_XDP: %w", ifc.Name, err)
	}
	setSendBuffers(ifc.Name, dev)
	var ports []txPort
	for i := range dev.NumTxQueues() {
		s := dev.TxQueue(i).(*afxdp.TxQueue).Socket()
		ring := s.NumFreeTxSlots() // No send ran yet, so the TX ring is empty and this is its size.
		ports = append(ports, txPort{
			publish: publisher(s),
			kick:    s.KickIfNeeded,
			pending: func() int { return ring - s.NumFreeTxSlots() },
			counts:  kickCounts(s),
		})
	}
	d, err := newDevice(ifc, dev, ports, uint32(link.Attrs().MTU), &Impair{m: impair}, aead)
	if err != nil {
		dev.Close()
		impair.Close()
		return nil, err
	}
	if err := d.placeCPUs("/sys", "/proc", cpus); err != nil {
		d.ns.close()
		dev.Close()
		impair.Close()
		return nil, fmt.Errorf("failed to place the queue interrupts and the threads of the relay: %w", err)
	}
	// Info reads the zero-copy state of each socket and the XDP mode from the kernel.
	info, err := dev.Fleet().Info()
	if err != nil {
		slog.Warn("Failed to read the AF_XDP state of the relay interface", "link", ifc.Name, "error", err)
	}
	slog.Info("Opened the relay interface", "link", ifc.Name, "zero_copy", info.ZeroCopy, "xdp_mode", info.XDPMode,
		"queues", info.NumQueues, "frame_size", info.FrameSize, "driver", info.Driver)
	return d, nil
}

// modeOptions returns the go-afxdp mode of the zero-copy setting zc. go-afxdp uses copy mode
// unless it gets WithZeroCopy.
func modeOptions(zc bool) []xdp.Option {
	if zc {
		return []xdp.Option{xdp.WithZeroCopy()}
	}
	return nil
}

// frameOptions sizes the UMEM of each queue. The RX frames are a full fill ring, a full RX ring,
// the frames at the workers (frameAllowance) and the frames that QUIC holds: quicQueue datagrams,
// and the read datagrams of the turn that quic-go reads (at most rxBatch), because a turn gives its
// frames back when quic-go read all of it. The QUIC datagrams of all queues can come on one queue,
// so each queue has frames for a full QUIC queue: with a full RX ring and a full QUIC queue, a fill
// ring of frames is still for the fill ring and the NIC (in zero-copy the NIC holds frames that it
// took from the fill ring). The TX frames and the rings keep the go-afxdp defaults.
func frameOptions() []xdp.Option {
	o := xdp.DefaultOptions()
	rx := o.FillRingNumDescs + o.RxRingNumDescs + frameAllowance + quicQueue + rxBatch
	return []xdp.Option{xdp.WithNumFrames(o.TxFrames + rx), xdp.WithTxFrames(o.TxFrames)}
}

// setSendBuffers gives each copy-mode TX socket of dev a send buffer for all its TX frames, and logs
// the value that the kernel took. Without it a kick sends nothing after about 90 frames in flight.
func setSendBuffers(link string, dev packetio.Device) {
	var sockets, want, got int
	var failed error
	for i := range dev.NumTxQueues() {
		q := dev.TxQueue(i).(*afxdp.TxQueue)
		s := q.Socket()
		zc, err := s.ZeroCopy()
		n := sendBuffer(err == nil && zc, q.NumFreeFrames(), s.FrameSize())
		if n == 0 {
			continue
		}
		v, err := setSendBuffer(s.FD(), n)
		if err != nil {
			failed = err
			continue
		}
		if sockets == 0 || v < got {
			got = v
		}
		sockets, want = sockets+1, n
	}
	if failed != nil {
		slog.Warn("Failed to set the send buffer of a copy-mode TX socket", "link", link, "error", failed)
	}
	if sockets > 0 {
		slog.Info("Set the send buffer of the copy-mode TX sockets", "link", link, "sockets", sockets,
			"want_bytes", want, "send_buffer_bytes", got)
	}
}

// sendBuffer returns the send buffer in bytes for a TX socket with frames TX frames of frameSize
// bytes. A zero-copy socket does not use the send buffer, so it gets 0.
func sendBuffer(zeroCopy bool, frames, frameSize int) int {
	if zeroCopy {
		return 0
	}
	return frames * frameSize
}

// setSendBuffer sets the send buffer of the socket fd to n bytes and returns the value that the
// kernel took. Without CAP_NET_ADMIN it uses SO_SNDBUF, which the kernel limits to wmem_max.
func setSendBuffer(fd, n int) (int, error) {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n); err != nil {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, n); err != nil {
			return 0, err
		}
	}
	return unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
}

// nameThread gives the OS thread of the caller a name, for top, perf and /proc, and returns its old
// name. The kernel keeps the first 15 bytes. It calls syscall.Syscall, not unix.Prctl: only in the
// arguments of syscall.Syscall does the compiler keep buf and b alive and in place during the call.
func nameThread(name string) (old string) {
	var buf [16]byte
	_, _, e := syscall.Syscall(unix.SYS_PRCTL, unix.PR_GET_NAME, uintptr(unsafe.Pointer(&buf[0])), 0)
	if e == 0 {
		old = unix.ByteSliceToString(buf[:])
	}
	b, err := unix.BytePtrFromString(name)
	if err != nil {
		return old
	}
	_, _, _ = syscall.Syscall(unix.SYS_PRCTL, unix.PR_SET_NAME, uintptr(unsafe.Pointer(b)), 0)
	return old
}

// The build fails when maxCPUs is not the number of CPUs that unix.CPUSet holds.
const (
	_ = maxCPUs - 8*unsafe.Sizeof(unix.CPUSet{})
	_ = 8*unsafe.Sizeof(unix.CPUSet{}) - maxCPUs
)

// relayCPUs returns the CPU set of the relay: cpus, which must be in the CPU set of the process, or
// the CPU set of the process when cpus is empty.
func relayCPUs(cpus []int) ([]int, error) {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return nil, fmt.Errorf("failed to read the CPU set of the relay: %w", err)
	}
	if len(cpus) == 0 {
		for c := range maxCPUs {
			if set.IsSet(c) {
				cpus = append(cpus, c)
			}
		}
		return cpus, nil
	}
	for _, c := range cpus {
		if !set.IsSet(c) {
			return nil, fmt.Errorf("CPU %d of the relay CPUs is not in the CPU set of the process", c)
		}
	}
	return cpus, nil
}

// pinThread sets the CPU affinity of the calling OS thread to cpu, and logs it. The caller locks
// its goroutine to the thread first. A pin that fails stops Run, as a plan failure does.
func pinThread(role string, cpu int) error {
	var set unix.CPUSet
	set.Set(cpu)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		return fmt.Errorf("failed to pin the %s thread to CPU %d: %w", role, cpu, err)
	}
	slog.Info("Pinned a relay thread", "role", role, "tid", unix.Gettid(), "cpu", cpu)
	return nil
}

// kickCounts returns the counts of the TX port of s. Stats fails after the close; Device.KickCounts
// then has the counts that Run read before.
func kickCounts(s *xdp.Socket) func() KickCounts {
	return func() KickCounts {
		st, _ := s.Stats() // An error of XDP_STATISTICS still gives the counts of the library.
		return KickCounts{Sendto: st.Kicks, EAGAIN: st.KickEAGAIN, Exhausted: st.KickExhausted, EBUSY: st.KickEBUSY}
	}
}

// publisher returns the publish of the TX queue of s. The txQueue lock keeps it to one call at a
// time, so it can use one slice for the descriptors.
func publisher(s *xdp.Socket) func([]packetio.Desc) int {
	var xd []xdp.Desc
	return func(descs []packetio.Desc) int {
		xd = xd[:0]
		for _, d := range descs {
			// The kernel drops a TX descriptor with an option bit other than the continuation bit.
			xd = append(xd, xdp.Desc{Addr: d.Addr, Len: d.Len, Options: d.Options & packetio.OptContinued})
		}
		return s.TransmitNoKick(xd)
	}
}

// loadRelayXDP loads the relay XDP program with the XSK map and the queue map of go-afxdp, and the
// impair map.
func loadRelayXDP(sockets, queues, impair *ebpf.Map) (*ebpf.Program, error) {
	spec, err := loadXdp()
	if err != nil {
		return nil, fmt.Errorf("failed to load the relay XDP objects: %w", err)
	}
	maps := map[string]*ebpf.Map{"xsks_map": sockets, "qidconf_map": queues, "impair": impair}
	for name, m := range maps {
		spec.Maps[name].MaxEntries = m.MaxEntries()
	}
	var objs xdpPrograms
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{MapReplacements: maps}); err != nil {
		return nil, fmt.Errorf("failed to load the relay XDP program: %w", err)
	}
	return objs.RelayXdp, nil
}
