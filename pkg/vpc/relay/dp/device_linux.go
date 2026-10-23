// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
	"unsafe"

	xdp "github.com/atoonk/go-afxdp"
	"github.com/atoonk/packetio"
	"github.com/atoonk/packetio/afxdp"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// OpenDevice opens the dedicated interface ifc with AF_XDP on all its queues. It takes all packets:
// the kernel gets no packet of the interface. The relay XDP program drops the packets that the
// impair map tells it to drop. A send only publishes with TransmitNoKick; the kicker of each TX
// queue kicks.
func OpenDevice(ifc Interface) (*Device, error) {
	link, err := net.InterfaceByName(ifc.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to find the relay interface: %w", err)
	}
	impair, err := openImpairMap()
	if err != nil {
		return nil, err
	}
	xdpOpts := append(modeOptions(ifc.ZeroCopy), xdp.WithProgram(func(sockets, queues *ebpf.Map) (*ebpf.Program, error) {
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
	var ports []txPort
	for i := range dev.NumTxQueues() {
		s := dev.TxQueue(i).(*afxdp.TxQueue).Socket()
		ports = append(ports, txPort{publish: publisher(s), kick: s.KickIfNeeded})
	}
	d, err := newDevice(ifc, dev, ports, uint32(link.MTU), impair)
	if err != nil {
		dev.Close()
		impair.Close()
		return nil, err
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

// nameThread gives the OS thread of the caller a name, for top, perf and /proc. The kernel keeps
// the first 15 bytes.
func nameThread(name string) {
	b, err := unix.BytePtrFromString(name)
	if err != nil {
		return
	}
	_ = unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(b)), 0, 0, 0)
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
