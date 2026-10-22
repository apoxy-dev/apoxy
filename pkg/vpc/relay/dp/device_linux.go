// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"errors"
	"fmt"
	"net"
	"time"

	xdp "github.com/atoonk/go-afxdp"
	"github.com/atoonk/packetio/afxdp"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// OpenDevice opens the dedicated interface ifc with AF_XDP on all its queues. It takes all packets:
// the kernel gets no packet of the interface. The relay XDP program drops the packets that the
// impair map tells it to drop.
func OpenDevice(ifc Interface) (*Device, error) {
	link, err := net.InterfaceByName(ifc.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to find the relay interface: %w", err)
	}
	impair, err := openImpairMap()
	if err != nil {
		return nil, err
	}
	xdpOpt := afxdp.WithXDP(xdp.WithProgram(func(sockets, queues *ebpf.Map) (*ebpf.Program, error) {
		return loadRelayXDP(sockets, queues, impair)
	}))
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
	d, err := newDevice(ifc, dev, uint32(link.MTU), impair)
	if err != nil {
		dev.Close()
		impair.Close()
		return nil, err
	}
	return d, nil
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
