// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"fmt"
	"net"

	"github.com/atoonk/packetio"
	"github.com/atoonk/packetio/afxdp"
)

// OpenDevice opens the dedicated interface ifc with AF_XDP on all its queues. It takes all packets:
// the kernel gets no packet of the interface.
func OpenDevice(ifc Interface) (*Device, error) {
	link, err := net.InterfaceByName(ifc.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to find the relay interface: %w", err)
	}
	dev, err := afxdp.Open(ifc.Name, afxdp.WithSteering(packetio.SteeringFilter{Promiscuous: true}))
	if err != nil {
		return nil, fmt.Errorf("failed to open %s with AF_XDP: %w", ifc.Name, err)
	}
	d, err := newDevice(ifc, dev, uint32(link.MTU))
	if err != nil {
		dev.Close()
		return nil, err
	}
	return d, nil
}
