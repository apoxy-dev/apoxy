// icx_network.go
package netstack

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/apoxy-dev/icx"
	icxns "github.com/apoxy-dev/icx/vtep/netstack"
	"github.com/dpeckett/network"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/l2pc"
)

// TODO (dpeckett): nuke this at some point and merge the logic into the router.
type ICXNetwork struct {
	network.Network
	handler *icx.Handler
	phy     *l2pc.L2PacketConn
	ns      *Stack

	// dp is the shared ICX netstack datapath driver (icx/vtep/netstack). It owns
	// the channel.Endpoint <-> engine <-> underlay pump; this type contributes
	// the gVisor stack, SNAT, and TCP/UDP forwarders around it.
	dp *icxns.Datapath

	closeOnce sync.Once
}

// l2Underlay adapts *l2pc.L2PacketConn to the icx netstack datapath's Underlay.
// WriteFrames reuses a scratch []batchpc.Message; the datapath's outbound pump
// is single-goroutine, so the scratch needs no synchronization.
type l2Underlay struct {
	phy  *l2pc.L2PacketConn
	msgs []batchpc.Message
}

func (u *l2Underlay) ReadFrame(buf []byte) (int, error) {
	return u.phy.ReadFrame(buf)
}

func (u *l2Underlay) WriteFrames(frames [][]byte) (int, error) {
	if cap(u.msgs) < len(frames) {
		u.msgs = make([]batchpc.Message, len(frames))
	}
	msgs := u.msgs[:len(frames)]
	for i, f := range frames {
		msgs[i].Buf = f
	}
	return u.phy.WriteBatchFrames(msgs, 0)
}

// NewICXNetwork creates a new ICXNetwork instance with the given handler, physical connection, MTU, and resolve configuration.
// If pcapPath is provided, it will create a packet sniffer that writes to the specified file.
// The handler must be configured in layer3 mode.
func NewICXNetwork(handler *icx.Handler, phy *l2pc.L2PacketConn, mtu int, resolveConf *network.ResolveConfig, pcapPath string) (*ICXNetwork, error) {
	ns, err := NewStack(mtu, pcapPath)
	if err != nil {
		return nil, err
	}

	dp, err := icxns.New(icxns.Config{
		Engine:   handler,
		Endpoint: ns.Endpoint,
		Underlay: &l2Underlay{phy: phy},
	})
	if err != nil {
		_ = phy.Close()
		ns.Close()
		return nil, fmt.Errorf("could not create ICX netstack datapath: %w", err)
	}

	net := &ICXNetwork{
		Network: ns.Network(resolveConf),
		handler: handler,
		phy:     phy,
		ns:      ns,
		dp:      dp,
	}

	return net, nil
}

// Close cleans up the network stack and closes the underlying resources.
func (net *ICXNetwork) Close() error {
	net.closeOnce.Do(func() {
		if net.dp != nil {
			_ = net.dp.Close()
		}

		net.ns.Close()
	})

	return nil
}

// Start copies packets to and from netstack and icx.
// Start runs the netstack <-> ICX datapath until ctx is cancelled or the
// underlying transport (phy) is closed. It blocks and should run in its own
// goroutine. The two pump loops (channel.Endpoint <-> engine <-> underlay) now
// live in the shared icx/vtep/netstack driver; this method just drives it.
func (net *ICXNetwork) Start(ctx context.Context) error {
	return net.dp.Run(ctx)
}

func (net *ICXNetwork) AddAddr(addr netip.Prefix) error {
	return net.ns.AddAddr(addr)
}

func (net *ICXNetwork) DelAddr(addr netip.Prefix) error {
	return net.ns.DelAddr(addr)
}

// ForwardTo forwards all inbound TCP traffic to the upstream network.
func (net *ICXNetwork) ForwardTo(ctx context.Context, upstream network.Network) error {
	return net.ns.ForwardTo(ctx, upstream)
}
