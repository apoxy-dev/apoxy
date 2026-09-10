package netstack

import (
	"log/slog"
	"math/rand"
	"slices"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// randSNATTarget implements stack.Target. It rewrites the source address of a
// packet to a random member of addrs. A packet whose source already is a
// member keeps it, so a socket bound to one overlay address is not moved to a
// sibling address.
type randSNATTarget struct {
	networkProtocol tcpip.NetworkProtocolNumber

	mu    sync.RWMutex
	addrs []tcpip.Address
}

// pick returns the source address the packet must carry, or false if there
// are no addresses.
func (t *randSNATTarget) pick(src tcpip.Address) (tcpip.Address, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.addrs) == 0 {
		return tcpip.Address{}, false
	}
	if slices.ContainsFunc(t.addrs, src.Equal) {
		return src, true
	}
	return t.addrs[rand.Intn(len(t.addrs))], true
}

// Action implements stack.Target.
func (t *randSNATTarget) Action(
	pkt *stack.PacketBuffer,
	hook stack.Hook,
	r *stack.Route,
	_ stack.AddressableEndpoint,
) (stack.RuleVerdict, int) {
	src := pkt.Network().SourceAddress()
	addr, ok := t.pick(src)
	if !ok {
		slog.Debug("SNAT target has no addresses, dropping packet")
		return stack.RuleDrop, 0
	}
	if addr.Equal(src) {
		return stack.RuleAccept, 0
	}

	slog.Debug("SNAT target selected address", slog.Any("address", addr))

	// A per-packet target: concurrent callers must not share Addr.
	snat := stack.SNATTarget{
		NetworkProtocol: t.networkProtocol,
		Addr:            addr,
		ChangeAddress:   true,
	}
	return snat.Action(pkt, hook, r, nil)
}

func (t *randSNATTarget) add(addr tcpip.Address) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !slices.ContainsFunc(t.addrs, addr.Equal) {
		t.addrs = append(t.addrs, addr)
	}
}

func (t *randSNATTarget) del(addr tcpip.Address) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.addrs = slices.DeleteFunc(t.addrs, addr.Equal)
}

type IPTables struct {
	SNATv4 *randSNATTarget
	SNATv6 *randSNATTarget
}

func newIPTables() *IPTables {
	return &IPTables{
		SNATv4: &randSNATTarget{networkProtocol: header.IPv4ProtocolNumber},
		SNATv6: &randSNATTarget{networkProtocol: header.IPv6ProtocolNumber},
	}
}

func (ipt *IPTables) defaultIPTables(clock tcpip.Clock, rand *rand.Rand) *stack.IPTables {
	iptables := stack.DefaultTables(clock, rand)
	ipv4filter := iptables.GetTable(stack.FilterID, false /* ipv6 */)
	ipv4filter.Rules = []stack.Rule{
		{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.TCPProtocolNumber,
				CheckProtocol: true,
			},
			Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber},
		},
		{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.UDPProtocolNumber,
				CheckProtocol: true,
			},
			Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber},
		},
		{Target: &stack.DropTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
		{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
	}
	ipv4filter.BuiltinChains = [stack.NumHooks]int{
		stack.Prerouting:  0,
		stack.Input:       0,
		stack.Forward:     0,
		stack.Output:      0,
		stack.Postrouting: 3, // allow
	}
	ipv4filter.Underflows = [stack.NumHooks]int{
		stack.Prerouting:  2, // drop
		stack.Input:       2, // drop
		stack.Forward:     2, // drop
		stack.Output:      2, // drop
		stack.Postrouting: 2, // drop
	}
	iptables.ReplaceTable(stack.FilterID, ipv4filter, false /* ipv6 */)

	ipv4nat := iptables.GetTable(stack.NATID, false /* ipv6 */)
	ipv4nat.Rules = []stack.Rule{
		{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.TCPProtocolNumber,
				CheckProtocol: true,
			},
			Target: ipt.SNATv4,
		},
		{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.UDPProtocolNumber,
				CheckProtocol: true,
			},
			Target: ipt.SNATv4,
		},
		{Target: &stack.DropTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
		{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
	}
	ipv4nat.BuiltinChains = [stack.NumHooks]int{
		stack.Prerouting:  3,
		stack.Input:       3,
		stack.Forward:     stack.HookUnset,
		stack.Output:      3,
		stack.Postrouting: 0,
	}
	ipv4nat.Underflows = [stack.NumHooks]int{
		stack.Prerouting:  2,
		stack.Input:       2,
		stack.Forward:     2,
		stack.Output:      2,
		stack.Postrouting: 2,
	}
	iptables.ReplaceTable(stack.NATID, ipv4nat, false /* ipv6 */)

	ipv6filter := iptables.GetTable(stack.FilterID, true)
	ipv6filter.Rules = []stack.Rule{
		{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.TCPProtocolNumber,
				CheckProtocol: true,
			},
			Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber},
		},
		{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.UDPProtocolNumber,
				CheckProtocol: true,
			},
			Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber},
		},
		{Target: &stack.DropTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
		{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
	}
	ipv6filter.BuiltinChains = [stack.NumHooks]int{
		stack.Prerouting:  0,
		stack.Input:       0,
		stack.Forward:     0,
		stack.Output:      0,
		stack.Postrouting: 3,
	}
	ipv6filter.Underflows = [stack.NumHooks]int{
		stack.Prerouting:  2,
		stack.Input:       2,
		stack.Forward:     2,
		stack.Output:      2,
		stack.Postrouting: 2,
	}
	iptables.ReplaceTable(stack.FilterID, ipv6filter, true /* ipv6 */)

	ipv6nat := iptables.GetTable(stack.NATID, true /* ipv6 */)
	ipv6nat.Rules = []stack.Rule{
		{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.TCPProtocolNumber,
				CheckProtocol: true,
			},
			Target: ipt.SNATv6,
		},
		{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.UDPProtocolNumber,
				CheckProtocol: true,
			},
			Target: ipt.SNATv6,
		},
		{Target: &stack.DropTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
		{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
	}
	ipv6nat.BuiltinChains = [stack.NumHooks]int{
		stack.Prerouting:  3,
		stack.Input:       3,
		stack.Forward:     stack.HookUnset,
		stack.Output:      3,
		stack.Postrouting: 0,
	}
	ipv6nat.Underflows = [stack.NumHooks]int{
		stack.Prerouting:  2,
		stack.Input:       2,
		stack.Forward:     2,
		stack.Output:      2,
		stack.Postrouting: 2,
	}
	iptables.ReplaceTable(stack.NATID, ipv6nat, true /* ipv6 */)

	return iptables
}
