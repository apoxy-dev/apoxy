package netstack

import (
	"log/slog"
	"math/rand"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// randSNATTarget implements stack.Target that performs SNAT using
// a randomly selected address from Addrs.
type randSNATTarget struct {
	stack.SNATTarget

	Addrs []tcpip.Address
}

// Action implements stack.Target.
func (t *randSNATTarget) Action(
	pkt *stack.PacketBuffer,
	hook stack.Hook,
	r *stack.Route,
	_ stack.AddressableEndpoint,
) (stack.RuleVerdict, int) {
	if len(t.Addrs) == 0 {
		// No addresses available for SNAT, drop the packet.
		slog.Debug("SNAT target has no addresses, dropping packet")
		return stack.RuleDrop, 0
	}
	t.SNATTarget.Addr = t.Addrs[rand.Intn(len(t.Addrs))]
	slog.Debug("SNAT target selected address", "address", t.SNATTarget.Addr)
	return t.SNATTarget.Action(pkt, hook, r, nil)
}

func (t *randSNATTarget) add(addr tcpip.Address) {
	for _, a := range t.Addrs {
		if a.Equal(addr) {
			return
		}
	}
	t.Addrs = append(t.Addrs, addr)
}

func (t *randSNATTarget) del(addr tcpip.Address) {
	for i, a := range t.Addrs {
		if a.Equal(addr) {
			t.Addrs = append(t.Addrs[:i], t.Addrs[i+1:]...)
			return
		}
	}
}

type IPTables struct {
	SNATv4 *randSNATTarget
	SNATv6 *randSNATTarget
}

func newIPTables() *IPTables {
	return &IPTables{
		SNATv4: &randSNATTarget{
			SNATTarget: stack.SNATTarget{
				NetworkProtocol: header.IPv4ProtocolNumber,
				ChangeAddress:   true,
			},
			Addrs: []tcpip.Address{},
		},
		SNATv6: &randSNATTarget{
			SNATTarget: stack.SNATTarget{
				NetworkProtocol: header.IPv6ProtocolNumber,
				ChangeAddress:   true,
			},
			Addrs: []tcpip.Address{},
		},
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
