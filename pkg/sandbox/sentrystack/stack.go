//go:build linux

// Package sentrystack registers a gVisor PluginStack that runs inside
// each sandbox's Sentry. It owns the in-Sentry *tcpip.Stack — the only
// network the sandboxed process ever sees — and wires the loopback +
// eth0 NICs the sandbox boots with.
//
// This is the tenant- and egress-neutral CORE carved out of clrk's
// sandbox runtime. It wires addressing only; the egress/IMDS/DNS
// forwarder data path is layered back on by an embedder through the
// [ForwarderInstaller] hook (clrk's internal/sentrystack wrapper sets it
// at package init() via a blank import — the standard Go extension
// pattern, cf. database/sql drivers and image-format decoders). A
// standalone consumer that imports only this package (e.g. workerd-host
// before the egress track lands) leaves the hook nil and gets a sandbox
// with lo + eth0 and no outbound forwarder.
//
// Lifecycle:
//
//   - Package init() constructs a singleton Stack with an empty
//     *tcpip.Stack (no NICs) and registers it via plugin.RegisterPluginStack.
//     The same init() runs in the host process (which calls PreInit
//     to compose the initStr per-sandbox) and in each Sentry boot
//     child (which calls Init exactly once to wire up NICs).
//   - PreInit runs in the host process. It validates and returns the
//     per-sandbox initStr the host stashed in the InitStrEnv env var.
//   - Init runs in the Sentry boot child. It reads initStr, adds lo +
//     (when addressing is present) eth0 to the singleton's *tcpip.Stack,
//     and finally invokes ForwarderInstaller if an embedder registered one.
//
// inet.Stack is satisfied by the embedded *netstack.Stack, which wraps
// the same *tcpip.Stack. We don't reimplement Interfaces / InterfaceAddrs
// / RouteTable / etc — gVisor's existing implementation reads them
// straight off the stack.
package sentrystack

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// ForwarderInstaller, when non-nil, is invoked by Init after the lo/eth0
// NICs are wired and the route table is set, to install transport-protocol
// handlers (the egress/IMDS/DNS forwarder data path). Set it from an
// embedder's package init() via a blank import — the standard Go
// extension pattern. The core stays tenant- and egress-neutral; the
// installer reaches the inner *tcpip.Stack via the [Stack.TCPIPStack]
// accessor and reads the egress fields (IMDSHostAddr, EgressHostAddr,
// IMDSV4/V6, DNSResolvers) the host stamped into the decoded InitStr.
//
// Left nil (standalone core), Init wires lo + eth0 with no outbound
// forwarder: loopback works, egress awaits an installer.
var ForwarderInstaller func(s *Stack, init *InitStr)

// NIC IDs. Stable values so logs and forwarder-side code can refer to
// them by symbol.
const (
	loNICID   tcpip.NICID = 1
	eth0NICID tcpip.NICID = 2
)

// Stack is the sandbox PluginStack implementation. Wraps an *netstack.Stack
// (which in turn wraps the *tcpip.Stack) so inet.Stack is satisfied by
// embedding; PreInit and Init are added on top to satisfy plugin.PluginStack.
type Stack struct {
	*netstack.Stack

	// initOnce guards Init so a double-Init from the runsc bootstrap
	// path can't tear down a stack that's already wired up.
	initOnce sync.Once
	initErr  error
}

// Compile-time check that Stack satisfies plugin.PluginStack.
var _ plugin.PluginStack = (*Stack)(nil)

// newStack constructs the singleton with an empty *tcpip.Stack (no NICs
// yet). Run at package init time so the Stack pointer is valid before
// any sentry code calls inet.Stack methods on it; Init adds NICs later
// in the Sentry boot child.
func newStack() *Stack {
	ts := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: true,
	})
	return &Stack{
		Stack: netstack.NewStack(ts, 1),
	}
}

// tcpipStack returns the inner *tcpip.Stack. Used by our socket Provider
// to create endpoints.
func (s *Stack) tcpipStack() *stack.Stack {
	return s.Stack.Stack
}

// TCPIPStack exposes the inner *tcpip.Stack so a [ForwarderInstaller]
// can register transport-protocol handlers (the egress forwarder data
// path) on it. Exported for embedders only; the core never registers
// transport handlers itself.
func (s *Stack) TCPIPStack() *stack.Stack {
	return s.tcpipStack()
}

// PreInit runs in the runsc subprocess (host-spawned). Reads the
// InitStr from the InitStrEnv env var, validates it, and returns the
// raw payload — urpc ships it to the Sentry boot child where Init
// decodes it again. Empty env yields a valid empty envelope so manual
// `run` invocations (no per-sandbox config) boot with just lo.
func (s *Stack) PreInit(args *plugin.PreInitStackArgs) (string, []int, error) {
	raw := os.Getenv(InitStrEnv)
	// Validate roundtrip so a malformed host-side payload fails fast
	// in PreInit rather than confusingly later in Init.
	init, err := DecodeInitStr(raw)
	if err != nil {
		return "", nil, fmt.Errorf("sentrystack PreInit decode: %w", err)
	}

	// Surface the inbound host-listener fd so runsc ships it to the Sentry
	// via the FilePayload → InitStackArgs.FDs path. The host handed this fd
	// to the runsc-start subprocess via cmd.ExtraFiles, so it's already open
	// at InboundFDIndex in this (PreInit's) process; runsc dups it across the
	// urpc boundary into the Sentry. nil when no inbound is configured, which
	// keeps the egress-only default untouched.
	var fds []int
	if init.InboundFDIndex > 0 {
		fds = []int{init.InboundFDIndex}
	}

	if raw == "" {
		// Re-encode an empty envelope so the Sentry side gets a
		// well-formed string (Init's DecodeInitStr also handles ""
		// but explicit encoding keeps the wire payload self-describing).
		enc, err := (&InitStr{}).Encode()
		if err != nil {
			return "", nil, fmt.Errorf("sentrystack PreInit encode empty: %w", err)
		}
		return enc, fds, nil
	}
	return raw, fds, nil
}

// Init runs in the Sentry boot child. Decodes the initStr and adds NICs
// to the singleton's *tcpip.Stack. Wires lo always, eth0 when the host
// provided per-sandbox addressing, then invokes the optional
// ForwarderInstaller for the egress data path.
func (s *Stack) Init(args *plugin.InitStackArgs) error {
	s.initOnce.Do(func() {
		s.initErr = s.doInit(args)
	})
	return s.initErr
}

func (s *Stack) doInit(args *plugin.InitStackArgs) error {
	init, err := DecodeInitStr(args.InitStr)
	if err != nil {
		return fmt.Errorf("sentrystack Init: %w", err)
	}

	ts := s.tcpipStack()

	// lo NIC. Loopback link endpoint delivers WritePackets straight back
	// into DeliverNetworkPacket so 127.0.0.1 and ::1 work without
	// touching the host kernel.
	//
	// CreateNICWithOptions (not CreateNIC) so the NIC carries its name —
	// userspace tools inside the sandbox (ip / getifaddrs) and our
	// test helpers both key off NICInfo.Name.
	if err := ts.CreateNICWithOptions(loNICID, loopback.New(), stack.NICOptions{Name: "lo"}); err != nil {
		return fmt.Errorf("creating lo NIC: %s", err)
	}
	if err := ts.SetPromiscuousMode(loNICID, true); err != nil {
		return fmt.Errorf("setting lo promiscuous: %s", err)
	}
	if err := ts.SetSpoofing(loNICID, true); err != nil {
		return fmt.Errorf("setting lo spoofing: %s", err)
	}

	v4 := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			PrefixLen: 8,
		},
	}
	if err := ts.AddProtocolAddress(loNICID, v4, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("adding lo v4 address: %s", err)
	}

	v6 := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16(loV6Bytes()),
			PrefixLen: 128,
		},
	}
	if err := ts.AddProtocolAddress(loNICID, v6, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("adding lo v6 address: %s", err)
	}

	v6LoopbackSubnet, err := tcpip.NewSubnet(header.IPv6Loopback, tcpip.MaskFromBytes(allOnes16[:]))
	if err != nil {
		return fmt.Errorf("building lo v6 subnet: %w", err)
	}

	routes := []tcpip.Route{
		{
			Destination: header.IPv4LoopbackSubnet,
			NIC:         loNICID,
		},
		{
			Destination: v6LoopbackSubnet,
			NIC:         loNICID,
		},
	}

	// eth0 is wired only when the host provided addressing in initStr.
	// lo-only callers (no addressing) get a lo-only sandbox; callers
	// with addressing get eth0 routed via loopether with the per-sandbox IP.
	if init.Eth0V4 != "" || init.Eth0V6 != "" {
		ethRoutes, err := s.wireEth0(init)
		if err != nil {
			return fmt.Errorf("wiring eth0: %w", err)
		}
		routes = append(routes, ethRoutes...)
	}

	ts.SetRouteTable(routes)

	// Install the optional egress/forwarder data path. The core wires
	// only lo + eth0 addressing; an embedder registers ForwarderInstaller
	// at package init() to add the TCP/UDP forwarders that bridge
	// outbound flows to the host's egress + IMDS + DNS planes. Left nil
	// (standalone core) the sandbox gets lo + eth0 with no outbound
	// forwarder — loopback works, egress awaits an installer.
	//
	// With promiscuous + spoofing on eth0, every outbound packet loops
	// back into the protocol layer; an installed forwarder catches it
	// (no listening endpoint matches) and bridges it upstream.
	if ForwarderInstaller != nil {
		ForwarderInstaller(s, init)
	}

	// Inbound forwarder (the reverse of the egress forwarders an installer
	// adds above): when the host passed a host AF_UNIX listener fd and an
	// in-sandbox listen address, accept host-originated connections off that
	// fd and splice each to a fresh in-stack dial toward the resident server.
	// The dial is demuxed to the resident listener, not any egress catch-all,
	// because a bound endpoint shadows the global TCP handler (see
	// inbound_demux_test.go). Unlike egress, inbound is tenant-neutral, so the
	// core installs it directly — a standalone consumer (workerd-host) that
	// leaves ForwarderInstaller nil still gets ingress. Skipped entirely when
	// no inbound fd/addr is configured, leaving the sandbox egress-only.
	if len(args.FDs) > 0 && init.InboundListenAddr != "" {
		if err := s.installInboundForwarder(args.FDs[0], init.InboundListenAddr); err != nil {
			return fmt.Errorf("installing inbound forwarder: %w", err)
		}
	}

	// Control forwarder (resident → host manager): the guest→host mirror of
	// inbound and, like inbound, tenant-neutral so the core installs it directly
	// (a standalone consumer that leaves ForwarderInstaller nil still gets a
	// control plane). When the host set both an in-sandbox control listen addr
	// and a host control listener addr, run an in-stack listener the dispatcher
	// dials and splice each connection to the host manager's control server.
	// Needs no donated fd — the Sentry dials the host loopback TCP listener
	// directly. Skipped when unset, leaving the resident with no WorkerLoader
	// source.
	if init.ControlForwardAddr != "" && init.ControlHostAddr != "" {
		if err := s.installControlForwarder(init.ControlForwardAddr, init.ControlHostAddr); err != nil {
			return fmt.Errorf("installing control forwarder: %w", err)
		}
	}

	return nil
}

// wireEth0 creates the eth0 NIC backed by a loopether LinkEndpoint and
// returns the default routes that should be added to the stack-wide
// route table. Caller must check init has at least one of Eth0V4 or
// Eth0V6 populated before calling; an init with neither leaves eth0
// off entirely (lo-only mode).
func (s *Stack) wireEth0(init *InitStr) ([]tcpip.Route, error) {
	ts := s.tcpipStack()

	mac, err := ParseMAC(init.Eth0MAC)
	if err != nil {
		return nil, fmt.Errorf("parsing eth0 MAC %q: %w", init.Eth0MAC, err)
	}
	link := newLoopether(mac)
	if init.Eth0MTU != 0 {
		link.SetMTU(init.Eth0MTU)
	}

	if err := ts.CreateNICWithOptions(eth0NICID, link, stack.NICOptions{Name: "eth0"}); err != nil {
		return nil, fmt.Errorf("creating eth0 NIC: %s", err)
	}
	// Promiscuous + spoofing are mandatory: outbound packets from the
	// sandbox go through loopether → DeliverNetworkPacket; without
	// promiscuous the stack drops them because the dst isn't ours,
	// without spoofing it drops them because the src isn't ours either.
	// Loopback semantics require both. See the loopether type comment.
	if err := ts.SetPromiscuousMode(eth0NICID, true); err != nil {
		return nil, fmt.Errorf("setting eth0 promiscuous: %s", err)
	}
	if err := ts.SetSpoofing(eth0NICID, true); err != nil {
		return nil, fmt.Errorf("setting eth0 spoofing: %s", err)
	}

	var routes []tcpip.Route

	if init.Eth0V4 != "" {
		addr, prefix, err := ParsePrefixed(init.Eth0V4, init.Eth0V4PrefixLen, 4)
		if err != nil {
			return nil, fmt.Errorf("eth0 v4 %q: %w", init.Eth0V4, err)
		}
		pa := tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addr,
				PrefixLen: prefix,
			},
		}
		if err := ts.AddProtocolAddress(eth0NICID, pa, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("adding eth0 v4 address: %s", err)
		}
		// Default v4 route via eth0. Gateway is cosmetic; the
		// forwarder catches everything before any neighbor
		// resolution happens.
		routes = append(routes, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         eth0NICID,
		})
	}

	if init.Eth0V6 != "" {
		addr, prefix, err := ParsePrefixed(init.Eth0V6, init.Eth0V6PrefixLen, 16)
		if err != nil {
			return nil, fmt.Errorf("eth0 v6 %q: %w", init.Eth0V6, err)
		}
		pa := tcpip.ProtocolAddress{
			Protocol: ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addr,
				PrefixLen: prefix,
			},
		}
		if err := ts.AddProtocolAddress(eth0NICID, pa, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("adding eth0 v6 address: %s", err)
		}
		routes = append(routes, tcpip.Route{
			Destination: header.IPv6EmptySubnet,
			NIC:         eth0NICID,
		})
	}

	return routes, nil
}

// ParseMAC parses a hardware address into a 6-byte LinkAddress, accepting
// every form net.ParseMAC accepts (colon, dash, dotted-quad). An empty
// string returns a zero MAC — valid but presents as 00:00:00:00:00:00.
//
// Exported for unit tests.
func ParseMAC(s string) (tcpip.LinkAddress, error) {
	if s == "" {
		var zero [6]byte
		return tcpip.LinkAddress(zero[:]), nil
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		return "", fmt.Errorf("MAC %q: %w", s, err)
	}
	if len(hw) != 6 {
		return "", fmt.Errorf("MAC %q must be 6 octets (got %d)", s, len(hw))
	}
	return tcpip.LinkAddress(hw), nil
}

// ParsePrefixed parses an IPv4 or IPv6 address string into a tcpip.Address
// of the expected byte width (4 or 16), returning the prefix length
// (defaulting to /32 for v4 and /128 for v6 if the caller passed 0).
//
// Exported for unit tests.
func ParsePrefixed(s string, prefix, want int) (tcpip.Address, int, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return tcpip.Address{}, 0, fmt.Errorf("parse: %w", err)
	}
	switch want {
	case 4:
		if !a.Is4() {
			a4 := a.Unmap()
			if !a4.Is4() {
				return tcpip.Address{}, 0, fmt.Errorf("expected v4")
			}
			a = a4
		}
		if prefix == 0 {
			prefix = 32
		}
		return tcpip.AddrFrom4(a.As4()), prefix, nil
	case 16:
		if !a.Is6() {
			return tcpip.Address{}, 0, fmt.Errorf("expected v6")
		}
		if prefix == 0 {
			prefix = 128
		}
		return tcpip.AddrFrom16(a.As16()), prefix, nil
	default:
		return tcpip.Address{}, 0, fmt.Errorf("unsupported address width %d", want)
	}
}

// allOnes16 is the /128 mask for the IPv6 loopback subnet.
var allOnes16 = [16]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

// loV6Bytes returns ::1 as a 16-byte array.
func loV6Bytes() [16]byte {
	var b [16]byte
	b[15] = 1
	return b
}
