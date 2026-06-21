// The InitStr envelope is pure JSON with no gvisor dependencies — leave
// it without a //go:build constraint so cross-platform unit tests can
// exercise Encode/Decode without pulling in linux-only gvisor packages.
package sentrystack

import (
	"encoding/json"
	"fmt"
)

// initStrVersion is the current envelope version. Bump when the InitStr
// shape changes incompatibly so an old Sentry binary refuses to boot
// against a newer worker's payload (or vice versa) instead of silently
// misinterpreting fields.
const initStrVersion = 1

// InitStrEnv is the env var the host sets on each runsc subprocess
// invocation to communicate per-sandbox InitStr to PreInit. JSON-encoded
// per InitStr.Encode().
//
// Why an env var instead of pid lookup or OCI annotations: PreInit runs
// in the runsc subprocess (same binary as the host, but a separate
// fork-exec'd process), so in-memory state in the host doesn't carry
// over. The PreInitStackArgs only exposes the boot child's pid, which
// isn't a stable key the host can pre-register against. Env vars are
// inherited by the subprocess at exec time, available to PreInit
// immediately, and naturally per-invocation — one Container.Create →
// one runsc subprocess → one env. OCI annotations would also work but
// require the subprocess to reach into the in-progress config struct,
// which the runsc setupNetwork path doesn't expose easily.
//
// Lives in this (un-tagged) file so cross-platform unit tests can
// reference it without pulling linux-only gvisor packages.
const InitStrEnv = "CLRK_SENTRYSTACK_INITSTR"

// InitStr is the serialized payload sent from the host process to the
// Sentry boot child via urpc NetworkInitPluginStack. Host fills it in
// PreInit (per-sandbox); Sentry reads it in Init.
//
// Carries everything the Sentry needs to wire its in-process *tcpip.Stack
// for a specific sandbox: addressing (eth0), MTU, MAC, default
// gateway (cosmetic), and — for egress-capable embedders — MITM/IMDS
// endpoints, DNS resolvers, and the policy snapshot. The core only acts
// on the addressing fields; the egress fields are opaque pass-through
// consumed by an installed forwarder (see [ForwarderInstaller]). Fields
// that aren't set on a given call (zero-valued) cause the corresponding
// Sentry-side wiring to be skipped, so a lo-only sandbox and an
// egress-capable one share the same envelope.
type InitStr struct {
	Version int `json:"v"`

	// SandboxID is the host's opaque identifier for this sandbox.
	// Echoed back over PROXY-v2 TLVs so an egress embedder can demux
	// IMDS callbacks and egress streams to the right invocation.
	SandboxID string `json:"sandbox_id,omitempty"`

	// Eth0V4 is the per-sandbox IPv4 address (e.g. "10.200.0.6") and
	// PrefixLen is its CIDR prefix. If V4 is empty, no eth0 v4
	// addressing is wired; the sandbox sees only lo's 127.0.0.1.
	Eth0V4          string `json:"eth0_v4,omitempty"`
	Eth0V4PrefixLen int    `json:"eth0_v4_prefix,omitempty"`

	// Eth0V6 is the per-sandbox IPv6 address (e.g. "fd00:ec2::ffff").
	// If empty, no eth0 v6 addressing is wired.
	Eth0V6          string `json:"eth0_v6,omitempty"`
	Eth0V6PrefixLen int    `json:"eth0_v6_prefix,omitempty"`

	// Eth0MAC is the synthesized link-layer address for eth0 in colon
	// form (e.g. "02:ca:fe:00:00:01"). Sandbox userspace tools that
	// read /sys/class/net/eth0/address or call getifaddrs see this
	// value. Empty falls back to a zero MAC, which is legal but ugly.
	Eth0MAC string `json:"eth0_mac,omitempty"`

	// Eth0MTU overrides loopetherMTU when set. Zero keeps the default
	// (1500). Only set this if a specific test scenario needs it —
	// loopback semantics make the on-wire MTU irrelevant.
	Eth0MTU uint32 `json:"eth0_mtu,omitempty"`

	// GatewayV4 / GatewayV6 are the IP addresses written as the
	// default-route gateway. The forwarder never actually delivers
	// frames to them (loopether short-circuits), but presenting a
	// gateway IP keeps tools like `ip route` happy.
	GatewayV4 string `json:"gw_v4,omitempty"`
	GatewayV6 string `json:"gw_v6,omitempty"`

	// IMDSHostAddr is the host-process address (typically
	// "127.0.0.1:<WorkerIMDSPort>") the Sentry's TCP forwarder dials
	// when it sees an outbound SYN to 169.254.169.254:80 /
	// [fd00:ec2::254]:80. The Sentry writes a PROXY v2 frame with
	// SandboxID TLV onto the dialed conn so the host can demux.
	// Empty disables IMDS bridging — the dst falls through to
	// direct dial, which will fail since there's no in-Sentry IMDS
	// listener anymore. Opaque to the core; consumed only by an
	// installed forwarder.
	IMDSHostAddr string `json:"imds_host_addr,omitempty"`

	// EgressHostAddr is the host-process address (typically
	// "127.0.0.1:<WorkerEgressPort>") the Sentry's TCP forwarder
	// dials for every non-IMDS, non-DNS outbound stream so the
	// host stays the central egress dispatcher (policy + MITM
	// backend selection + identity/InvocationID PROXY v2 TLVs all
	// live there). The Sentry writes a SandboxID-bearing PROXY v2
	// frame onto the dialed conn so the host can demux; empty
	// disables egress bridging and the Sentry direct-dials through
	// its host netns (useful for tests, but loses MITM + policy).
	// Opaque to the core; consumed only by an installed forwarder.
	EgressHostAddr string `json:"egress_host_addr,omitempty"`

	// IMDSV4 / IMDSV6 are the link-local IMDS addresses the
	// sandbox-side resolver answers; the forwarder matches outbound
	// dst against these to decide IMDS-vs-direct routing. Strings
	// over netip.AddrPort so the wire payload stays self-describing.
	IMDSV4 string `json:"imds_v4,omitempty"`
	IMDSV6 string `json:"imds_v6,omitempty"`

	// DNSResolvers is the list of host-side DNS resolver addrs
	// ("ip:port") the forwarder dials when an outbound UDP SYN
	// targets :53. The Sentry never serves DNS itself — it bridges
	// every query to the host's resolvers and ships the response
	// back over the same flow. Empty disables DNS interception (UDP
	// :53 falls through to direct dial, which inside the Sentry
	// would mean dialing through the host netns — workable but not
	// the intended path).
	DNSResolvers []string `json:"dns_resolvers,omitempty"`

	// InboundListenAddr is the in-sandbox "ip:port" a RESIDENT server
	// (workerd, or a test stub) listens on, e.g. "127.0.0.1:8080".
	// When set together with InboundFDIndex, the Sentry installs an
	// inbound forwarder that accepts host-originated connections off the
	// passed fd and dials this address inside the in-Sentry stack,
	// splicing the two — the exact reverse of the egress forwarder. Empty
	// leaves the sandbox egress-only (the historical behavior). The dial
	// reaches the resident listener rather than any installed egress
	// catch-all forwarder because a bound listening endpoint shadows the
	// global TCP handler (proven in inbound_demux_test.go). Inbound is
	// tenant-neutral, so unlike the egress fields above it is acted on by
	// the core itself, not by an installed [ForwarderInstaller].
	InboundListenAddr string `json:"inbound_listen_addr,omitempty"`

	// InboundFDIndex is the file-descriptor number, inside the runsc-start
	// subprocess, of the host AF_UNIX listening socket the host handed off
	// via cmd.ExtraFiles. PreInit surfaces this fd in its []int return so
	// runsc ships it (FilePayload → InitStackArgs.FDs) into the Sentry,
	// where the inbound forwarder accepts on it. Zero (the default) means
	// no inbound fd was passed. See runscStart for why the fd rides the
	// start subprocess and not create.
	InboundFDIndex int `json:"inbound_fd_index,omitempty"`

	// ControlForwardAddr is the in-sandbox "ip:port" a RESIDENT dispatcher dials
	// to reach the host manager's control server (e.g. "127.0.0.2:80",
	// deliberately distinct from InboundListenAddr's 127.0.0.1 data socket). When
	// set together with ControlHostAddr, the Sentry installs a control
	// forwarder: an in-stack listener on this address that splices each guest
	// connection to a host net.Dial("tcp", ControlHostAddr). It is the
	// guest→host mirror of InboundListenAddr and, like inbound, tenant-neutral
	// (acted on by the core, not by a ForwarderInstaller). It needs no fd
	// donation — the Sentry shares the host net namespace and dials the manager's
	// loopback control listener directly. Empty leaves the control plane
	// unconfigured.
	ControlForwardAddr string `json:"control_forward_addr,omitempty"`

	// ControlHostAddr is the HOST loopback "ip:port" of the manager's control
	// server (TCP) the control forwarder dials for each guest connection to
	// ControlForwardAddr. TCP, not AF_UNIX: the Sentry's plugin seccomp filter
	// only allows socket() for AF_INET/AF_INET6, so a host unix dial from inside
	// the Sentry returns ENOSYS. Empty (regardless of ControlForwardAddr)
	// disables control forwarding.
	ControlHostAddr string `json:"control_host_addr,omitempty"`
}

// Encode serializes an InitStr. Empty SandboxID is allowed (lo-only).
func (s *InitStr) Encode() (string, error) {
	s.Version = initStrVersion
	b, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("encoding initstr: %w", err)
	}
	return string(b), nil
}

// DecodeInitStr parses the payload received over urpc. Rejects mismatched
// versions to surface skew loudly instead of misreading fields.
func DecodeInitStr(s string) (*InitStr, error) {
	if s == "" {
		return &InitStr{Version: initStrVersion}, nil
	}
	var out InitStr
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("decoding initstr: %w", err)
	}
	if out.Version != initStrVersion {
		return nil, fmt.Errorf("initstr version mismatch: got %d, want %d", out.Version, initStrVersion)
	}
	return &out, nil
}
