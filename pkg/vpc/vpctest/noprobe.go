// SPDX-License-Identifier: AGPL-3.0-only

package vpctest

import (
	"net"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
)

// NoProbeConn is an agent socket that drops the PSP path probes of the agent, so
// its relay sessions fall back to QUIC mode. QUIC keeps its UDP socket path.
type NoProbeConn struct{ *net.UDPConn }

// QUIC uses GSO, GRO and ECN only on a socket with these methods.
var _ quic.OOBCapablePacketConn = NoProbeConn{}

func (c NoProbeConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if _, probe := p2p.ProbeSID(b); probe {
		return len(b), nil
	}
	return c.UDPConn.WriteTo(b, addr)
}

func (c NoProbeConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if _, probe := p2p.ProbeSID(b); probe {
		return len(b), len(oob), nil
	}
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}
