// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"log/slog"
	"net"
	"net/netip"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// checkMoved tells the relay when the local address of the agent changes.
// The relay then follows the QUIC connection to its new path.
func (a *Agent) checkMoved() {
	a.mu.Lock()
	rc := a.rc
	a.mu.Unlock()
	if rc == nil {
		return
	}
	l := rc.localAddr()
	if !l.IsValid() || l == rc.local {
		return
	}
	slog.Info("Local address changed", "relay", rc.addr, "from", rc.local, "to", l)
	rc.local = l
	go func() {
		if err := rc.send(&dp.SessionRequest{Msg: &dp.SessionRequest_Moved{Moved: &dp.Moved{}}}); err != nil && !rc.ended() {
			slog.Warn("Failed to tell the relay about the new local address", "relay", rc.addr, "error", err)
		}
	}()
}

// localAddr returns the source address that the kernel selects toward the
// relay, with the port of the agent socket. It sends no packet.
func (rc *relayConn) localAddr() netip.AddrPort {
	dst := netip.AddrPortFrom(rc.relayAddr.Addr().Unmap(), rc.relayAddr.Port())
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(dst))
	if err != nil {
		return netip.AddrPort{}
	}
	defer c.Close()
	src := c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	var port uint16
	if ua, ok := rc.a.cfg.Transport.Conn.LocalAddr().(*net.UDPAddr); ok {
		port = uint16(ua.Port)
	}
	return netip.AddrPortFrom(src, port)
}
