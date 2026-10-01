// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"errors"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

// Relay sessions need this QUIC InitialPacketSize or more for 1200 B peer packets.
const MinPacketSize = 1270

var errNoDatagrams = errors.New("relay session has no datagrams")

// serveDatagrams forwards the peer frames of s until its connection closes.
func (r *Router) serveDatagrams(s *Session, qc quic.Connection) {
	for {
		b, err := qc.ReceiveDatagram(qc.Context())
		if err != nil {
			return
		}
		r.forwardDatagram(s, b, time.Now())
	}
}

// forwardDatagram sends a peer frame from s to the session of its destination,
// if s routes its source. It reports whether it sent the frame.
func (r *Router) forwardDatagram(s *Session, b []byte, now time.Time) bool {
	dst, src, _, err := peerconn.DecodeToRelay(b)
	if err != nil {
		return false
	}
	r.mu.RLock()
	owner := r.lookup(s.id.VPC, src)
	r.mu.RUnlock()
	if owner != s {
		return false
	}
	next := r.Route(s, dst, now)
	if next == nil {
		return false
	}
	return next.sendDatagram(peerconn.Forwarded(b)) == nil
}
