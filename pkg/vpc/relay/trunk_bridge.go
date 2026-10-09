// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"encoding/binary"
	"net/netip"

	pspwire "github.com/apoxy-dev/softpsp/psp"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// trunkCarries reports whether the relay can send inner, a clear packet of s,
// to the relay of h. It counts the drop if not. A hop on this relay needs no trunk.
func (r *Router) trunkCarries(s *Session, h hop, inner []byte) bool {
	switch {
	case h.home == "":
		return true
	case h.tag == 0:
		// The other relay knows a sender only by its tag.
		s.dataDrops.Add(1)
		return false
	}
	// The limit is the same as for the PSP packet of a row with this inner packet.
	return r.trunkFits(s, h.pair, h.sa, len(inner)+pspwire.Overhead) == Pass
}

// sealTrunk seals inner into buf with the trunk SA and the sender tag of h, and
// sends the trunk packet to the relay of h.
func (r *Router) sealTrunk(h hop, inner, buf []byte) error {
	br := r.bridge.Load()
	if br == nil || h.sa == nil || h.tag == trunkTagRelay || buf == nil {
		return errNoSA
	}
	n, err := h.sa.SealTrunk(h.tag, buf, inner)
	if err != nil {
		// The SA has no sequence number left.
		r.drops[dropTrunkKeys].Add(1)
		return err
	}
	_, err = br.tr.WriteTo(buf[:n], h.pair.udp)
	return err
}

// bridgeIn sends inner, the clear packet in pkt of the sender tag on member home,
// to its receiver: a data frame, or sealed in buf with fwd. sess gave the SA of pkt.
func (r *Router) bridgeIn(home string, sess *MeshSession, tag uint32, pkt, inner, buf []byte, fwd forwarder) (dropReason, bool) {
	src, ok := innerSource(inner)
	if !ok {
		return dropMalformed, false
	}
	r.mu.RLock()
	h, why := r.hopIn(home, sess, tag, src, inner)
	var vni uint32
	if h.next != nil {
		vni = h.next.sync.ref.GetNetworkId()
	}
	r.mu.RUnlock()
	switch {
	case h.next == nil:
		return why, false
	case h.mode == dp.Mode_MODE_QUIC:
		// The frame header takes the 5 bytes before the inner packet. The frame
		// has the network ID of the receiver, because the trunk packet has none.
		frame := pkt[pspwire.PrefixLen-peerconn.DataLen : pspwire.PrefixLen+len(inner)]
		frame[0] = peerconn.TypeData
		binary.BigEndian.PutUint32(frame[1:peerconn.DataLen], vni<<8)
		if h.out.sendDatagram(frame) != nil {
			return dropTrunkNotSent, false
		}
	case h.mode == dp.Mode_MODE_PSP && h.sa != nil:
		n, err := h.sa.Seal(buf, inner)
		if err != nil {
			return dropTrunkNotSent, false
		}
		fwd.add(buf[:n], h.addr)
	default:
		return dropTrunkNotSent, false
	}
	// The relay of the sender applied the tunnel limit.
	if h.att != nil {
		h.att.count.packets.Add(1)
		h.att.count.bytes.Add(uint64(len(inner)))
	}
	return 0, true
}

// hopIn does the checks of inner for the sender tag on member home: the entry
// of the sender, Permit and the route of the destination. Router.mu must be held.
func (r *Router) hopIn(home string, sess *MeshSession, tag uint32, src netip.Addr, inner []byte) (hop, dropReason) {
	dst, _ := innerDest(inner)
	h := hop{dst: dst}
	if sess == nil {
		// The member did not get the SA of the packet on a session.
		return h, dropTrunkSender
	}
	// The entry of the sender has the route of the inner source, as for a peer frame.
	from, why := r.trunk.Load().m.pres.tagged(sess, tag, dropTrunkSource, func(e *presenceEntry) bool {
		o := r.ownerOf(e.vpc, src)
		return o.s != nil && o.s.home == home && o.origin == e.id
	})
	switch {
	case from == nil && why == dropTrunkSource:
		return h, dropTrunkSource
	case from == nil:
		return h, dropTrunkSender
	case !r.permit(from.vpc, from.subject, from.vpc, dst):
		return h, dropTrunkPermit
	}
	// The packet came from another relay, so it goes to no other relay.
	to := r.localOwner(from.vpc, dst)
	if to.s == nil {
		return h, dropTrunkNotLocal
	}
	h.local(to, inner)
	return h, 0
}
