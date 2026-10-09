// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"errors"
	"net/netip"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

const (
	// meshFramesRevision is the first revision of a relay that gets the peer
	// frames of the agents of another relay.
	meshFramesRevision = 7

	// The first byte of a datagram on a mesh session is its type, so that
	// other types can come later.
	meshFramePeer = 0x01
	// meshPeerHeader is the type and the sender tag. The destination, the
	// source and the packet of the frame of the agent come after them.
	meshPeerHeader = 1 + 3
	// meshPeerLen is the length of a peer frame on the mesh with no packet.
	meshPeerLen = meshPeerHeader + 16 + 16
)

// meshPeerFrame returns the peer frame b of the session with tag as the
// datagram for a member. The type and the tag take the place of the type of b.
func meshPeerFrame(b []byte, tag uint32) []byte {
	n := len(b)
	b = append(b, make([]byte, meshPeerHeader-1)...)
	copy(b[meshPeerHeader:], b[1:n])
	b[0], b[1], b[2], b[3] = meshFramePeer, byte(tag>>16), byte(tag>>8), byte(tag)
	return b
}

// sendToMember sends the peer frame b of the session with tag to the member
// home, which has the session of its destination. It counts each drop.
func (r *Router) sendToMember(home string, tag uint32, b []byte) bool {
	var ms *MeshSession
	if t := r.trunk.Load(); t != nil {
		ms = t.m.Session(home)
	}
	switch {
	case ms == nil:
		r.drops[dropMeshNoSession].Add(1)
		return false
	case ms.Version().GetRevision() < meshFramesRevision:
		r.drops[dropMeshOldMember].Add(1)
		return false
	}
	err := ms.SendDatagram(meshPeerFrame(b, tag))
	var large *quic.DatagramTooLargeError
	switch {
	case err == nil:
		return true
	case errors.As(err, &large):
		// The relay does not split a frame.
		r.drops[dropMeshTooLarge].Add(1)
	default:
		r.drops[dropMeshNoSession].Add(1)
	}
	return false
}

// datagram gives the peer frame in the datagram b of the member of s to a
// session of r. It counts each datagram that it drops.
func (p *presence) datagram(r *Router, s *MeshSession, b []byte) {
	// A send copies the frame, so quic-go can use b again.
	defer quic.ReleaseDatagram(b)
	to, reason := p.receiver(r, s, b)
	if to == nil {
		r.drops[reason].Add(1)
		return
	}
	// The last byte of the tag is where the frame of the agent had its type.
	if to.sendDatagram(peerconn.Forwarded(b[meshPeerHeader-1:])) != nil {
		r.drops[dropMeshNotSent].Add(1)
	}
}

// receiver checks the datagram b of the member of s. It returns the session
// of r that gets the peer frame, or the reason of the drop.
func (p *presence) receiver(r *Router, s *MeshSession, b []byte) (*Session, dropReason) {
	if len(b) < meshPeerLen || b[0] != meshFramePeer {
		return nil, dropMeshMalformed
	}
	tag := uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	dst := netip.AddrFrom16([16]byte(b[meshPeerHeader : meshPeerHeader+16])).Unmap()
	src := netip.AddrFrom16([16]byte(b[meshPeerHeader+16 : meshPeerLen])).Unmap()
	r.mu.RLock()
	defer r.mu.RUnlock()
	from, reason := p.sender(r, s, tag, src)
	switch {
	case from == nil:
		return nil, reason
	case !r.permit(from.vpc, from.subject, from.vpc, dst):
		return nil, dropMeshPermit
	}
	// The frame came from another relay, so it goes to no other relay.
	if to := r.localOwner(from.vpc, dst).s; to != nil {
		return to, 0
	}
	return nil, dropMeshNotLocal
}

// sender returns the entry with tag from the Presence call of s that has the
// route of src, or the reason that there is none. Router.mu must be held.
func (p *presence) sender(r *Router, s *MeshSession, tag uint32, src netip.Addr) (*presenceEntry, dropReason) {
	// The entries that the relay keeps of a session that ended give no sender.
	if s.Context().Err() != nil {
		return nil, dropMeshOldSession
	}
	return p.tagged(s, tag, dropMeshSource, func(e *presenceEntry) bool {
		o := r.ownerOf(e.vpc, src)
		return o.s != nil && o.s.home == s.name && o.origin == e.id
	})
}

// tagged returns the first entry with tag from the Presence call of s that ok
// accepts. With none, it returns the reason: miss if ok accepted no entry.
func (p *presence) tagged(s *MeshSession, tag uint32, miss dropReason, ok func(*presenceEntry) bool) (*presenceEntry, dropReason) {
	p.mu.Lock()
	defer p.mu.Unlock()
	reason := dropMeshUnknownTag
	in := p.in[s.name]
	if in == nil {
		return nil, reason
	}
	for _, e := range in.tags[tag] {
		// An older session of the member can have given the tag to another agent.
		if in.sess != s || e.sess != s {
			if reason == dropMeshUnknownTag {
				reason = dropMeshOldSession
			}
			continue
		}
		if ok(e) {
			return e, 0
		}
		reason = miss
	}
	return nil, reason
}
