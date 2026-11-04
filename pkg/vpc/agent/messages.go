// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"net/netip"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/quic-go/quic-go"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The messages between the processes of the agent. A message up from a session
// names the session in s.

// endMsg is the last message from a parent to a child: the child ends.
type endMsg struct{}

// taskDone is the result of a task of a process.
type taskDone struct{ m any }

// Root to a home session.
type (
	// attachX asks for the extra attachment spec. ctx is the context of the
	// caller of Attach, or nil.
	attachX struct {
		spec *AttachmentSpec
		ctx  context.Context
	}
	// detachX removes the extra attachment spec. ctx is the context of the
	// caller of Detach, or nil.
	detachX struct {
		spec *AttachmentSpec
		ctx  context.Context
	}
	// cancelX tells that the caller of Attach of spec stopped to wait.
	cancelX struct{ spec *AttachmentSpec }
	// bindingMsg answers bindMsg.
	bindingMsg struct {
		b   *psp.Binding
		err error
	}
	// clampedMsg tells that the clamp of the attempt is in the binding.
	clampedMsg struct {
		peer    *psp.Peer
		attempt uint64
	}
	// routesDone tells that the callback of the routes of the delta rev returned.
	routesDone struct{ rev uint64 }
	// rekeyMsg has new receive SAs for the relay peer. Attempt 0 is a renewal.
	rekeyMsg struct {
		peer    *psp.Peer
		attempt uint64
		req     keys.Request
		err     error
	}
	// appliedMsg is the result of the transmit SAs of an applyMsg.
	appliedMsg struct {
		peer    *psp.Peer
		attempt uint64
		refused []uint32
		err     error
	}
)

// A session to its parent.
type (
	// sessAttached has the state of a home session at its attach. Later mode
	// changes go only in the mode value.
	sessAttached struct {
		s  *session
		st sessState
	}
	// upChanged has the keys of the up values of the session that changed.
	upChanged struct {
		s    *session
		keys []string
	}
	// bindMsg asks for the binding after the attach.
	bindMsg struct {
		s   *session
		cfg *dp.Config
	}
	// clampMsg reserves the path MTU of an attempt and asks for the clamp.
	clampMsg struct {
		s       *session
		peer    *psp.Peer
		attempt uint64
		mtu     int
	}
	// peerMode tells the mode of a relay peer after a change or an attempt.
	peerMode struct {
		s    *session
		peer *psp.Peer
		mode dp.Mode
	}
	// routesMsg is a change of the route table of a home session. A change
	// from a RouteDelta has delta set, and the root answers routesDone. first
	// is set at the end of the first table.
	routesMsg struct {
		s       *session
		changes []routeChange
		first   bool
		delta   bool
		rev     uint64
	}
	// offerMsg, refusedMsg and applyMsg are key operations on the relay peer of
	// a session, or on the direct peer of a pair when pr is set.
	offerMsg struct {
		s       *session
		pr      *pair
		peer    *psp.Peer
		attempt uint64
	}
	refusedMsg struct {
		s       *session
		pr      *pair
		peer    *psp.Peer
		attempt uint64
		spis    []uint32
	}
	applyMsg struct {
		s       *session
		pr      *pair
		peer    *psp.Peer
		attempt uint64
		req     keys.Request
	}
	// attachedX is the result of an attachX.
	attachedX struct {
		s    *session
		spec *AttachmentSpec
		at   Attachment
		err  error
	}
	// detachedX tells that a detachX ended.
	detachedX struct {
		s    *session
		spec *AttachmentSpec
	}
	drainedMsg struct {
		s    *session
		alts []endpoint
	}
	// sessEnded is the last message of a session, with its link (home only)
	// and its relay peer for the root to remove.
	sessEnded struct {
		s    *session
		err  error
		link *psp.Link
		peer *psp.Peer
	}
)

// Root to a pair. rekeyMsg and appliedMsg also go to a pair, for its direct peer.
type (
	// candidatesMsg has the newest own candidates and own list.
	candidatesMsg struct{ v *candsVal }
	// revocationsMsg has the last revocation list of each session.
	revocationsMsg struct{ v *revLists }
	// openOK opens the channel of a pairOpen, with the direct peer of the pair.
	openOK struct{ peer *psp.Peer }
	// dupMsg ends a pair: the root keeps another pair with the same peer.
	dupMsg struct{}
	// heldMsg tells a pair that is not open that an open pair holds its peer end. A pair with no
	// connection ends; a connection waits for its Hello, so that both agents keep one channel.
	heldMsg struct{}
	// identityMsg tells that the own cert changed.
	identityMsg struct{}
	// peerRemoved tells that the direct peer of the pair is out of the binding.
	peerRemoved struct{}
	// evictMsg ends a pair to free a place for a new one.
	evictMsg struct{}
	// useMsg tells that the pair had a use: a head to a prefix that it holds or a channel packet.
	useMsg struct{}
)

// A pair to the root.
type (
	// pairOpen asks to open the channel conn, whose Hello passed.
	pairOpen struct {
		p    *pair
		key  pairKey
		name string // Agent name of the peer cert.
		list []netip.Prefix
		conn connAddrs
	}
	// peerList is the newest list of the peer after pairOpen.
	peerList struct {
		p    *pair
		list []netip.Prefix
	}
	// pairStatus is the newest state of the pair for Status.
	pairStatus struct {
		p  *pair
		st pairState
	}
	// removePeerMsg asks the root to remove the direct peer of the pair, if it has one.
	removePeerMsg struct{ p *pair }
	// pairEnded is the last message of a pair.
	pairEnded struct{ p *pair }
)

// These keys name the values that a session writes for the root.
const (
	keyMode    = "mode"    // The value is a *modeState.
	keyReport  = "report"  // The value is an *rxReport.
	keyRevoked = "revoked" // The value is a *revokedList.
)

// revokedList is the newest revocation list that the relay of a session sent.
type revokedList struct {
	agents []vpcv1alpha1.RevokedAgent
}

// modeState is the data mode of a session and why it is in QUIC mode.
type modeState struct {
	mode   dp.Mode
	reason dp.FallbackReason
}

// rxReport is the newest receive report of the relay peer of a session. The
// counts only grow, so the root can skip a report.
type rxReport struct {
	peer *psp.Peer
	sas  []psp.SACount
}

// sessState is the state of a home session that the root keeps.
type sessState struct {
	attached       bool
	link           *psp.Link
	peer           *psp.Peer
	base           Attachment
	mode           dp.Mode
	reason         dp.FallbackReason
	connect, setup time.Duration
	stats          func() quic.ConnectionStats
	dnsServers     []string
	dnsSearch      []string
}

// The callbacks process and the root.
type (
	eventMsg struct {
		seq uint64
		fn  func()
	}
	doneMsg struct{ seq uint64 }
	cbEnded struct{}
)

// Public calls to the root.
type (
	attachReqMsg struct {
		spec  *AttachmentSpec
		ctx   context.Context
		reply chan attachReply
	}
	attachReply struct {
		at  Attachment
		err error
	}
	cancelReqMsg struct{ spec *AttachmentSpec }
	detachReqMsg struct {
		name  string
		ctx   context.Context
		reply chan error
	}
)

// identityEnded is the result of the identity loop.
type identityEnded struct{ err error }
