// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/keys"

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
	// statusMsg has the state of a home session for the snapshot.
	statusMsg struct {
		s  *session
		st sessState
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
	// from a RouteDelta has delta set, and the root answers routesDone.
	routesMsg struct {
		s           *session
		add, remove []netip.Prefix
		first       bool
		delta       bool
		rev         uint64
	}
	reportMsg struct {
		s    *session
		peer *psp.Peer
		sas  []psp.SACount
	}
	offerMsg struct {
		s       *session
		peer    *psp.Peer
		attempt uint64
	}
	refusedMsg struct {
		s       *session
		peer    *psp.Peer
		attempt uint64
		spis    []uint32
	}
	applyMsg struct {
		s       *session
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

// sessState is the state of a home session that the root keeps.
type sessState struct {
	attached       bool
	link           *psp.Link
	peer           *psp.Peer
	base           Attachment
	mode           dp.Mode
	reason         dp.FallbackReason
	connect, setup time.Duration
	rtt            *atomic.Int64
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
