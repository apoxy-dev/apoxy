// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// ErrUpgrade is the error when this agent is too old for a relay, a peer or a
// grant. Run returns it when a relay refuses the agent: the user must upgrade.
var ErrUpgrade = errors.New("agent needs an upgrade")

// errRevision is the admit error for a peer whose revision is below the
// minimum of this agent.
var errRevision = errors.New("revision is too old")

// upgradeError is an ErrUpgrade with its cause.
type upgradeError struct{ detail string }

func (e *upgradeError) Error() string { return ErrUpgrade.Error() + ": " + e.detail }
func (e *upgradeError) Unwrap() error { return ErrUpgrade }

// relayUpgrade returns err as an ErrUpgrade when the relay at addr closed the
// session with UPGRADE, or when its grant needs a newer revision.
func relayUpgrade(addr string, err error) error {
	var ae *quic.ApplicationError
	switch {
	case errors.Is(err, relay.ErrGrantRevision):
		return &upgradeError{fmt.Sprintf("relay %s: %v", addr, err)}
	case errors.As(err, &ae) && ae.Remote && ae.ErrorCode == quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_UPGRADE):
		return &upgradeError{fmt.Sprintf("relay %s: %s", addr, ae.ErrorMessage)}
	}
	return err
}

// relayAtLeast reports whether the relay of rc is at revision n or later. The
// agent knows the revision from Welcome, before it makes another call.
func (rc *relayConn) relayAtLeast(n uint32) bool {
	return rc.version.GetRevision() >= n
}

// atLeast reports whether the peer is at revision n or later. Before Open
// passes, the peer is at revision 0.
func (p *peer) atLeast(n uint32) bool {
	select {
	case <-p.ready:
		return p.version.GetRevision() >= n
	default:
		return n == 0
	}
}

// checkRevision returns an errRevision when the revision of the peer p is
// below the minimum of this agent. The peer gets the text as the close reason.
func (a *Agent) checkRevision(p *peer, v *dp.Version) error {
	got, least := v.GetRevision(), a.ver.GetMinRevision()
	if got >= least {
		return nil
	}
	other, self := "dialer", "listener"
	if p.dialer {
		other, self = self, other
	}
	return fmt.Errorf("%w: %s revision %d is below the %s minimum %d", errRevision, other, got, self, least)
}

// refusedUpgrade returns the close reason when the peer closed qc with
// UPGRADE: this agent is below the minimum revision of the peer.
func refusedUpgrade(qc quic.Connection, err error) (string, bool) {
	var ae *quic.ApplicationError
	// quic-go ends the call streams before it sets the close cause.
	if !errors.As(err, &ae) && !errors.As(context.Cause(qc.Context()), &ae) {
		return "", false
	}
	return ae.ErrorMessage, ae.Remote && ae.ErrorCode == quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_UPGRADE)
}
