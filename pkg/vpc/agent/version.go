// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// ErrUpgrade is the error when this agent is too old for a relay.
// Run returns it when a relay refuses the agent: the user must upgrade.
var ErrUpgrade = errors.New("agent needs an upgrade")

// upgradeError is an ErrUpgrade with its cause.
type upgradeError struct{ detail string }

func (e *upgradeError) Error() string { return ErrUpgrade.Error() + ": " + e.detail }
func (e *upgradeError) Unwrap() error { return ErrUpgrade }

// relayUpgrade returns err as an ErrUpgrade when the relay at addr closed the
// session with UPGRADE.
func relayUpgrade(addr string, err error) error {
	var ae *quic.ApplicationError
	if errors.As(err, &ae) && ae.Remote && ae.ErrorCode == quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_UPGRADE) {
		return &upgradeError{fmt.Sprintf("relay %s: %s", addr, ae.ErrorMessage)}
	}
	return err
}

// relayRevision returns an error when the relay revision is below the
// minimum of the agent. Nil is revision 0.
func relayRevision(relay, agent *dp.Version) error {
	if got, least := relay.GetRevision(), agent.GetMinRevision(); got < least {
		return fmt.Errorf("relay revision %d is below the agent minimum %d", got, least)
	}
	return nil
}
