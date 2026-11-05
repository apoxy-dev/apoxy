// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
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
	if code, reason, ok := rpc.RemoteClose(nil, err); ok && code == quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_UPGRADE) {
		return &upgradeError{fmt.Sprintf("relay %s: %s", addr, reason)}
	}
	return err
}
