// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"fmt"
	"log/slog"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// checkRevision keeps the version v of the agent of s. It closes a session
// below the minimum of the relay with UPGRADE and the minimum in the reason.
func (r *Router) checkRevision(s *Session, v *dp.Version) error {
	if got, least := v.GetRevision(), r.ver.GetMinRevision(); got < least {
		msg := fmt.Sprintf("agent revision %d is below the relay minimum %d", got, least)
		slog.Info("Refused relay session of an old agent", "agent", s.id.ID,
			"revision", got, "min_revision", least, "build", buildLabel(v.GetBuild()))
		s.close(dp.RelayCloseCode_RELAY_CLOSE_CODE_UPGRADE, msg)
		return rpc.Errorf(rpc.FailedPrecondition, "%s", msg)
	}
	r.mu.Lock()
	s.version = v
	r.mu.Unlock()
	return nil
}

// agentAtLeast reports whether the agent of s is at revision n or later. It
// is false for n above 0 before Hello.
func (r *Router) agentAtLeast(s *Session, n uint32) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return s.version.GetRevision() >= n
}
