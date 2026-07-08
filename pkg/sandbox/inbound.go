// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import "path/filepath"

// InboundSockPath returns the host filesystem path of the AF_UNIX listening
// socket that fronts a sandbox's resident server. Lives under the runsc state
// dir alongside the rest of the per-sandbox state. Kept short to stay under
// the 108-byte sun_path limit — callers composing ids into this path (see
// pkg/workerd/names) guard the budget with tests.
//
// Exported (and kept build-tag free) because the path is a cross-component
// contract: the manager creates the socket here and the gateway's xDS
// translator emits the same path into the resident Envoy cluster on any
// platform.
func InboundSockPath(stateDir string, id SandboxID) string {
	return filepath.Join(stateDir, string(id)+".in.sock")
}
