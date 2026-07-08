// SPDX-License-Identifier: AGPL-3.0-only

// Package names is the single owner of the workerd resident naming scheme.
//
// The resident's sandbox id, its host AF_UNIX socket path, and the Envoy
// cluster that dials that socket form a cross-component contract: the manager
// (pkg/workerd/host, pkg/workerd/manager) creates the sandbox and socket, and
// the gateway's xDS translator (pkg/gateway/xds/translator) independently
// emits the cluster pointing at the same path — in a different process, on a
// different node role, from a different repo (apoxy-cloud's shared backplane).
// Every derivation therefore lives here and ONLY here; tests pin the exact
// byte values so the two sides cannot drift.
//
// Tenancy: a tenant is a project UUID (the shared backplane's multicluster
// cluster name / per-project route namespace). The empty tenant "" is the
// single-project topology (apoxy dev, dedicated mode) and reproduces the
// legacy constants byte-for-byte.
package names

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

const (
	// ResidentPrefix is the stem of every resident sandbox id and Envoy
	// cluster name.
	ResidentPrefix = "apoxy-workerd-resident"
	// DefaultStateDir is workerd-manager's default --state_dir
	// (pkg/workerd/manager.Run). The xDS translator composes socket paths over
	// this constant because it cannot observe the manager's flags; overriding
	// --state_dir under a fronting Envoy is unsupported.
	DefaultStateDir = "/run/workerd-manager/state"
)

// ResidentID returns the per-tenant resident sandbox id: the legacy constant
// "apoxy-workerd-resident" for the empty tenant, else
// "apoxy-workerd-resident-<tenant>". Dash-separated (not slash) because the id
// doubles as a filesystem name (runsc state dir, staging dir, socket file).
func ResidentID(tenant string) sandbox.SandboxID {
	if tenant == "" {
		return sandbox.SandboxID(ResidentPrefix)
	}
	return sandbox.SandboxID(ResidentPrefix + "-" + tenant)
}

// ResidentClusterName returns the Envoy cluster name for a tenant's resident:
// the legacy "apoxy-workerd-resident" for the empty tenant, else
// "apoxy-workerd-resident/<tenant>". Slash-separated to match the
// "<type>/<namespace>/..." cluster-name idiom, so SplitN(name, "/", 3)[1]
// yields the project UUID exactly as it does for route-derived clusters.
func ResidentClusterName(tenant string) string {
	if tenant == "" {
		return ResidentPrefix
	}
	return ResidentPrefix + "/" + tenant
}

// ResidentSocketPath returns the host AF_UNIX path Envoy dials for a tenant's
// resident. An empty stateDir means DefaultStateDir. The path must stay under
// the ~108-byte sun_path limit; names_test.go guards the budget.
func ResidentSocketPath(stateDir, tenant string) string {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	return sandbox.InboundSockPath(stateDir, ResidentID(tenant))
}

// ValidateTenant accepts the empty tenant (single-project topologies) or a
// canonical lowercase UUID (project IDs). Anything else is rejected: the
// tenant flows into filesystem paths, runsc sandbox ids, and Envoy cluster
// names, so a malformed value means a broken upstream invariant (e.g. the
// shared backplane's route-namespace rewrite) — fail loudly, never sanitize.
func ValidateTenant(tenant string) error {
	if tenant == "" {
		return nil
	}
	id, err := uuid.Parse(tenant)
	if err != nil {
		return fmt.Errorf("tenant %q is not a project UUID: %w", tenant, err)
	}
	if id.String() != tenant {
		return fmt.Errorf("tenant %q is not in canonical lowercase UUID form", tenant)
	}
	return nil
}
