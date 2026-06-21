// Package sandbox is the tenant-neutral gVisor/runsc sandbox runtime spine
// shared by apoxy's workerd host and the clrk agent worker.
//
// It is the neutral CORE: the bare
// pull -> OCI bundle -> runsc -> cgroup-v2 -> sentrystack-loopback lifecycle,
// with the agent-lineage, identity, egress, trust and persistent-state
// coupling kept OUT. It lives here in apoxy as the lower, foundational layer
// so that both consumers depend in one direction (consumer -> core) and the
// repos never form a dependency cycle:
//
//   - apoxy's own workerd host (pkg/workerd/host, cmd/workerd-*) imports it
//     in-tree for a bare single-tenant, inbound-capable sandbox — a workerd
//     sandbox is just an OCI image whose [Spec.Command] is `workerd serve`.
//   - clrk's internal/worker/sandbox re-points onto this package across the
//     module boundary (clrk's apoxy pin) and layers the tenant/egress concerns
//     back on as a thin wrapper, so the agent worker keeps its full
//     egress-capable behavior.
//
// One source of truth, not a second copy.
//
// The seam is the [Runtime] interface — the tenant-neutral lifecycle
// (Create/Start/Stop/Kill/Wait/Delete/Purge/Status/List/Cleanup) — plus the
// optional [EgressController] extension. Above the seam is policy + fan-out
// (which tenant, which revision, how many resident); below it is mechanism
// (ORAS pull, OCI bundle, runsc, cgroup-v2, the sentrystack loopback NIC).
// Nothing below the seam knows about tenants, Kubernetes, or revisions. The
// tenant wrapper in clrk's internal/worker/sandbox plugs egress, identity,
// trust and persistent state back in through the core's extension seams
// ([Spec.Mounts], the [EgressController] setters, the sentrystack init
// payload).
package sandbox
