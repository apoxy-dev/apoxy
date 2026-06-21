package sandbox

import "context"

// Runtime is the tenant-neutral gVisor/runsc sandbox lifecycle seam — the
// spine's load-bearing interface. The production implementation is *Manager;
// unit tests and the downstream stubs that land first against this interface —
// ServiceManager (APO-796), workerd-host (APO-625), the egress config sink
// (APO-723) — implement it with a fake until the real manager arrives.
//
// The methods correspond 1:1 to clrk's worker sandbox manager. The interface
// exists so callers off-platform (darwin) and in tests can name the seam
// without the linux-only runsc plumbing, exactly as clrk's agents.SandboxRuntime
// does — but here the three egress setters are split out into the optional
// [EgressController] extension so the core stays tenant- and egress-neutral and
// clrk's internal wrapper owns the egress data path.
type Runtime interface {
	// Create pulls Spec.Image (ORAS), extracts the rootfs, builds the OCI
	// bundle and runs `runsc create`. The returned Instance is in phase Ready
	// (created, not started). Returns [ErrAlreadyExists] if Spec.ID is live.
	Create(ctx context.Context, spec Spec) (*Instance, error)

	// Start runs `runsc start`: the Sentry boots, the sentrystack PluginStack
	// is initialized (loopback NIC + inbound forwarder), and the guest process
	// is forked. Moves the instance Ready -> Running.
	Start(ctx context.Context, id SandboxID) error

	// Stop sends SIGTERM and moves the instance Running -> Stopping. It does
	// NOT block for exit: the caller polls Status / Wait for the eventual
	// transition to Stopped (the graceful-drain loop lives above the seam, as
	// it does in clrk). The instance lands in Stopped synchronously only if it
	// had already exited before the signal.
	Stop(ctx context.Context, id SandboxID) error

	// Kill sends SIGKILL — the non-graceful stop.
	Kill(ctx context.Context, id SandboxID) error

	// Wait blocks until the guest process exits and returns its exit code.
	Wait(ctx context.Context, id SandboxID) (exitCode int, err error)

	// Delete tears down the runsc container and frees its on-host state
	// (rootfs, cgroup, bundle). Returns [ErrNotFound] if the id is unknown.
	Delete(ctx context.Context, id SandboxID) error

	// Purge is the best-effort, error-swallowing teardown used on cleanup
	// paths where a hung Delete must not pin the caller. It never returns an
	// error by design.
	Purge(ctx context.Context, id SandboxID)

	// Status returns the current Instance for id, or [ErrNotFound].
	Status(ctx context.Context, id SandboxID) (*Instance, error)

	// List returns a snapshot of all live instances.
	List() []*Instance

	// Cleanup reconciles on-host runsc state against the in-process instance
	// table, reaping orphans left by a previous host incarnation.
	Cleanup(ctx context.Context) error
}
