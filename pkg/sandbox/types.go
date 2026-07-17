package sandbox

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"time"

	"oras.land/oras-go/v2/registry/remote/auth"
)

// SandboxID uniquely identifies a sandbox instance within a host.
type SandboxID string

// SandboxPhase is the lifecycle phase of a sandbox.
type SandboxPhase string

const (
	// SandboxCreating is set while Create is pulling/extracting/bundling.
	SandboxCreating SandboxPhase = "Creating"
	// SandboxReady is a created-but-not-started sandbox (the resident-pool
	// warm state): runsc create has run, the guest has not been forked.
	SandboxReady SandboxPhase = "Ready"
	// SandboxRunning is an active sandbox: runsc start has forked the guest.
	SandboxRunning SandboxPhase = "Running"
	// SandboxStopping is a sandbox that has been signalled and is awaiting exit.
	SandboxStopping SandboxPhase = "Stopping"
	// SandboxStopped is an exited sandbox (not yet Deleted).
	SandboxStopped SandboxPhase = "Stopped"
)

var (
	// ErrAlreadyExists is returned by Create when a sandbox with the given ID
	// is already live.
	ErrAlreadyExists = errors.New("sandbox already exists")
	// ErrNotFound is returned when no sandbox with the given ID exists.
	ErrNotFound = errors.New("sandbox not found")
)

// Spec is the per-call input to [Runtime.Create]. It is the tenant-neutral
// core of clrk's sandbox.CreateRequest: the CRD-shaped AgentSandbox /
// ExecutionResources, the []corev1.EnvVar, the proxyproto.AgentIdentity, the
// CAPEM trust bundle and the persistent AgentState are all kept out of the
// core (the four de-contamination seams of §3.6) so the spine carries no
// agent-lineage, identity, trust, or Kubernetes coupling. clrk's internal
// wrapper adapts its CRD CreateRequest down to this Spec; an external caller
// describes a sandbox purely as "this OCI image, run this argv with this env
// under these cgroup limits, with these extra mounts".
type Spec struct {
	// ID is the caller-assigned sandbox identifier. Must be unique among live
	// sandboxes on the host; Create returns [ErrAlreadyExists] otherwise.
	ID SandboxID

	// Image is the OCI image reference the runtime pulls (ORAS) and extracts
	// into the sandbox rootfs. For workerd this is the bundle image whose
	// command is `workerd serve`.
	Image string

	// ImagePullCredential authenticates the Image pull against a private
	// registry. The zero value pulls anonymously.
	ImagePullCredential auth.Credential

	// Command overrides the image entrypoint (argv from index 0). Empty uses
	// the image's own entrypoint. (Adapted from clrkv1alpha1.AgentSandbox.)
	Command []string

	// Args are appended after Command.
	Args []string

	// Env is the process environment as "KEY=VALUE" strings. Adapted from
	// clrk's []corev1.EnvVar — the core carries no Kubernetes core types.
	Env []string

	// CPUMillis is the cgroup-v2 cpu.max budget in milli-CPU (1000 == one
	// core). Zero leaves cpu.max at "max". Adapted from
	// ExecutionResources.CPU.MilliValue().
	CPUMillis int64

	// MemBytes is the cgroup-v2 memory.max budget in bytes. Zero leaves
	// memory.max at "max". Adapted from ExecutionResources.Memory.Value().
	MemBytes int64

	// Mounts are extra mounts layered onto the default OCI mount set inside
	// the jail (e.g. a bundle config dir, a UDS directory). This is the
	// extension seam clrk's wrapper uses to re-add trust and persistent-state
	// bind mounts without the core knowing about them.
	Mounts []Mount

	// Stdio requests caller-facing stdio pipes on the resulting Instance
	// (Instance.Stdin/Stdout/Stderr). A resident socket-server workerd does
	// not need them; one-shot stdio callers do.
	Stdio bool

	// Annotations are OCI annotations stamped onto the container config.
	// clrk's wrapper computes agent-lineage labels here; the core treats
	// them as opaque key/value metadata (recoverable out-of-band via
	// `runsc state`). Nil is fine.
	Annotations map[string]string

	// Egress carries the opaque sentrystack egress-routing fields an
	// egress-capable embedder wants merged into the per-sandbox init
	// payload. The core stamps only the addressing fields it computes
	// itself (eth0 IP/MAC, gateway) and copies these through verbatim;
	// it never acts on them. Zero value = a sandbox with lo + eth0 and
	// no egress routing (direct dial), which is the standalone-core path.
	Egress EgressInit

	// InboundListenAddr opts the sandbox into the ingress path: the
	// in-sandbox "ip:port" a resident server listens on (e.g.
	// "127.0.0.1:8080"). When set, Create seals it into the sentrystack
	// init payload (InboundListenAddr + InboundFDIndex) before the Sentry
	// boots, and Start opens a host AF_UNIX listening socket fronting the
	// resident server, donating its fd so the in-Sentry inbound forwarder
	// can accept on it. The host socket path is surfaced on
	// [Instance.InboundSocket]. Unlike [Spec.Egress] this is tenant-neutral
	// and acted on by the core directly, so a standalone consumer
	// (workerd-host) gets ingress with no egress installer. Empty keeps the
	// sandbox egress-only.
	//
	// It must be set here, not on the returned Instance: Create seals the
	// initStr before returning, so a value assigned post-Create never
	// reaches the Sentry's PreInit and the forwarder silently never installs.
	InboundListenAddr string

	// ControlForwardAddr opts the sandbox into the control path: the in-sandbox
	// "ip:port" a resident dispatcher dials to reach the host manager's control
	// server (e.g. "127.0.0.2:80", distinct from InboundListenAddr's 127.0.0.1
	// data socket). When set together with ControlHostAddr, Create seals both
	// into the sentrystack init payload and the in-Sentry control forwarder
	// accepts the dispatcher's connections on an in-stack listener and splices
	// each to the host control listener. Like InboundListenAddr this is
	// tenant-neutral and acted on by the core; unlike inbound it needs no fd
	// donation — the Sentry shares the host net namespace and dials the manager's
	// loopback control listener directly. Empty leaves the sandbox without a
	// control plane.
	//
	// Like InboundListenAddr it must be set here, not on the returned Instance:
	// Create seals the initStr before returning.
	ControlForwardAddr string

	// ControlHostAddr is the HOST loopback "ip:port" of the manager's control
	// server (TCP) the in-Sentry control forwarder dials for each guest
	// connection to ControlForwardAddr. TCP, not AF_UNIX: the Sentry's plugin
	// seccomp filter only allows socket() for AF_INET/AF_INET6, so a host unix
	// dial from inside the Sentry returns ENOSYS. Empty (regardless of
	// ControlForwardAddr) disables control forwarding.
	ControlHostAddr string
}

// EgressInit is the opaque set of sentrystack egress-routing fields a
// [Spec] carries for an egress-capable embedder (clrk's wrapper). The
// core never acts on them — it copies them into the per-sandbox init
// payload the in-Sentry forwarder reads. Mirrors the egress fields of
// sentrystack.InitStr; kept as a flat neutral struct so the core Spec
// surface doesn't grow IMDS/MITM vocabulary of its own.
type EgressInit struct {
	// IMDSHostAddr is the host-bound IMDS dial target (e.g.
	// "127.0.0.1:<port>") the in-Sentry forwarder dials for IMDS traffic.
	IMDSHostAddr string
	// EgressHostAddr is the host-bound egress dial target for every
	// non-IMDS, non-DNS outbound stream.
	EgressHostAddr string
	// IMDSV4 / IMDSV6 are the link-local IMDS addrs ("ip:port") the
	// forwarder matches outbound dst against to route IMDS-vs-direct.
	IMDSV4 string
	IMDSV6 string
	// DNSResolvers is the host-side resolver list the forwarder dials for
	// outbound :53. An entry is either "ip:port" or "unix://<socket>" — the
	// resident's per-sandbox unixgram DNS listener, "@"-prefixed for the
	// Linux abstract namespace so it stays dialable from the chrooted Sentry.
	DNSResolvers []string
}

// Mount is one extra mount layered into the sandbox rootfs. It maps directly
// to an OCI runtime-spec mount in the manager's buildSpec.
type Mount struct {
	// Source is the host path (for a bind) or fs source ("tmpfs", "proc", ...).
	Source string
	// Destination is the in-sandbox mount point.
	Destination string
	// Type is the mount type ("bind", "tmpfs", ...). Empty defaults to "bind".
	Type string
	// Options are mount options (e.g. "ro", "nosuid", "rbind").
	Options []string
}

// Instance is the runtime's view of a single live sandbox. It is the neutral
// core of clrk's sandbox.Instance: the CRD AgentSandbox / ExecutionResources
// snapshots, the proxyproto.AgentIdentity, and the agent-lineage
// AgentRef/Namespace fields are kept on clrk's wrapper, not here (§3.6).
type Instance struct {
	// ID is the sandbox identifier from [Spec.ID].
	ID SandboxID

	// Phase is the current lifecycle phase.
	Phase SandboxPhase

	// RootFS is the extracted rootfs path on the host.
	RootFS string

	// SandboxIP is the per-sandbox container IP written into the in-Sentry
	// PluginStack eth0 via the sentrystack init payload.
	SandboxIP netip.Addr

	// InboundSocket is the host filesystem path of the AF_UNIX listening
	// socket that fronts the in-sandbox resident server, set at Start when
	// [Spec.InboundListenAddr] was requested. Callers on the host (an Envoy
	// upstream cluster, the backplane bridge, or an acceptance test) dial
	// this path to reach the in-sandbox listener — there is no host route to
	// the in-Sentry SandboxIP, so this socket is the ingress entry point.
	// Empty when the sandbox is egress-only.
	InboundSocket string

	// GatewayIP is the per-sandbox default-route gateway. Cosmetic under
	// sentrystack (the in-Sentry forwarder never delivers frames to it) but
	// exposed so `ip route` inside the sandbox shows a sane default route and
	// so /etc/resolv.conf has a destination that triggers the in-Sentry DNS
	// forwarder.
	GatewayIP netip.Addr

	// Stdin/Stdout/Stderr are populated only when the sandbox was Created with
	// [Spec.Stdio] true; nil otherwise.
	Stdin  io.WriteCloser
	Stdout io.ReadCloser
	Stderr io.ReadCloser

	// CreatedAt is when Create completed.
	CreatedAt time.Time

	// stdioPipes groups the host-side stdio plumbing FDs of the sandbox.
	// Embedded so references promote (sb.stdoutChild, sb.stdoutToCaller,
	// ...). Allocated in Create by wireSandboxStdio, torn down by closeStdio.
	stdioPipes

	// initStr is the per-sandbox sentrystack payload computed at Create.
	// Retained on the instance so Start can re-pass it through the
	// runsc-start subprocess's env — gVisor calls PluginStack.PreInit from
	// inside `runsc start` (not `runsc create`), so the create-time env
	// doesn't reach where PreInit reads it.
	initStr string

	// inboundListenAddr mirrors [Spec.InboundListenAddr], stashed at Create
	// so Start knows whether to open + donate the host inbound listener.
	// Empty = egress-only.
	inboundListenAddr string

	// controlForwardAddr / controlHostAddr mirror [Spec.ControlForwardAddr] /
	// [Spec.ControlHostAddr], stashed at Create so buildSandboxInitStr can seal
	// them into the per-sandbox initStr. Empty = no control plane. Unlike inbound
	// they need no Start-time action (no fd donation), so they are read only at
	// Create.
	controlForwardAddr string
	controlHostAddr    string
}

// stdioPipes groups the host-side stdio plumbing FDs of an [Instance].
// Embedded into Instance so call sites that reach for sb.stdinChild /
// sb.stdoutToCaller / etc. keep working via field promotion.
//
// stdinChild / stdoutChild / stderrChild are the Sentry-facing ends:
// passed to the runsc-create subprocess as its cmd.Stdin/Stdout/Stderr so
// the subprocess donates them to the Sentry boot child.
//
// stdoutInternalR / stderrInternalR are the host-side read ends of the
// Sentry's stdout/stderr pipes. drainSentryStdio reads from these and fans
// bytes out to the log sink and (in stdio mode) the caller-facing outer pipe.
//
// stdoutToCaller / stderrToCaller are the write ends of the caller-facing
// outer pipes (paired with sb.Stdout / sb.Stderr). Only allocated when
// Stdio is true; nil otherwise so the drain goroutine skips the caller fan-out.
type stdioPipes struct {
	stdinChild      *os.File
	stdoutChild     *os.File
	stderrChild     *os.File
	stdoutInternalR *os.File
	stderrInternalR *os.File
	stdoutToCaller  *os.File
	stderrToCaller  *os.File
}
