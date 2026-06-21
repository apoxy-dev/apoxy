//go:build linux

package sandbox

import (
	"path/filepath"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const ociSpecVersion = "1.0.0"

// buildSpec returns the OCI runtime spec for a sandbox. Args and Env are
// baked in here because runsc's Start has no per-call override — the spec
// on disk is the final word.
//
// NetworkNamespace is explicitly pinned to the host's netns. Under
// --network=plugin, runsc otherwise creates a fresh empty netns for the
// Sentry — see
// https://github.com/apoxy-dev/gvisor/blob/5d6cfb0c0960/runsc/sandbox/sandbox.go#L1045-L1053
// — which would strand the Sentry's forwarder dials (DNS upstream
// resolvers, IMDS bridge on 127.0.0.1, egress MITM bridge), all reached
// via Linux net.Dial from inside the Sentry process. Pinning to
// /proc/self/ns/net resolves (in runsc) to runsc's own netns, which is
// inherited from the host; the Sentry then setns()es into that same netns
// and gains reachability to 127.0.0.1:<port>. The sandboxed application
// never touches the host's netns — it only sees the in-Sentry PluginStack
// — so this doesn't widen the security perimeter.
func buildSpec(
	id, rootfs string,
	args, env []string,
	cpuMillis, memBytes int64,
	mounts []Mount,
	annotations map[string]string,
) *specs.Spec {
	caps := []string{"CAP_NET_BIND_SERVICE"}

	spec := &specs.Spec{
		Version: ociSpecVersion,
		Process: &specs.Process{
			User: specs.User{UID: 0, GID: 0},
			Args: args,
			Env:  env,
			Cwd:  "/",
			Capabilities: &specs.LinuxCapabilities{
				Bounding:  caps,
				Effective: caps,
				Permitted: caps,
				Ambient:   caps,
			},
			NoNewPrivileges: true,
			Rlimits: []specs.POSIXRlimit{
				{Type: "RLIMIT_NOFILE", Hard: 1024, Soft: 1024},
			},
		},
		Root: &specs.Root{
			Path:     rootfs,
			Readonly: true,
		},
		Hostname:    id,
		Mounts:      append(defaultSpecMounts(), mountsToSpec(mounts)...),
		Annotations: annotations,
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.MountNamespace},
				{Type: specs.UTSNamespace},
				{Type: specs.IPCNamespace},
				{Type: specs.PIDNamespace},
				{Type: specs.CgroupNamespace},
				{Type: specs.NetworkNamespace, Path: "/proc/self/ns/net"},
			},
			MaskedPaths: []string{
				"/proc/kcore",
				"/sys/firmware",
			},
			ReadonlyPaths: []string{
				"/proc/sys", "/proc/sysrq-trigger", "/proc/irq", "/proc/bus",
			},
			Resources:   &specs.LinuxResources{},
			CgroupsPath: filepath.Join("/system", id),
		},
	}

	// Linux.Resources is cosmetic under --ignore-cgroups — runsc never
	// reads it. Real per-sandbox enforcement happens in the host-owned
	// cgroup at <host>/system/<id> (see createSandboxCgroup); we still
	// populate the OCI block so the on-disk config.json matches what the
	// kernel is actually enforcing, which keeps `runsc state` / config
	// dumps useful during post-mortem.
	if memBytes > 0 {
		v := memBytes
		spec.Linux.Resources.Memory = &specs.LinuxMemory{Limit: &v}
	}
	if cpuMillis > 0 {
		quota, period := cpuMaxFor(cpuMillis)
		p := uint64(period)
		spec.Linux.Resources.CPU = &specs.LinuxCPU{Quota: &quota, Period: &p}
	}

	return spec
}

// mountsToSpec converts the neutral [Mount] slice into OCI runtime-spec
// mounts. An empty Type defaults to "bind" (the common case for the
// extension-seam mounts an embedder layers on).
func mountsToSpec(mounts []Mount) []specs.Mount {
	out := make([]specs.Mount, 0, len(mounts))
	for _, m := range mounts {
		typ := m.Type
		if typ == "" {
			typ = "bind"
		}
		out = append(out, specs.Mount{
			Destination: m.Destination,
			Source:      m.Source,
			Type:        typ,
			Options:     m.Options,
		})
	}
	return out
}

// resolveProcessArgs returns command (else the image entrypoint), with
// extra appended. Baked into the OCI spec at Create time — runsc's Start
// has no per-call override.
func resolveProcessArgs(command, extra, entrypoint []string) []string {
	var args []string
	if len(command) > 0 {
		args = append(args, command...)
	} else {
		args = append(args, entrypoint...)
	}
	return append(args, extra...)
}

func defaultSpecMounts() []specs.Mount {
	return []specs.Mount{
		{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"noexec", "nosuid", "nodev"}},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755"}},
		{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"ro", "noexec", "nosuid", "nodev"}},
		{Destination: "/sys/fs/cgroup", Type: "cgroup", Source: "cgroup", Options: []string{"ro", "noexec", "nosuid", "nodev", "relatime"}},
		{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"}},
		{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=1777", "size=100M"}},
	}
}
