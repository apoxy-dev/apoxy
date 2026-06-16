// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/clrk/pkg/sandbox"
)

const (
	// workerRootDir is the in-jail directory the bundle's modules layer
	// extracts to and where the generated config is bind-mounted, so module
	// embed paths are Module.Path relative to it. This is a bundle-format
	// contract with the builder (APO-700).
	workerRootDir = "/worker"
	// configFileName is the generated workerd config, co-located with the
	// modules so workerd `embed` paths resolve relatively.
	configFileName = "config.capnp"
)

// inJailConfigPath is where the generated config is mounted inside the sandbox.
func inJailConfigPath() string {
	return filepath.Join(workerRootDir, configFileName)
}

// assetsDir is the in-jail path the assets disk service serves, or "" if the
// bundle has no assets.
func assetsDir(m computev1alpha1.BundleManifest) string {
	if m.AssetsPrefix == "" {
		return ""
	}
	return filepath.Join(workerRootDir, "assets")
}

// sandboxID is the per-(tenant,revision) sandbox identifier. Distinct per
// customer and revision, which makes per-customer isolation hold by
// construction: the core allocates a fresh sandbox network, cgroup, and Sentry
// per id.
func sandboxID(tenant, revision string) sandbox.SandboxID {
	return sandbox.SandboxID(tenant + "/" + revision)
}

// bundleImageRef builds the OCI reference Create pulls — digest-pinned when a
// digest is set (the serving path is digest-addressed and immutable).
func bundleImageRef(b computev1alpha1.BundleRef) (string, error) {
	if b.Repo == "" {
		return "", fmt.Errorf("workerd-host: bundle has no repo")
	}
	if b.Digest != "" {
		return b.Repo + "@" + b.Digest, nil
	}
	if b.Tag != "" {
		return b.Repo + ":" + b.Tag, nil
	}
	return "", fmt.Errorf("workerd-host: bundle %q has neither digest nor tag", b.Repo)
}

// buildSpec maps a resident request to the sandbox.Spec that runs stock workerd.
func buildSpec(id sandbox.SandboxID, imageRef string, want ResidentRef, cfgHostPath string) sandbox.Spec {
	return sandbox.Spec{
		ID:    id,
		Image: imageRef,
		// Stock workerd: serve the reconstructed config. --platform=systrap
		// because KVM is unavailable inside gVisor.
		Command: []string{"workerd", "serve", inJailConfigPath(), "--platform=systrap"},
		Env:     workerdEnv(want.Config),
		Mounts: []sandbox.Mount{
			// The rootfs is read-only and digest-shared, so the generated
			// config cannot be written into it — it rides in as a bind mount.
			{Source: cfgHostPath, Destination: inJailConfigPath(), Type: "bind", Options: []string{"ro"}},
		},
		// Resident socket server: no caller stdio.
		Stdio: false,
		// M1 backend mode: lo+eth0, direct dial, no egress forwarder.
		Egress: sandbox.EgressInit{},
		// Ingress (APO-694): the worker's http socket binds inside the
		// in-Sentry netstack with no host route, so opt the sandbox into the
		// inbound forwarder. The core opens a host AF_UNIX socket fronting the
		// worker (surfaced as Instance.InboundSocket) that an Envoy upstream
		// cluster — or the acceptance test — dials. Empty for non-HTTP sockets.
		InboundListenAddr: hostInboundAddr(want.Socket),
	}
}

// hostInboundAddr is the in-sandbox "ip:port" the inbound forwarder dials to
// reach the resident worker, derived from the worker's listening socket. The
// worker's http socket binds "*:<port>" (all in-Sentry interfaces), so the
// forwarder dials it on loopback — 127.0.0.1 is always present, even before
// eth0 addressing, and a wildcard listener accepts the loopback destination.
// Returns "" for a non-HTTP socket (filter/UDS), which leaves the sandbox
// without a TCP ingress forwarder.
func hostInboundAddr(sock SocketSpec) string {
	if sock.Kind != HTTPSocket {
		return ""
	}
	_, port, err := net.SplitHostPort(sock.Addr)
	if err != nil || port == "" {
		return ""
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// workerdEnv is the process environment for the workerd binary itself (NOT the
// worker's bindings, which live in the capnp config). M1 passes none.
func workerdEnv(cfg computev1alpha1.ServiceConfigSpec) []string {
	return nil
}

// stageConfig writes the generated capnp to a host path that is bind-mounted
// into the sandbox. The rootfs is read-only and digest-shared, so the config
// cannot be written into it directly.
func stageConfig(rootDir string, id sandbox.SandboxID, capnp string) (string, error) {
	dir := filepath.Join(rootDir, sanitizeID(id))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating config stage dir: %w", err)
	}
	path := filepath.Join(dir, configFileName)
	if err := os.WriteFile(path, []byte(capnp), 0o644); err != nil {
		return "", fmt.Errorf("writing config: %w", err)
	}
	return path, nil
}

// sanitizeID makes a sandbox id filesystem-safe (the id contains '/').
func sanitizeID(id sandbox.SandboxID) string {
	return strings.ReplaceAll(string(id), "/", "_")
}
