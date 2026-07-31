// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

const (
	// workerRootDir is the in-jail directory where the generated config is
	// bind-mounted.
	workerRootDir = "/worker"
	// configFileName is the generated binary Cap'n Proto config.
	configFileName = "config.bin"
)

// inJailConfigPath is where the generated config is mounted inside the sandbox.
func inJailConfigPath() string {
	return filepath.Join(workerRootDir, configFileName)
}

// BundleImageRef builds the digest-pinned OCI reference for a bundle, exported
// for the manager, which pulls a revision's modules to inline into the
// WorkerLoader payload.
func BundleImageRef(b computev1alpha1.BundleRef) (string, error) {
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

// hostInboundAddr is the in-sandbox "ip:port" the inbound forwarder dials to
// reach the resident worker. The worker's HTTP socket binds "*:<port>" (all
// in-Sentry interfaces), so the forwarder dials it on loopback. Returns "" for
// a Unix socket or an unparseable address.
func hostInboundAddr(addr string) string {
	// A "unix:/path" listener has no TCP host:port to forward. net.SplitHostPort
	// would mis-parse it as host="unix", port="/path", so guard it explicitly.
	if strings.HasPrefix(addr, "unix:") {
		return ""
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return ""
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// stagingDir is the single owner of the staged-config layout: both the create
// side (stageConfig) and the teardown side (ResidentHost.Stop) derive the path
// from it.
func stagingDir(rootDir string, id sandbox.SandboxID) string {
	return filepath.Join(rootDir, sanitizeID(id))
}

// stageConfig writes the generated binary config to a host path that is bind-mounted
// into the sandbox. The rootfs is read-only and digest-shared, so the config
// cannot be written into it directly.
func stageConfig(rootDir string, id sandbox.SandboxID, config []byte) (string, error) {
	dir := stagingDir(rootDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating config stage dir: %w", err)
	}
	path := filepath.Join(dir, configFileName)
	if err := os.WriteFile(path, config, 0o644); err != nil {
		return "", fmt.Errorf("writing config: %w", err)
	}
	return path, nil
}

// sanitizeID makes a sandbox id filesystem-safe (the id contains '/').
func sanitizeID(id sandbox.SandboxID) string {
	return strings.ReplaceAll(string(id), "/", "_")
}
