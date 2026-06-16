// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package host

import "github.com/apoxy-dev/clrk/pkg/sandbox"

// newCore builds the gVisor/runsc sandbox manager: it initializes the host
// cgroup v2 hierarchy and the OCI image store, then constructs the Manager.
// This is the only linux-specific, CGO-bound part of the runtime — the rest of
// the wrapper drives the tenant-neutral sandbox.Runtime interface.
func newCore(cfg Config) (sandbox.Runtime, error) {
	hostCgroupPath, err := sandbox.InitHostCgroup()
	if err != nil {
		return nil, err
	}
	store := sandbox.NewImageStore(cfg.ImageBaseDir)
	return sandbox.NewManager(sandbox.ManagerConfig{
		StateDir:       cfg.StateDir,
		RootDir:        cfg.RootDir,
		ImageStore:     store,
		HostCgroupPath: hostCgroupPath,
	}), nil
}
