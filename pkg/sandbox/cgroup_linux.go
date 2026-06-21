//go:build linux

package sandbox

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// cgroupFSRoot is where cgroup v2 is mounted inside the host
	// container. The pod is privileged with /sys/fs/cgroup mounted rw
	// by the CRI, so the host can mutate its own subtree without an
	// explicit hostPath.
	cgroupFSRoot = "/sys/fs/cgroup"

	// hostSandboxParent is the cgroup directory under the host cgroup
	// that every per-sandbox cgroup lives in. The shape mirrors the
	// CgroupsPath runsc would otherwise consume in the OCI spec
	// ("/system/<id>"); we preserve it so the on-disk spec stays
	// diagnostically useful even though runsc itself ignores the
	// resources block under --ignore-cgroups.
	hostSandboxParent = "system"

	// hostSelfCgroup is the leaf cgroup the host process moves itself
	// into at startup so its own cgroup becomes empty of processes and
	// can have controllers enabled via cgroup.subtree_control. cgroup
	// v2's "no internal process" rule fails any subtree_control write on
	// a cgroup with processes in cgroup.procs.
	hostSelfCgroup = "init"
)

// InitHostCgroup performs one-time cgroup v2 setup so the host can
// enforce per-sandbox CPU/memory limits via per-sandbox children:
//
//   - parses /proc/self/cgroup; fails closed if the host isn't cgroup
//     v2 (legacy v1/hybrid hosts would silently lose enforcement);
//   - mkdir <host>/init and moves the host PID into it so <host>
//     itself becomes empty;
//   - writes "+memory +cpu" to <host>/cgroup.subtree_control to
//     delegate enforcement to per-sandbox children;
//   - mkdir <host>/system as the per-sandbox parent.
//
// Returns the absolute filesystem path of the host cgroup (e.g.
// "/sys/fs/cgroup/kubepods.slice/.../cri-containerd-xxx.scope").
func InitHostCgroup() (string, error) {
	rel, err := readSelfCgroupV2Path()
	if err != nil {
		return "", err
	}
	hostPath := filepath.Join(cgroupFSRoot, rel)

	initDir := filepath.Join(hostPath, hostSelfCgroup)
	if err := os.MkdirAll(initDir, 0o755); err != nil {
		return "", fmt.Errorf("creating host self cgroup %s: %w", initDir, err)
	}
	if err := writeCgroupFile(filepath.Join(initDir, "cgroup.procs"), strconv.Itoa(os.Getpid())); err != nil {
		return "", fmt.Errorf("moving host into %s: %w", initDir, err)
	}
	if err := writeCgroupFile(filepath.Join(hostPath, "cgroup.subtree_control"), "+memory +cpu"); err != nil {
		return "", fmt.Errorf("enabling +memory +cpu on %s: %w", hostPath, err)
	}
	if err := os.MkdirAll(filepath.Join(hostPath, hostSandboxParent), 0o755); err != nil {
		return "", fmt.Errorf("creating per-sandbox parent cgroup: %w", err)
	}
	return hostPath, nil
}

// readSelfCgroupV2Path returns the host's cgroup path relative to the
// cgroup v2 filesystem root by parsing /proc/self/cgroup. cgroup v2
// emits a single line shaped "0::<path>" — non-zero hierarchy ids or a
// non-empty controller field mean the host is on cgroup v1/hybrid and we
// refuse to proceed.
func readSelfCgroupV2Path() (string, error) {
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return "", fmt.Errorf("opening /proc/self/cgroup: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		hierID, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		controllers, path, ok := strings.Cut(rest, ":")
		if !ok {
			continue
		}
		if hierID == "0" && controllers == "" {
			return path, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("reading /proc/self/cgroup: %w", err)
	}
	return "", errors.New("/proc/self/cgroup has no cgroup v2 entry; a cgroup v2 host is required")
}

// sandboxCgroupDir returns the absolute path of the per-sandbox cgroup
// directory under the host's cgroup subtree.
func sandboxCgroupDir(hostPath string, id SandboxID) string {
	return filepath.Join(hostPath, hostSandboxParent, string(id))
}

// createSandboxCgroup creates <host>/system/<id>, writes the CPU/memory
// limits, and returns an opened directory FD suitable for
// SysProcAttr.CgroupFD with UseCgroupFD=true. clone3 with
// CLONE_INTO_CGROUP places the runsc-create child — and every descendant
// the kernel later forks under it (Sentry, gofer, guest process tree) —
// into the new cgroup atomically at fork time.
//
// The kernel only consults the FD during clone3; callers should Close it
// as soon as runscCreate returns and must call removeSandboxCgroup on
// rollback or sandbox teardown. On any error after mkdir the directory is
// cleaned up before returning, so callers never see partial state.
//
// cpuMillis / memBytes are zero-means-unlimited cgroup budgets.
func createSandboxCgroup(hostPath string, id SandboxID, cpuMillis, memBytes int64) (*os.File, error) {
	if hostPath == "" {
		return nil, errors.New("host cgroup path is empty; InitHostCgroup must run first")
	}
	dir := sandboxCgroupDir(hostPath, id)
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("creating sandbox cgroup %s: %w", dir, err)
	}
	cleanup := func() { _ = os.Remove(dir) }

	if memBytes > 0 {
		if err := writeCgroupFile(filepath.Join(dir, "memory.max"), strconv.FormatInt(memBytes, 10)); err != nil {
			cleanup()
			return nil, fmt.Errorf("writing memory.max: %w", err)
		}
		// Swap silently extends the effective memory budget past
		// memory.max; pin to zero so the OOM killer fires predictably the
		// moment memory.max is exceeded.
		if err := writeCgroupFile(filepath.Join(dir, "memory.swap.max"), "0"); err != nil {
			cleanup()
			return nil, fmt.Errorf("writing memory.swap.max: %w", err)
		}
	}
	if cpuMillis > 0 {
		quota, period := cpuMaxFor(cpuMillis)
		if err := writeCgroupFile(filepath.Join(dir, "cpu.max"), fmt.Sprintf("%d %d", quota, period)); err != nil {
			cleanup()
			return nil, fmt.Errorf("writing cpu.max: %w", err)
		}
	}

	f, err := os.OpenFile(dir, os.O_RDONLY, 0)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("opening sandbox cgroup dir for clone3: %w", err)
	}
	return f, nil
}

// cpuMaxFor converts millicores into a cgroup v2 cpu.max (quota, period)
// pair encoding CFS bandwidth. period is fixed at 100ms, matching the
// value buildSpec uses for the now-cosmetic OCI Linux.Resources block.
func cpuMaxFor(millis int64) (quota int64, period int64) {
	period = 100000
	quota = millis * period / 1000
	return quota, period
}

// removeSandboxCgroup rmdirs the per-sandbox cgroup. Retries briefly on
// EBUSY — runsc delete can return before the kernel has finished reaping
// the sandbox process tree — and ignores ENOENT so it's safe on partial-
// create paths and on shutdown over already-cleaned state.
func removeSandboxCgroup(hostPath string, id SandboxID) error {
	if hostPath == "" {
		return nil
	}
	dir := sandboxCgroupDir(hostPath, id)
	const attempts = 3
	for i := 0; i < attempts; i++ {
		err := os.Remove(dir)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if i+1 == attempts {
			return fmt.Errorf("removing sandbox cgroup %s: %w", dir, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// writeCgroupFile writes content to a cgroup v2 control file. cgroup
// files are kernel-backed and don't carry O_CREATE/O_TRUNC semantics, so
// we open O_WRONLY against the pre-existing entry rather than going
// through os.WriteFile.
func writeCgroupFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}
