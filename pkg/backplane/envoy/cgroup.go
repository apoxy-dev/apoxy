package envoy

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// defaultCgroupRoot is the mount point of the cgroup v2 filesystem.
const defaultCgroupRoot = "/sys/fs/cgroup"

// cgroupReader reads the memory limit and the OOM kill count of the cgroup the
// backplane and Envoy share.
type cgroupReader struct {
	// root is the mount point of the cgroup v2 filesystem.
	root string
}

// defaultCgroupReader returns the reader for the cgroup of this container.
var defaultCgroupReader = func() *cgroupReader {
	return &cgroupReader{root: defaultCgroupRoot}
}

// memoryLimit returns the memory limit of the cgroup in bytes. The second
// result is false when the limit is absent, unlimited or not a number, which
// is the case on cgroup v1 and outside Linux.
func (c *cgroupReader) memoryLimit() (int64, bool) {
	b, err := os.ReadFile(filepath.Join(c.root, "memory.max"))
	if err != nil {
		return 0, false
	}

	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}

	return v, true
}

// oomKills returns the number of processes the OOM killer stopped in this
// cgroup. The second result is false when the cgroup does not publish the
// count, which is the case on cgroup v1 and outside Linux.
func (c *cgroupReader) oomKills() (int64, bool) {
	b, err := os.ReadFile(filepath.Join(c.root, "memory.events"))
	if err != nil {
		return 0, false
	}

	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 || fields[0] != "oom_kill" {
			continue
		}
		v, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}

	return 0, false
}
