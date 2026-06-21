//go:build linux

package sandbox

import "testing"

// cpuMaxFor encodes the ExecutionResources.CPU (millicores) -> cgroup v2
// cpu.max (quota, period) seam. period is fixed at 100ms; quota = millis*100.
func TestCPUMaxFor(t *testing.T) {
	cases := []struct {
		name       string
		millis     int64
		wantQuota  int64
		wantPeriod int64
	}{
		{"one_core", 1000, 100000, 100000},
		{"half_core", 500, 50000, 100000},
		{"two_cores", 2000, 200000, 100000},
		{"tenth_core", 100, 10000, 100000},
		{"one_milli", 1, 100, 100000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			quota, period := cpuMaxFor(tc.millis)
			if quota != tc.wantQuota || period != tc.wantPeriod {
				t.Fatalf("cpuMaxFor(%d) = (%d, %d); want (%d, %d)",
					tc.millis, quota, period, tc.wantQuota, tc.wantPeriod)
			}
		})
	}
}

// sandboxCgroupDir composes the per-sandbox cgroup path under the host subtree;
// it must place the sandbox under the hostSandboxParent ("system") dir so
// removeSandboxCgroup and createSandboxCgroup agree on the location.
func TestSandboxCgroupDir(t *testing.T) {
	got := sandboxCgroupDir("/sys/fs/cgroup/worker", SandboxID("sb-42"))
	want := "/sys/fs/cgroup/worker/" + hostSandboxParent + "/sb-42"
	if got != want {
		t.Fatalf("sandboxCgroupDir = %q; want %q", got, want)
	}
}
