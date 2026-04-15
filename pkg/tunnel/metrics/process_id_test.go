package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCgroupForContainerID(t *testing.T) {
	// 64-hex fixtures taken from real-world cgroup paths.
	const k8sCri = "3bf3c5a2e4d8f9c0a1b2c3d4e5f6789012345678abcdef0123456789abcdef01"
	const docker = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	const criO = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "cgroup v1 k8s containerd",
			data: "12:memory:/kubepods.slice/kubepods-burstable.slice/" +
				"kubepods-burstable-pod1234abcd.slice/cri-containerd-" + k8sCri + ".scope\n",
			want: k8sCri,
		},
		{
			name: "cgroup v2 unified containerd",
			data: "0::/kubepods.slice/kubepods-burstable.slice/" +
				"kubepods-burstable-pod1234abcd.slice/cri-containerd-" + k8sCri + ".scope\n",
			want: k8sCri,
		},
		{
			name: "cgroup v1 docker",
			data: "11:memory:/docker/" + docker + "\n",
			want: docker,
		},
		{
			name: "cgroup v1 cri-o",
			data: "1:name=systemd:/kubepods/burstable/pod<uid>/crio-" + criO + ".scope\n",
			want: criO,
		},
		{
			name: "multiple lines picks the first 64-hex token",
			data: "12:cpuset:/\n" +
				"11:memory:/docker/" + docker + "\n" +
				"0::/docker/" + docker + "\n",
			want: docker,
		},
		{
			name: "no container id (bare-metal / tests)",
			data: "0::/user.slice/user-1000.slice/session-1.scope\n",
			want: "",
		},
		{
			name: "empty file",
			data: "",
			want: "",
		},
		{
			name: "hex shorter than 64 is not matched (avoids partial shas)",
			data: "0::/system.slice/some-service-abc123def.scope\n",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCgroupForContainerID([]byte(tt.data))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDetectContainerID_MissingFile(t *testing.T) {
	// Non-existent path — e.g., macOS dev or sandboxed environments.
	got := detectContainerID("/proc/does-not-exist/cgroup")
	assert.Empty(t, got, "missing file must return empty, not panic")
}

func TestAgentProcessID_Stable(t *testing.T) {
	// Whatever initProcessID() chose at package init, AgentProcessID() must
	// return the same value on every call within the process lifetime.
	a := AgentProcessID()
	b := AgentProcessID()
	assert.NotEmpty(t, a)
	assert.Equal(t, a, b, "AgentProcessID must be stable across calls")
}
