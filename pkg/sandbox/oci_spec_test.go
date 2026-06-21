//go:build linux

package sandbox

import (
	"reflect"
	"testing"
)

// resolveProcessArgs is the neutral argv-assembly seam: Command (else the
// image entrypoint) with Args appended. The wrapper's run-task path depends
// on Args landing *after* Command, so guard the ordering explicitly.
func TestResolveProcessArgs(t *testing.T) {
	cases := []struct {
		name       string
		command    []string
		extra      []string
		entrypoint []string
		want       []string
	}{
		{"command_with_args", []string{"sh", "-c", "echo hi"}, []string{"a", "b"}, []string{"/img"}, []string{"sh", "-c", "echo hi", "a", "b"}},
		{"command_overrides_entrypoint", []string{"sh"}, nil, []string{"/img"}, []string{"sh"}},
		{"entrypoint_when_no_command", nil, []string{"a"}, []string{"/img", "-x"}, []string{"/img", "-x", "a"}},
		{"extra_appended_to_entrypoint", nil, []string{"x", "y"}, []string{"run"}, []string{"run", "x", "y"}},
		{"command_no_extra", []string{"true"}, nil, nil, []string{"true"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveProcessArgs(tc.command, tc.extra, tc.entrypoint)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("resolveProcessArgs(%v, %v, %v) = %v; want %v", tc.command, tc.extra, tc.entrypoint, got, tc.want)
			}
		})
	}

	// All-empty yields no argv at all (the runtime then relies on the image's
	// own config, which buildSpec never reaches with an empty Args).
	if got := resolveProcessArgs(nil, nil, nil); len(got) != 0 {
		t.Fatalf("resolveProcessArgs(nil,nil,nil) = %v; want empty", got)
	}
}

// mountsToSpec converts the neutral Mount slice into OCI mounts, defaulting an
// empty Type to "bind" (the common case for the wrapper's trust/state mounts).
func TestMountsToSpec(t *testing.T) {
	in := []Mount{
		{Source: "/host/a", Destination: "/a", Type: "", Options: []string{"bind", "ro"}},
		{Source: "tmpfs", Destination: "/t", Type: "tmpfs", Options: nil},
	}
	got := mountsToSpec(in)
	if len(got) != 2 {
		t.Fatalf("mountsToSpec returned %d mounts; want 2", len(got))
	}
	if got[0].Type != "bind" {
		t.Errorf("empty Type must default to bind; got %q", got[0].Type)
	}
	if got[0].Destination != "/a" || got[0].Source != "/host/a" {
		t.Errorf("mount[0] = %+v; want dst=/a src=/host/a", got[0])
	}
	if !reflect.DeepEqual(got[0].Options, []string{"bind", "ro"}) {
		t.Errorf("mount[0].Options = %v; want [bind ro]", got[0].Options)
	}
	if got[1].Type != "tmpfs" {
		t.Errorf("explicit Type must be preserved; got %q", got[1].Type)
	}
	if n := len(mountsToSpec(nil)); n != 0 {
		t.Errorf("mountsToSpec(nil) returned %d mounts; want 0", n)
	}
}

// defaultSpecMounts is the fixed baseline mount set the wrapper's reserved-path
// list (reservedGuestMountPaths) is kept in sync with; lock its destinations.
func TestDefaultSpecMounts(t *testing.T) {
	want := map[string]bool{
		"/proc": true, "/dev": true, "/sys": true,
		"/sys/fs/cgroup": true, "/dev/pts": true, "/tmp": true,
	}
	got := defaultSpecMounts()
	if len(got) != len(want) {
		t.Fatalf("defaultSpecMounts returned %d mounts; want %d", len(got), len(want))
	}
	for _, m := range got {
		if !want[m.Destination] {
			t.Errorf("unexpected default mount destination %q", m.Destination)
		}
	}
}
