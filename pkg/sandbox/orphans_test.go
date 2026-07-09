// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

// TestScanOrphanIDs pins orphan detection against BOTH runsc root layouts:
// per-container directories and the flat "<id>_sandbox:<sid>.state"/".lock"
// metadata files newer runsc writes directly into the root. The flat layout
// regression wedged workerd-manager in a crashloop ("container already
// exists") because the boot cleanup only scanned directories.
func TestScanOrphanIDs(t *testing.T) {
	cases := []struct {
		name  string
		dirs  []string
		files []string
		want  []SandboxID
	}{
		{
			name:  "flat runsc metadata files",
			files: []string{"apoxy-workerd-resident_sandbox:apoxy-workerd-resident.state", "apoxy-workerd-resident_sandbox:apoxy-workerd-resident.lock"},
			want:  []SandboxID{"apoxy-workerd-resident"},
		},
		{
			name: "per-container directories",
			dirs: []string{"apoxy-workerd-resident", "apoxy-workerd-resident-bundle"},
			want: []SandboxID{"apoxy-workerd-resident", "apoxy-workerd-resident-bundle"},
		},
		{
			name:  "mixed layouts dedupe to one id",
			dirs:  []string{"sb-1"},
			files: []string{"sb-1_sandbox:sb-1.state", "sb-1_sandbox:sb-1.lock"},
			want:  []SandboxID{"sb-1"},
		},
		{
			name:  "non-metadata files are ignored",
			files: []string{"apoxy-workerd-resident.in.sock", "apoxy-workerd-resident.debug.log", "runsc-apoxy-workerd-resident.sock"},
			want:  nil,
		},
		{
			name: "empty root",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, d := range tc.dirs {
				if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for _, f := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := scanOrphanIDs(dir)
			if err != nil {
				t.Fatalf("scanOrphanIDs: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("scanOrphanIDs = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("scanOrphanIDs = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestRemoveSandboxMetaFiles(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "other_sandbox:other.state")
	for _, f := range []string{"sb-1_sandbox:sb-1.state", "sb-1_sandbox:sb-1.lock", "other_sandbox:other.state"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	removeSandboxMetaFiles(dir, "sb-1")

	if _, err := os.Stat(filepath.Join(dir, "sb-1_sandbox:sb-1.state")); !os.IsNotExist(err) {
		t.Error("sb-1 state file should be removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "sb-1_sandbox:sb-1.lock")); !os.IsNotExist(err) {
		t.Error("sb-1 lock file should be removed")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("other sandbox's metadata must be untouched")
	}
}
