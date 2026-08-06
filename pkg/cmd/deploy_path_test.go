package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDeployInput(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "edge")
	sourceDir := filepath.Join(projectDir, "src")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(sourceDir, "worker.js")
	if err := os.WriteFile(sourcePath, []byte("export default {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeSourcePath, err := filepath.Rel(cwd, sourcePath)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		arg       string
		entry     string
		wantDir   string
		wantEntry string
		wantErr   string
	}{
		{
			name:      "current project",
			wantDir:   ".",
			wantEntry: "",
		},
		{
			name:      "project directory with nested entry",
			arg:       projectDir,
			entry:     "src/worker.js",
			wantDir:   projectDir,
			wantEntry: "src/worker.js",
		},
		{
			name:      "standalone file",
			arg:       sourcePath,
			wantDir:   sourceDir,
			wantEntry: "worker.js",
		},
		{
			name:      "relative standalone file",
			arg:       relativeSourcePath,
			wantDir:   filepath.Dir(relativeSourcePath),
			wantEntry: "worker.js",
		},
		{
			name:      "standalone file with entry override",
			arg:       sourcePath,
			entry:     "alternate.js",
			wantDir:   sourceDir,
			wantEntry: "alternate.js",
		},
		{
			name:    "missing path",
			arg:     filepath.Join(root, "missing.js"),
			wantErr: "resolving",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotDir, gotEntry, err := resolveDeployInput(tc.arg, tc.entry)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("resolveDeployInput() error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveDeployInput() error = %v", err)
			}
			if gotDir != tc.wantDir {
				t.Errorf("resolveDeployInput() dir = %q, want %q", gotDir, tc.wantDir)
			}
			if gotEntry != tc.wantEntry {
				t.Errorf("resolveDeployInput() entry = %q, want %q", gotEntry, tc.wantEntry)
			}
		})
	}
}
