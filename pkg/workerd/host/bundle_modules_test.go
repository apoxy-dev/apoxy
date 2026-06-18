// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

// makeModuleLayer builds a gzip-compressed tar from name->content pairs.
func makeModuleLayer(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractModulesFromLayer(t *testing.T) {
	blob := makeModuleLayer(t, map[string]string{
		"./index.js":      "export default {}",
		"lib/util.js":     "export const x = 1",
		"./data/cfg.json": `{"k":"v"}`,
	})
	got := map[string][]byte{}
	if err := extractModulesFromLayer(blob, got); err != nil {
		t.Fatalf("extractModulesFromLayer: %v", err)
	}
	// Keys are cleaned: leading "./" stripped, path.Clean applied.
	want := map[string]string{
		"index.js":      "export default {}",
		"lib/util.js":   "export const x = 1",
		"data/cfg.json": `{"k":"v"}`,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %v", len(got), len(want), keys(got))
	}
	for k, v := range want {
		if string(got[k]) != v {
			t.Errorf("module %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestExtractModulesFromLayer_SkipsDirsAndSymlinks(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	// A directory entry and a symlink entry should be skipped; only the regular
	// file survives.
	_ = tw.WriteHeader(&tar.Header{Name: "dir/", Mode: 0o755, Typeflag: tar.TypeDir})
	_ = tw.WriteHeader(&tar.Header{Name: "link.js", Linkname: "index.js", Typeflag: tar.TypeSymlink})
	_ = tw.WriteHeader(&tar.Header{Name: "index.js", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hi"))
	_ = tw.Close()
	_ = gz.Close()

	got := map[string][]byte{}
	if err := extractModulesFromLayer(buf.Bytes(), got); err != nil {
		t.Fatalf("extractModulesFromLayer: %v", err)
	}
	if len(got) != 1 || string(got["index.js"]) != "hi" {
		t.Errorf("want only index.js=hi, got %v", keys(got))
	}
}

func TestCleanModulePath(t *testing.T) {
	cases := map[string]string{
		"./index.js":    "index.js",
		"index.js":      "index.js",
		"a/./b.js":      "a/b.js",
		"./a/../b.json": "b.json",
	}
	for in, want := range cases {
		if got := CleanModulePath(in); got != want {
			t.Errorf("CleanModulePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
