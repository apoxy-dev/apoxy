package sandbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type tarEntry struct {
	name     string
	typeflag byte
	mode     int64
	content  string
	linkname string
}

// buildLayer serializes entries into a (optionally gzipped) tar blob and
// returns it together with the matching OCI layer media type.
func buildLayer(t *testing.T, entries []tarEntry, gz bool) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	var w io.Writer = &buf
	var gw *gzip.Writer
	if gz {
		gw = gzip.NewWriter(&buf)
		w = gw
	}
	tw := tar.NewWriter(w)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Mode:     e.mode,
			Linkname: e.linkname,
			Size:     int64(len(e.content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader %q: %v", e.name, err)
		}
		if len(e.content) > 0 {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatalf("Write %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if gw != nil {
		if err := gw.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
	}
	mt := "application/vnd.oci.image.layer.v1.tar"
	if gz {
		mt += "+gzip"
	}
	return buf.Bytes(), mt
}

func TestExtractLayer(t *testing.T) {
	t.Run("files dirs and symlink, gzip", func(t *testing.T) {
		rootFS := t.TempDir()
		blob, mt := buildLayer(t, []tarEntry{
			{name: "bin", typeflag: tar.TypeDir, mode: 0o755},
			{name: "bin/sh", typeflag: tar.TypeReg, mode: 0o755, content: "#!/bin/sh\n"},
			{name: "bin/bash", typeflag: tar.TypeSymlink, linkname: "sh"},
		}, true)
		if err := extractLayer(rootFS, blob, mt); err != nil {
			t.Fatalf("extractLayer: %v", err)
		}

		got, err := os.ReadFile(filepath.Join(rootFS, "bin/sh"))
		if err != nil {
			t.Fatalf("read bin/sh: %v", err)
		}
		if string(got) != "#!/bin/sh\n" {
			t.Fatalf("bin/sh = %q", got)
		}
		fi, err := os.Lstat(filepath.Join(rootFS, "bin/bash"))
		if err != nil {
			t.Fatalf("lstat bin/bash: %v", err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("bin/bash is not a symlink: mode %v", fi.Mode())
		}
		if target, _ := os.Readlink(filepath.Join(rootFS, "bin/bash")); target != "sh" {
			t.Fatalf("bin/bash -> %q, want sh", target)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		rootFS := t.TempDir()
		blob, mt := buildLayer(t, []tarEntry{
			{name: "orig.txt", typeflag: tar.TypeReg, mode: 0o644, content: "data"},
			{name: "link.txt", typeflag: tar.TypeLink, linkname: "orig.txt"},
		}, false)
		if err := extractLayer(rootFS, blob, mt); err != nil {
			t.Fatalf("extractLayer: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(rootFS, "link.txt"))
		if err != nil {
			t.Fatalf("read link.txt: %v", err)
		}
		if string(got) != "data" {
			t.Fatalf("link.txt = %q, want data", got)
		}
	})

	t.Run("path traversal and absolute paths are skipped", func(t *testing.T) {
		rootFS := t.TempDir()
		// A sibling dir next to rootFS that a "../" entry would land in.
		sibling := filepath.Join(filepath.Dir(rootFS), "escape-target")
		if err := os.MkdirAll(sibling, 0o755); err != nil {
			t.Fatalf("mkdir sibling: %v", err)
		}
		blob, mt := buildLayer(t, []tarEntry{
			{name: "../escape-target/pwn.txt", typeflag: tar.TypeReg, mode: 0o644, content: "x"},
			{name: "/abs.txt", typeflag: tar.TypeReg, mode: 0o644, content: "x"},
			{name: "ok.txt", typeflag: tar.TypeReg, mode: 0o644, content: "ok"},
		}, false)
		if err := extractLayer(rootFS, blob, mt); err != nil {
			t.Fatalf("extractLayer: %v", err)
		}
		if _, err := os.Stat(filepath.Join(sibling, "pwn.txt")); !os.IsNotExist(err) {
			t.Fatalf("traversal entry escaped rootFS: pwn.txt exists in sibling (err=%v)", err)
		}
		// The benign entry in the same layer is still extracted.
		if got, err := os.ReadFile(filepath.Join(rootFS, "ok.txt")); err != nil || string(got) != "ok" {
			t.Fatalf("ok.txt = %q, err=%v; want ok", got, err)
		}
	})

	t.Run("file whiteout removes the named file", func(t *testing.T) {
		rootFS := t.TempDir()
		base, mt := buildLayer(t, []tarEntry{
			{name: "a.txt", typeflag: tar.TypeReg, mode: 0o644, content: "a"},
			{name: "b.txt", typeflag: tar.TypeReg, mode: 0o644, content: "b"},
		}, false)
		if err := extractLayer(rootFS, base, mt); err != nil {
			t.Fatalf("extractLayer base: %v", err)
		}
		wh, mt2 := buildLayer(t, []tarEntry{
			{name: ".wh.a.txt", typeflag: tar.TypeReg, mode: 0o644},
		}, false)
		if err := extractLayer(rootFS, wh, mt2); err != nil {
			t.Fatalf("extractLayer whiteout: %v", err)
		}
		if _, err := os.Stat(filepath.Join(rootFS, "a.txt")); !os.IsNotExist(err) {
			t.Fatalf("a.txt should be whited out (err=%v)", err)
		}
		if _, err := os.Stat(filepath.Join(rootFS, "b.txt")); err != nil {
			t.Fatalf("b.txt should survive: %v", err)
		}
		// The whiteout marker itself is not materialized.
		if _, err := os.Stat(filepath.Join(rootFS, ".wh.a.txt")); !os.IsNotExist(err) {
			t.Fatalf(".wh.a.txt marker should not be written (err=%v)", err)
		}
	})

	t.Run("opaque whiteout clears directory children", func(t *testing.T) {
		rootFS := t.TempDir()
		base, mt := buildLayer(t, []tarEntry{
			{name: "d", typeflag: tar.TypeDir, mode: 0o755},
			{name: "d/x", typeflag: tar.TypeReg, mode: 0o644, content: "x"},
			{name: "d/y", typeflag: tar.TypeReg, mode: 0o644, content: "y"},
			{name: "keep.txt", typeflag: tar.TypeReg, mode: 0o644, content: "k"},
		}, false)
		if err := extractLayer(rootFS, base, mt); err != nil {
			t.Fatalf("extractLayer base: %v", err)
		}
		opq, mt2 := buildLayer(t, []tarEntry{
			{name: "d/.wh..wh..opq", typeflag: tar.TypeReg, mode: 0o644},
		}, false)
		if err := extractLayer(rootFS, opq, mt2); err != nil {
			t.Fatalf("extractLayer opaque: %v", err)
		}
		if _, err := os.Stat(filepath.Join(rootFS, "d/x")); !os.IsNotExist(err) {
			t.Fatalf("d/x should be cleared (err=%v)", err)
		}
		if _, err := os.Stat(filepath.Join(rootFS, "d/y")); !os.IsNotExist(err) {
			t.Fatalf("d/y should be cleared (err=%v)", err)
		}
		if _, err := os.Stat(filepath.Join(rootFS, "keep.txt")); err != nil {
			t.Fatalf("keep.txt outside d should survive: %v", err)
		}
	})
}

func TestEnsureBaseSystemFiles(t *testing.T) {
	t.Run("creates missing files", func(t *testing.T) {
		rootFS := t.TempDir()
		if err := ensureBaseSystemFiles(rootFS); err != nil {
			t.Fatalf("ensureBaseSystemFiles: %v", err)
		}
		if _, err := os.Stat(filepath.Join(rootFS, "etc/resolv.conf")); err != nil {
			t.Fatalf("resolv.conf not created: %v", err)
		}
		nss, err := os.ReadFile(filepath.Join(rootFS, "etc/nsswitch.conf"))
		if err != nil {
			t.Fatalf("nsswitch.conf not created: %v", err)
		}
		if string(nss) != "hosts: files dns\n" {
			t.Fatalf("nsswitch.conf = %q", nss)
		}
	})

	t.Run("does not clobber existing files", func(t *testing.T) {
		rootFS := t.TempDir()
		etc := filepath.Join(rootFS, "etc")
		if err := os.MkdirAll(etc, 0o755); err != nil {
			t.Fatalf("mkdir etc: %v", err)
		}
		if err := os.WriteFile(filepath.Join(etc, "resolv.conf"), []byte("nameserver 1.1.1.1\n"), 0o644); err != nil {
			t.Fatalf("seed resolv.conf: %v", err)
		}
		if err := ensureBaseSystemFiles(rootFS); err != nil {
			t.Fatalf("ensureBaseSystemFiles: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(etc, "resolv.conf"))
		if err != nil {
			t.Fatalf("read resolv.conf: %v", err)
		}
		if string(got) != "nameserver 1.1.1.1\n" {
			t.Fatalf("resolv.conf was clobbered: %q", got)
		}
	})
}

func TestTarFileMode(t *testing.T) {
	cases := []struct {
		in   int64
		want os.FileMode
	}{
		{0o755, 0o755},
		{0o644, 0o644},
		{0o4755, 0o755}, // setuid high bit stripped
		{0o2755, 0o755}, // setgid high bit stripped
		{0o1777, 0o777}, // sticky high bit stripped
	}
	for _, tc := range cases {
		if got := tarFileMode(tc.in); got != tc.want {
			t.Errorf("tarFileMode(%#o) = %#o, want %#o", tc.in, got, tc.want)
		}
	}
}

func TestCachedRefs(t *testing.T) {
	s := NewImageStore(t.TempDir())
	if got := s.CachedRefs(); len(got) != 0 {
		t.Fatalf("fresh store CachedRefs = %v, want empty", got)
	}
	s.images["registry.example/a@sha256:aaa"] = &ImageInfo{RootFS: "/x"}
	s.images["registry.example/b@sha256:bbb"] = &ImageInfo{RootFS: "/y"}
	if got := s.CachedRefs(); len(got) != 2 {
		t.Fatalf("CachedRefs = %v, want 2 entries", got)
	}
}
