package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// untar returns the entries of a gzip tar: name to content.
func untar(t *testing.T, data []byte) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	got := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return got
		}
		require.NoError(t, err)
		b, err := io.ReadAll(tr)
		require.NoError(t, err)
		got[hdr.Name] = string(b)
	}
}

func TestRemoveFilesAndPack(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"results/floor/netstack-psp-relay.json":          `{"key": "x"}`,
		"logs/netstack-psp-relay.log":                    "log",
		"work/netstack-psp-relay/rep-1/client.out":       "out",
		"work/netstack-psp-relay/rep-1/server-cred.json": "key",
		"work/netstack-psp-relay/rep-1/vpcbench-ca.pem":  "ca",
		"work/netstack-psp-direct/client.out":            "direct",
	}
	for name, content := range files {
		p := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}
	require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(dir, "logs", "link")))

	n, err := removeFiles(dir, []string{"*-cred.json", "vpcbench-ca.pem"})
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	var buf bytes.Buffer
	require.NoError(t, pack(dir, &buf))
	got := untar(t, buf.Bytes())
	var names []string
	for name := range got {
		names = append(names, name)
	}
	sort.Strings(names)
	assert.Equal(t, []string{
		"logs/", "logs/netstack-psp-relay.log",
		"results/", "results/floor/", "results/floor/netstack-psp-relay.json",
		"work/", "work/netstack-psp-direct/", "work/netstack-psp-direct/client.out",
		"work/netstack-psp-relay/", "work/netstack-psp-relay/rep-1/", "work/netstack-psp-relay/rep-1/client.out",
	}, names)
	assert.Equal(t, `{"key": "x"}`, got["results/floor/netstack-psp-relay.json"])
}
