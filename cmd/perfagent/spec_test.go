package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validSpec() Spec {
	return Spec{
		RunID:    "123-1-vpc",
		Deadline: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC),
		Bins:     []File{{Name: "perfrig", URL: "https://b.example/bin/perfrig?sig=1", SHA256: testSHA}, {Name: "vpcbench", SHA256: testSHA}},
		Files:    []File{{Name: "baseline.json", URL: "https://b.example/baseline.json", SHA256: testSHA}},
		Sysctls:  map[string]string{"net.core.rmem_max": "134217728"},
		Modules:  []string{"sch_netem"},
		Remove:   []string{"*-cred.json"},
		Nodes:    map[string]string{"server": "10.0.1.5"},
		Rows:     []Row{{ID: "netstack-psp-relay", Group: "floor", Args: []string{"-workload=exec"}}, {ID: "netstack-psp-relay-loss0.1", Group: "info", Cmd: "node"}},
		Upload:   Upload{Results: "https://b.example/r", Log: "https://b.example/l", Report: "https://b.example/a"},
	}
}

func TestSpecValidate(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(*Spec)
		upload  bool
		wantErr string
	}{
		{name: "valid", edit: func(*Spec) {}, upload: true},
		{name: "no upload URLs with -out", edit: func(s *Spec) { s.Upload = Upload{} }},
		{name: "no upload URLs", edit: func(s *Spec) { s.Upload = Upload{} }, upload: true, wantErr: "results upload URL is not HTTPS"},
		{name: "bad run id", edit: func(s *Spec) { s.RunID = "../x" }, wantErr: "bad run_id"},
		{name: "no deadline", edit: func(s *Spec) { s.Deadline = time.Time{} }, wantErr: "no deadline"},
		{name: "no perfrig", edit: func(s *Spec) { s.Bins = s.Bins[1:] }, wantErr: "bins have no perfrig"},
		{name: "bin name with a slash", edit: func(s *Spec) { s.Bins[1].Name = "a/b" }, wantErr: `bad bins name "a/b"`},
		{name: "bad sha256", edit: func(s *Spec) { s.Files[0].SHA256 = "ABC" }, wantErr: "bad sha256 of files"},
		{name: "HTTP URL", edit: func(s *Spec) { s.Bins[0].URL = "http://b.example/perfrig" }, wantErr: "is not HTTPS"},
		{name: "two files with one name", edit: func(s *Spec) { s.Bins[1].Name = "perfrig" }, wantErr: "two bins"},
		{name: "sysctl key with a slash", edit: func(s *Spec) { s.Sysctls = map[string]string{"net/core/rmem_max": "1"} }, wantErr: "bad sysctl key"},
		{name: "bad module", edit: func(s *Spec) { s.Modules = []string{"sch netem"} }, wantErr: "bad module"},
		{name: "remove pattern with a slash", edit: func(s *Spec) { s.Remove = []string{"work/*"} }, wantErr: "bad remove pattern"},
		{name: "bad remove pattern", edit: func(s *Spec) { s.Remove = []string{"["} }, wantErr: "bad remove pattern"},
		{name: "no rows", edit: func(s *Spec) { s.Rows = nil }, wantErr: "no rows"},
		{name: "two rows with one id", edit: func(s *Spec) { s.Rows[1].ID = "netstack-psp-relay" }, wantErr: "two rows"},
		{name: "bad group", edit: func(s *Spec) { s.Rows[0].Group = "" }, wantErr: "bad group"},
		{name: "bad cmd", edit: func(s *Spec) { s.Rows[0].Cmd = "compare" }, wantErr: "bad cmd"},
		{name: "bad node address", edit: func(s *Spec) { s.Nodes = map[string]string{"server": "host"} }, wantErr: "bad node"},
		{name: "bad node role", edit: func(s *Spec) { s.Nodes = map[string]string{"Server": "10.0.1.5"} }, wantErr: "bad node"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validSpec()
			tc.edit(&s)
			err := s.validate(tc.upload)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestLoadSpec(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"run_id": "from-url"}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
		return p
	}
	cases := []struct {
		name    string
		arg     string
		wantID  string
		wantErr string
	}{
		{name: "file", arg: write("ok.json", `{"run_id": "from-file"}`), wantID: "from-file"},
		{name: "URL", arg: srv.URL + "/spec.json", wantID: "from-url"},
		{name: "unknown field", arg: write("unknown.json", `{"run_id": "x", "rowz": []}`), wantErr: "unknown field"},
		{name: "more data", arg: write("more.json", `{"run_id": "x"} {}`), wantErr: "more data"},
		{name: "no file", arg: filepath.Join(dir, "none.json"), wantErr: "read the spec"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := loadSpec(context.Background(), srv.Client(), tc.arg)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantID, s.RunID)
		})
	}
}

func TestSpecJSONNames(t *testing.T) {
	// The perf module writes these names. Keep them stable.
	data, err := os.ReadFile("testdata/spec.json")
	require.NoError(t, err)
	s, err := loadSpec(context.Background(), http.DefaultClient, "testdata/spec.json")
	require.NoError(t, err, string(data))
	require.NoError(t, s.validate(true))
	assert.True(t, strings.HasPrefix(s.Upload.Report, "https://"))
}
