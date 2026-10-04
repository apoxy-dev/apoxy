package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAgent(t *testing.T, out string, client *http.Client) *agent {
	t.Helper()
	root := t.TempDir()
	// runAgent makes agent.log. These tests call main directly.
	require.NoError(t, os.WriteFile(filepath.Join(root, "agent.log"), []byte("log\n"), 0o644))
	return &agent{root: root, out: out, client: client}
}

func readReport(t *testing.T, data []byte) Report {
	t.Helper()
	var rep Report
	require.NoError(t, json.Unmarshal(data, &rep))
	return rep
}

func rowCodes(rows []RowResult) map[string]int {
	codes := map[string]int{}
	for _, r := range rows {
		codes[r.ID] = r.ExitCode
	}
	return codes
}

func TestAgentUpload(t *testing.T) {
	t.Setenv("PERFAGENT_FAKE_PERFRIG", "1")
	perfrig, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	baseline := []byte(`{"entries": {}}`)

	var mu sync.Mutex
	var order []string
	puts := map[string][]byte{}
	var spec []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/spec.json":
			_, _ = w.Write(spec)
		case r.Method == http.MethodGet && r.URL.Path == "/bin/perfrig":
			_, _ = w.Write(perfrig)
		case r.Method == http.MethodGet && r.URL.Path == "/baseline.json":
			_, _ = w.Write(baseline)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/up/"):
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			order = append(order, strings.TrimPrefix(r.URL.Path, "/up/"))
			puts[strings.TrimPrefix(r.URL.Path, "/up/")] = body
			mu.Unlock()
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	spec, err = json.Marshal(Spec{
		RunID:    "1-1-vpc",
		Deadline: time.Now().Add(time.Minute),
		Bins:     []File{{Name: "perfrig", URL: srv.URL + "/bin/perfrig?X-Amz-Signature=s", SHA256: sha256Hex(perfrig)}},
		Files:    []File{{Name: "baseline.json", URL: srv.URL + "/baseline.json", SHA256: sha256Hex(baseline)}},
		Rows: []Row{
			{ID: "pass", Group: "floor", Args: []string{"-fake=pass"}},
			{ID: "fail", Group: "info", Args: []string{"-fake=fail"}},
		},
		Upload: Upload{Results: srv.URL + "/up/results", Log: srv.URL + "/up/log", Report: srv.URL + "/up/report"},
	})
	require.NoError(t, err)

	a := newTestAgent(t, "", srv.Client())
	require.NoError(t, a.main(context.Background(), srv.URL+"/spec.json"))

	assert.Equal(t, []string{"results", "log", "report"}, order)
	rep := readReport(t, puts["report"])
	assert.Empty(t, rep.InfraError)
	assert.Equal(t, "1-1-vpc", rep.RunID)
	assert.Equal(t, map[string]int{"pass": 0, "fail": 1}, rowCodes(rep.Rows))
	assert.Equal(t, sha256Hex(puts["results"]), rep.ResultsSHA256)
	assert.Equal(t, "log\n", string(puts["log"]))
	files := untar(t, puts["results"])
	assert.Contains(t, files, "results/floor/pass.json")
	assert.Contains(t, files, "results/info/fail.json")
	assert.Contains(t, files, "logs/pass.log")
	assert.Equal(t, string(baseline), files["baseline.json"])
}

func TestAgentLocal(t *testing.T) {
	t.Setenv("PERFAGENT_FAKE_PERFRIG", "1")
	perfrig, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	good := Spec{
		RunID:    "local",
		Deadline: time.Now().Add(time.Minute),
		Bins:     []File{{Name: "perfrig", SHA256: sha256Hex(perfrig)}},
		Rows:     []Row{{ID: "pass", Group: "floor", Args: []string{"-fake=pass"}}},
	}
	cases := []struct {
		name      string
		edit      func(*Spec)
		wantFiles []string
		wantInfra string
		wantCodes map[string]int
	}{
		{
			name:      "pass",
			edit:      func(*Spec) {},
			wantFiles: []string{"agent.json", "agent.log", "results.tgz"},
			wantCodes: map[string]int{"pass": 0},
		},
		{
			name:      "deadline passed",
			edit:      func(s *Spec) { s.Deadline = time.Now().Add(-time.Minute) },
			wantFiles: []string{"agent.json", "agent.log", "results.tgz"},
			wantInfra: "did not end before the deadline",
			wantCodes: map[string]int{"pass": -1},
		},
		{
			name:      "bad spec",
			edit:      func(s *Spec) { s.Rows = nil },
			wantFiles: []string{"agent.json", "agent.log"},
			wantInfra: "no rows",
			wantCodes: map[string]int{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			a := newTestAgent(t, out, http.DefaultClient)
			binDir := filepath.Join(a.root, "bin")
			require.NoError(t, os.MkdirAll(binDir, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(binDir, "perfrig"), perfrig, 0o755))
			s := good
			tc.edit(&s)
			data, err := json.Marshal(s)
			require.NoError(t, err)
			specPath := filepath.Join(a.root, "spec.json")
			require.NoError(t, os.WriteFile(specPath, data, 0o644))

			require.NoError(t, a.main(context.Background(), specPath))

			ents, err := os.ReadDir(out)
			require.NoError(t, err)
			var names []string
			for _, e := range ents {
				names = append(names, e.Name())
			}
			assert.Equal(t, tc.wantFiles, names)
			report, err := os.ReadFile(filepath.Join(out, "agent.json"))
			require.NoError(t, err)
			rep := readReport(t, report)
			if tc.wantInfra == "" {
				assert.Empty(t, rep.InfraError)
			} else {
				assert.Contains(t, rep.InfraError, tc.wantInfra)
			}
			assert.Equal(t, tc.wantCodes, rowCodes(rep.Rows))
		})
	}
}

func TestAgentNoUploadURL(t *testing.T) {
	a := newTestAgent(t, "", http.DefaultClient)
	err := a.main(context.Background(), filepath.Join(a.root, "none.json"))
	require.ErrorContains(t, err, "put agent.json: no upload URL")
}
