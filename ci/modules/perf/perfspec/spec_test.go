package perfspec

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestSpecMatchesPerfagent checks the JSON names against the perfagent example spec.
func TestSpecMatchesPerfagent(t *testing.T) {
	data, err := os.ReadFile("../../../../cmd/perfagent/testdata/spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s Spec
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("perfagent has a field that Spec does not have: %v", err)
	}
	out, err := s.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("Spec drops or changes fields of the perfagent spec:\nwant %v\ngot  %v", want, got)
	}
}

func TestParsePlan(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr string
	}{
		{name: "rows and host setup", in: `{"rows": [{"id": "netstack-psp-relay", "group": "floor", "args": ["-workload=exec"]}], "tun": true, "modules": ["sch_netem"]}`},
		{name: "unknown field", in: `{"rows": [], "row": []}`, wantErr: "unknown field"},
		{name: "no rows", in: `{"tun": true}`, wantErr: "no rows"},
		{name: "sets bins", in: `{"rows": [{"id": "a", "group": "a"}], "bins": [{"name": "perfrig", "sha256": "x"}]}`, wantErr: "the module sets them"},
		{name: "sets upload", in: `{"rows": [{"id": "a", "group": "a"}], "upload": {"report": "https://x"}}`, wantErr: "the module sets them"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePlan(tc.in)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewKeys(t *testing.T) {
	cases := []struct {
		tag     string
		wantErr bool
	}{
		{tag: "18200000000-1-vpc"},
		{tag: "local"},
		{tag: "", wantErr: true},
		{tag: "../x", wantErr: true},
		{tag: "Run-1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.tag, func(t *testing.T) {
			k, err := NewKeys(tc.tag)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if err == nil && k.Bin("perfrig") != "runs/"+tc.tag+"/in/bin/perfrig" {
				t.Fatalf("Bin = %s", k.Bin("perfrig"))
			}
		})
	}
	k, _ := NewKeys("1-1-vpc")
	if k.Output("agent.json") != "runs/1-1-vpc/out/agent.json" || !strings.HasPrefix(k.Spec(), k.Inputs()) {
		t.Fatalf("keys = %s, %s", k.Output("agent.json"), k.Spec())
	}
}

func TestCloudInit(t *testing.T) {
	agent := "https://b.s3.us-west-2.amazonaws.com/runs/x/in/bin/perfagent?X-Amz-Credential=a%2Fb&X-Amz-Signature=c"
	spec := "https://b.s3.us-west-2.amazonaws.com/runs/x/in/spec.json?X-Amz-Signature=d&x=<y>"
	ud, err := CloudInit(agent, spec, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, ok := strings.CutPrefix(ud, "#cloud-config\n")
	if !ok {
		t.Fatalf("no #cloud-config line: %q", ud)
	}
	if strings.Contains(body, "\t") {
		t.Fatal("YAML must not have tabs")
	}
	var cfg struct {
		Bootcmd    [][]string `json:"bootcmd"`
		Packages   []string   `json:"packages"`
		WriteFiles []struct {
			Path   string            `json:"path"`
			Source map[string]string `json:"source"`
		} `json:"write_files"`
		Runcmd     [][]string     `json:"runcmd"`
		PowerState map[string]any `json:"power_state"`
	}
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Bootcmd) > 0 {
		t.Errorf("bootcmd = %v, want none", cfg.Bootcmd)
	}
	if got := strings.Join(cfg.Runcmd[0], " "); got != "systemd-run --no-block --on-active=60min systemctl poweroff -ff" {
		t.Errorf("runcmd[0] = %s", got)
	}
	if cfg.WriteFiles[0].Path != "/opt/perf/perfagent" || cfg.WriteFiles[0].Source["uri"] != agent {
		t.Errorf("write_files = %+v", cfg.WriteFiles)
	}
	if want := []string{"/opt/perf/perfagent", "-ec2", "-spec", spec}; !reflect.DeepEqual(cfg.Runcmd[1], want) {
		t.Errorf("runcmd[1] = %v, want %v", cfg.Runcmd[1], want)
	}
	if cfg.PowerState["mode"] != "poweroff" || !reflect.DeepEqual(cfg.Packages, []string{"iperf3", "ethtool"}) {
		t.Errorf("power_state = %v, packages = %v", cfg.PowerState, cfg.Packages)
	}
	if _, err := CloudInit(agent, spec, time.Second); err == nil {
		t.Error("CloudInit takes a poweroff of less than 1m")
	}
}

func tgz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if strings.HasSuffix(name, "/") {
			hdr = &tar.Header{Name: name, Mode: 0o755, Typeflag: tar.TypeDir}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil && hdr.Typeflag == tar.TypeReg {
			t.Fatal(err)
		}
	}
	if err := errors.Join(tw.Close(), gz.Close()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestUntar(t *testing.T) {
	cases := []struct {
		name    string
		entries map[string]string
		wantErr bool
	}{
		{name: "results", entries: map[string]string{"results/": "", "results/floor/netstack-psp-relay.json": "{}", "logs/netstack-psp-relay.log": "log"}},
		{name: "parent path", entries: map[string]string{"../x": "x"}, wantErr: true},
		{name: "absolute path", entries: map[string]string{"/etc/x": "x"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			err := Untar(bytes.NewReader(tgz(t, tc.entries)), dir)
			if tc.wantErr {
				if err == nil {
					t.Fatal("Untar takes an unsafe path")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for name, content := range tc.entries {
				if strings.HasSuffix(name, "/") {
					continue
				}
				got, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || string(got) != content {
					t.Errorf("%s = %q, %v", name, got, err)
				}
			}
		})
	}
}

func TestInfraReport(t *testing.T) {
	var r map[string]any
	if err := json.Unmarshal([]byte(InfraReport("1-1-vpc", errors.New("no capacity"))), &r); err != nil {
		t.Fatal(err)
	}
	if r["run_id"] != "1-1-vpc" || r["infra_error"] != "no capacity" || r["rows"] == nil {
		t.Fatalf("report = %v", r)
	}
}
