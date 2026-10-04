// Package perfspec has the perfagent spec, the cloud-init user data and the
// result unpacking of the perf module. It has no Dagger code, so its tests run
// with plain go test.
package perfspec

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Spec is the perfagent spec. The JSON names must match cmd/perfagent/spec.go.
type Spec struct {
	RunID    string            `json:"run_id"`
	Deadline time.Time         `json:"deadline"`
	Bins     []File            `json:"bins"`
	Files    []File            `json:"files,omitempty"`
	Sysctls  map[string]string `json:"sysctls,omitempty"`
	Modules  []string          `json:"modules,omitempty"`
	Tun      bool              `json:"tun,omitempty"`
	Remove   []string          `json:"remove,omitempty"`
	Rows     []Row             `json:"rows"`
	Upload   Upload            `json:"upload"`
}

// File is a file that perfagent fetches, or finds in place when URL is empty.
type File struct {
	Name   string `json:"name"`
	URL    string `json:"url,omitempty"`
	SHA256 string `json:"sha256"`
}

// Row is one "perfrig run".
type Row struct {
	ID    string   `json:"id"`
	Group string   `json:"group"`
	Args  []string `json:"args"`
}

// Upload has the presigned PUT URLs of the outputs.
type Upload struct {
	Results string `json:"results"`
	Log     string `json:"log"`
	Report  string `json:"report"`
}

// Agent is the name of the perfagent binary in the bins directory. It is not in Spec.Bins.
const Agent = "perfagent"

// ParsePlan reads a plan: a spec with the rows and the host setup only. The
// module sets run_id, deadline, bins, files and upload.
func ParsePlan(data string) (Spec, error) {
	var s Spec
	dec := json.NewDecoder(strings.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Spec{}, fmt.Errorf("parse the plan: %w", err)
	}
	if s.RunID != "" || !s.Deadline.IsZero() || len(s.Bins) > 0 || len(s.Files) > 0 || s.Upload != (Upload{}) {
		return Spec{}, errors.New("the plan sets run_id, deadline, bins, files or upload; the module sets them")
	}
	if len(s.Rows) == 0 {
		return Spec{}, errors.New("the plan has no rows")
	}
	return s, nil
}

// JSON returns the spec as perfagent reads it.
func (s Spec) JSON() (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	return buf.String(), nil
}

var runTagPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// Keys are the S3 keys of one run, under runs/RUN_TAG/.
type Keys struct{ Prefix string }

// NewKeys returns the keys of a run tag, for example 18200000000-1-vpc.
func NewKeys(runTag string) (Keys, error) {
	if !runTagPattern.MatchString(runTag) {
		return Keys{}, fmt.Errorf("bad run tag %q: want lowercase letters, digits, dots and dashes", runTag)
	}
	return Keys{Prefix: "runs/" + runTag + "/"}, nil
}

// Inputs is the prefix of the binaries, files and spec. The module deletes it at the end.
func (k Keys) Inputs() string            { return k.Prefix + "in/" }
func (k Keys) Bin(name string) string    { return k.Inputs() + "bin/" + name }
func (k Keys) File(name string) string   { return k.Inputs() + "files/" + name }
func (k Keys) Spec() string              { return k.Inputs() + "spec.json" }
func (k Keys) Output(name string) string { return k.Prefix + "out/" + name }

// RunTag is the KEY=VALUE instance tag of one run.
func RunTag(runTag string) string { return "apoxy-perf-run=" + runTag }

// Tags returns the instance tags. The reaper terminates the instance after expires.
func Tags(runTag string, expires time.Time) []string {
	return []string{
		"Name=apoxy-perf-" + runTag,
		"apoxy-perf=true",
		RunTag(runTag),
		"apoxy-perf-expires=" + expires.UTC().Format(time.RFC3339),
	}
}

// CloudInit returns the user data of a bench instance. cloud-init fetches
// perfagent, starts a systemd timer that powers off the host after poweroff,
// runs perfagent, and then powers off the host, also when perfagent fails.
func CloudInit(agentURL, specURL string, poweroff time.Duration) (string, error) {
	if poweroff < time.Minute {
		return "", fmt.Errorf("poweroff %s is less than 1m", poweroff)
	}
	cfg := map[string]any{
		"packages": []string{"iperf3", "ethtool"},
		"write_files": []map[string]any{{
			"path":        "/opt/perf/" + Agent,
			"permissions": "0755",
			"source":      map[string]string{"uri": agentURL},
		}},
		// systemd-run stops the boot when it runs in bootcmd, so the timer starts here.
		"runcmd": [][]string{
			{"systemd-run", "--no-block", fmt.Sprintf("--on-active=%dmin", int(poweroff.Minutes())), "systemctl", "poweroff", "-ff"},
			{"/opt/perf/" + Agent, "-ec2", "-spec", specURL},
		},
		"power_state": map[string]any{"mode": "poweroff", "condition": true, "delay": "now"},
	}
	// JSON is YAML. The encoder quotes the URLs.
	var buf bytes.Buffer
	buf.WriteString("#cloud-config\n")
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Report is the part of agent.json that the module writes when perfagent wrote none.
type Report struct {
	RunID      string `json:"run_id"`
	InfraError string `json:"infra_error"`
	Rows       []any  `json:"rows"`
}

// InfraReport returns an agent.json with the infra error.
func InfraReport(runID string, err error) string {
	b, _ := json.MarshalIndent(Report{RunID: runID, InfraError: err.Error(), Rows: []any{}}, "", "  ")
	return string(b) + "\n"
}

// Untar writes the directories and regular files of a gzip tar under dir. It
// refuses absolute paths and paths out of dir.
func Untar(r io.Reader, dir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(filepath.FromSlash(hdr.Name))
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe path %q in the results", hdr.Name)
		}
		path := filepath.Join(dir, name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		}
	}
}
