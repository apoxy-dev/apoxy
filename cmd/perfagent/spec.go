package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Spec tells the agent what to fetch, how to set up the host, which rows to
// run and where to put the outputs.
type Spec struct {
	// RunID names the run in the logs and in agent.json.
	RunID string `json:"run_id"`
	// Deadline is when the agent stops the rows. The uploads come after it.
	Deadline time.Time `json:"deadline"`
	// Bins go to the bin directory, which is first in the PATH of the rows.
	// They must include perfrig.
	Bins []File `json:"bins"`
	// Files go to the run directory, for example baseline.json.
	Files []File `json:"files,omitempty"`
	// Sysctls are host keys, for example the global net.core keys.
	Sysctls map[string]string `json:"sysctls,omitempty"`
	// Modules are kernel modules to load, for example sch_netem.
	Modules []string `json:"modules,omitempty"`
	// Tun makes /dev/net/tun when it is missing.
	Tun bool `json:"tun,omitempty"`
	// Remove are base name patterns of files that the agent deletes from the
	// run directory before it packs it, for example keys.
	Remove []string `json:"remove,omitempty"`
	// Rows run one at a time, in this order.
	Rows []Row `json:"rows"`
	// Upload has the presigned PUT URLs. With -out, the agent does not use them.
	Upload Upload `json:"upload"`
}

// File is a file to fetch. With no URL, the file must already be in place.
// The agent checks the SHA-256 in both cases.
type File struct {
	Name   string `json:"name"`
	URL    string `json:"url,omitempty"`
	SHA256 string `json:"sha256"`
}

// Row is one "perfrig run". The agent adds -out, -out-dir and -host-class.
type Row struct {
	ID string `json:"id"`
	// Group is the results subdirectory, for example floor or info.
	Group string   `json:"group"`
	Args  []string `json:"args"`
}

// Upload has a presigned PUT URL for each output.
type Upload struct {
	Results string `json:"results"`
	Log     string `json:"log"`
	// Report gets agent.json. The agent puts it last, so it tells that the run is done.
	Report string `json:"report"`
}

var (
	namePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	sysctlPattern = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_-]+)+$`)
	modulePattern = regexp.MustCompile(`^[a-z0-9_-]+$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// validate checks the spec. With upload false, the upload URLs are not needed.
func (s Spec) validate(upload bool) error {
	var errs []error
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	check(namePattern.MatchString(s.RunID), "bad run_id %q", s.RunID)
	check(!s.Deadline.IsZero(), "no deadline")
	files := func(kind string, fs []File) map[string]bool {
		seen := map[string]bool{}
		for _, f := range fs {
			check(namePattern.MatchString(f.Name), "bad %s name %q", kind, f.Name)
			check(!seen[f.Name], "two %s with the name %q", kind, f.Name)
			check(sha256Pattern.MatchString(f.SHA256), "bad sha256 of %s %q", kind, f.Name)
			check(f.URL == "" || httpsURL(f.URL), "the URL of %s %q is not HTTPS", kind, f.Name)
			seen[f.Name] = true
		}
		return seen
	}
	check(files("bins", s.Bins)["perfrig"], "bins have no perfrig")
	files("files", s.Files)
	for k := range s.Sysctls {
		check(sysctlPattern.MatchString(k), "bad sysctl key %q", k)
	}
	for _, m := range s.Modules {
		check(modulePattern.MatchString(m), "bad module %q", m)
	}
	for _, p := range s.Remove {
		_, err := filepath.Match(p, "x")
		check(err == nil && !strings.Contains(p, "/"), "bad remove pattern %q", p)
	}
	check(len(s.Rows) > 0, "no rows")
	ids := map[string]bool{}
	for _, r := range s.Rows {
		check(namePattern.MatchString(r.ID), "bad row id %q", r.ID)
		check(!ids[r.ID], "two rows with the id %q", r.ID)
		check(namePattern.MatchString(r.Group), "bad group %q of row %q", r.Group, r.ID)
		ids[r.ID] = true
	}
	if upload {
		check(httpsURL(s.Upload.Results), "the results upload URL is not HTTPS")
		check(httpsURL(s.Upload.Log), "the log upload URL is not HTTPS")
		check(httpsURL(s.Upload.Report), "the report upload URL is not HTTPS")
	}
	return errors.Join(errs...)
}

func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// loadSpec reads the spec from a file or an HTTPS URL.
func loadSpec(ctx context.Context, client *http.Client, arg string) (Spec, error) {
	var data []byte
	var err error
	if strings.HasPrefix(arg, "https://") {
		data, err = get(ctx, client, arg)
	} else {
		data, err = os.ReadFile(arg)
	}
	if err != nil {
		return Spec{}, fmt.Errorf("read the spec: %w", err)
	}
	var s Spec
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Spec{}, fmt.Errorf("parse the spec: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Spec{}, errors.New("parse the spec: more data after the JSON object")
	}
	return s, nil
}
