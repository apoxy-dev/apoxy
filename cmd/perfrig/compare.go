package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// defaultTolerance is the largest change that is not a regression.
const defaultTolerance = 0.10

var errRegression = errors.New("performance regression")

// Baseline holds the expected numbers for each result key.
type Baseline struct {
	// Tolerance is a fraction, for example 0.10. Zero means defaultTolerance.
	Tolerance float64                  `json:"tolerance"`
	Entries   map[string]BaselineEntry `json:"entries"`
}

// BaselineEntry holds the numbers of one result key. A zero field is not checked.
type BaselineEntry struct {
	Gbps               float64 `json:"gbps"`
	PacketsPerSecond   float64 `json:"packets_per_second"`
	ClientCoresPerGbps float64 `json:"client_cores_per_gbps"`
	ServerCoresPerGbps float64 `json:"server_cores_per_gbps"`
	// MinGbps is a floor for Gbps. It has no tolerance.
	MinGbps float64 `json:"min_gbps,omitempty"`
	// Tolerance overrides Baseline.Tolerance for this entry.
	Tolerance float64 `json:"tolerance,omitempty"`
	// Info makes the report show the regressions of this entry, but they do not fail.
	Info bool `json:"info,omitempty"`
	// Source tells where the numbers came from, for example a run date.
	Source string `json:"source,omitempty"`
}

// Check is one metric of a result compared with its baseline.
type Check struct {
	Metric    string
	Baseline  float64
	Got       float64
	Regressed bool
}

// Change is the relative change from the baseline.
func (c Check) Change() float64 { return (c.Got - c.Baseline) / c.Baseline }

// compare checks r against its baseline entry. It returns ok=false when the
// baseline has no entry for r.Key.
func compare(b Baseline, r Result) (checks []Check, ok bool) {
	e, ok := b.Entries[r.Key]
	if !ok {
		return nil, false
	}
	tol := b.Tolerance
	if e.Tolerance > 0 {
		tol = e.Tolerance
	}
	if tol <= 0 {
		tol = defaultTolerance
	}
	add := func(metric string, base, got float64, higherIsBetter bool) {
		if base <= 0 {
			return
		}
		bad := got > base*(1+tol)
		if higherIsBetter {
			bad = got < base*(1-tol)
		}
		checks = append(checks, Check{Metric: metric, Baseline: base, Got: got, Regressed: bad})
	}
	if e.MinGbps > 0 {
		checks = append(checks, Check{Metric: "min_gbps", Baseline: e.MinGbps, Got: r.Throughput.Gbps,
			Regressed: r.Throughput.Gbps < e.MinGbps})
	}
	add("gbps", e.Gbps, r.Throughput.Gbps, true)
	add("packets_per_second", e.PacketsPerSecond, r.Throughput.PacketsPerSecond, true)
	add("client_cores_per_gbps", e.ClientCoresPerGbps, r.CPU.Client.CoresPerGbps, false)
	add("server_cores_per_gbps", e.ServerCoresPerGbps, r.CPU.Server.CoresPerGbps, false)
	return checks, true
}

// entryFor makes a baseline entry from a result.
func entryFor(r Result) BaselineEntry {
	return BaselineEntry{
		Gbps:               r.Throughput.Gbps,
		PacketsPerSecond:   r.Throughput.PacketsPerSecond,
		ClientCoresPerGbps: r.CPU.Client.CoresPerGbps,
		ServerCoresPerGbps: r.CPU.Server.CoresPerGbps,
		Source:             r.StartedAt.Format("2006-01-02") + " " + r.Host.Kernel,
	}
}

// updateEntry makes a baseline entry from r. It keeps the floor, the
// tolerance and the info flag of old.
func updateEntry(old BaselineEntry, r Result) BaselineEntry {
	e := entryFor(r)
	e.MinGbps, e.Tolerance, e.Info = old.MinGbps, old.Tolerance, old.Info
	return e
}

// Statuses of a result in the report.
const (
	statusPass = "PASS"
	statusFail = "FAIL"
	// statusWarn is a failed check of an info entry.
	statusWarn = "WARN"
	// statusNew is a result with no baseline entry. It passes.
	statusNew = "NO BASELINE"
)

// outcome is the compare result of one result.
type outcome struct {
	Result Result
	Status string
	Checks []Check
}

// evaluate compares r with its baseline entry. An entry that checks no metric fails.
func evaluate(b Baseline, r Result) outcome {
	checks, ok := compare(b, r)
	o := outcome{Result: r, Status: statusPass, Checks: checks}
	if !ok {
		o.Status = statusNew
		return o
	}
	failed := len(checks) == 0
	for _, c := range checks {
		failed = failed || c.Regressed
	}
	if failed {
		o.Status = statusFail
		if b.Entries[r.Key].Info {
			o.Status = statusWarn
		}
	}
	return o
}

// needsRetry reports whether a run of r must run its reps again: one or more
// checks of a gated entry failed.
func needsRetry(b Baseline, r Result) bool {
	o := evaluate(b, r)
	return o.Status == statusFail && len(o.Checks) > 0
}

// compareResults writes a report to w and returns the outcomes. It returns
// errRegression when a result is worse than its baseline entry or its entry
// checks no metric. A result with no entry and a failed info entry pass.
func compareResults(w io.Writer, b Baseline, results []Result) ([]outcome, error) {
	failed := 0
	outcomes := make([]outcome, 0, len(results))
	for _, r := range results {
		o := evaluate(b, r)
		outcomes = append(outcomes, o)
		if o.Status == statusFail {
			failed++
		}
		switch {
		case o.Status == statusNew:
			fmt.Fprintf(w, "%s %s\n  gbps=%g packets_per_second=%g client_cores_per_gbps=%g server_cores_per_gbps=%g\n",
				o.Status, r.Key, r.Throughput.Gbps, r.Throughput.PacketsPerSecond, r.CPU.Client.CoresPerGbps, r.CPU.Server.CoresPerGbps)
			continue
		case len(o.Checks) == 0:
			fmt.Fprintf(w, "%s %s\n  the baseline entry checks no metric\n", o.Status, r.Key)
			continue
		}
		fmt.Fprintf(w, "%s %s\n", o.Status, r.Key)
		for _, c := range o.Checks {
			mark := "ok"
			if c.Regressed {
				mark = "REGRESSION"
			}
			fmt.Fprintf(w, "  %-22s %10.4f  baseline %10.4f  %+6.1f%%  %s\n",
				c.Metric, c.Got, c.Baseline, 100*c.Change(), mark)
		}
	}
	if failed > 0 {
		return outcomes, fmt.Errorf("%w: %d of %d results failed", errRegression, failed, len(results))
	}
	return outcomes, nil
}

func loadBaseline(path string, missingOK bool) (Baseline, error) {
	b := Baseline{Tolerance: defaultTolerance, Entries: map[string]BaselineEntry{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && missingOK {
		return b, nil
	}
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if b.Entries == nil {
		b.Entries = map[string]BaselineEntry{}
	}
	return b, nil
}

func saveBaseline(path string, b Baseline) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// loadResults reads result files. A directory adds all its *.json files.
func loadResults(paths []string) ([]Result, error) {
	var files []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			files = append(files, p)
			continue
		}
		matches, err := filepath.Glob(filepath.Join(p, "*.json"))
		if err != nil {
			return nil, err
		}
		sort.Strings(matches)
		files = append(files, matches...)
	}
	if len(files) == 0 {
		return nil, errors.New("no result files")
	}
	results := make([]Result, 0, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var r Result
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("parse result %s: %w", f, err)
		}
		if r.Key == "" {
			return nil, fmt.Errorf("result %s has no key", f)
		}
		results = append(results, r)
	}
	return results, nil
}
