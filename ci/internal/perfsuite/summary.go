package perfsuite

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Report is the part of agent.json that the summary uses.
type Report struct {
	RunID      string      `json:"run_id"`
	InfraError string      `json:"infra_error"`
	Rows       []RowResult `json:"rows"`
	Host       struct {
		Kernel string `json:"kernel"`
		CPUs   int    `json:"cpus"`
		EC2    *struct {
			InstanceID   string `json:"instance_id"`
			InstanceType string `json:"instance_type"`
			AZ           string `json:"az"`
			AMI          string `json:"ami"`
		} `json:"ec2"`
	} `json:"host"`
}

// RowResult is the outcome of one row in agent.json.
type RowResult struct {
	ID       string `json:"id"`
	Group    string `json:"group"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error"`
}

// ParseReport reads agent.json.
func ParseReport(data string) (Report, error) {
	var r Report
	if err := json.Unmarshal([]byte(data), &r); err != nil {
		return Report{}, fmt.Errorf("parse agent.json: %w", err)
	}
	return r, nil
}

// Compare is one "perfrig compare" of a result group.
type Compare struct {
	Group string
	// Ran is false when the group has no result.
	Ran bool
	// Unselected is true when the run selected no row of the group.
	Unselected bool
	// Code is the perfrig exit code: 0 pass, 1 regression, 3 infra error.
	Code     int
	Stdout   string
	Stderr   string
	Markdown string
}

// GateExit is 0 (pass or no gated row selected), 1 (regression or no gate
// result) or 3 (infra error).
func GateExit(rep Report, gate Compare) int {
	switch {
	case rep.InfraError != "":
		return 3
	case !gate.Ran && gate.Unselected:
		return 0
	case !gate.Ran:
		return 1
	case gate.Code == 0 || gate.Code == 3:
		return gate.Code
	default:
		return 1
	}
}

// Summary returns summary.md of a run.
func Summary(s Suite, rep Report, compares []Compare, console string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", s.Title)
	if h := rep.Host.EC2; h != nil {
		fmt.Fprintf(&b, "Host: %s %s in %s, %s, kernel %s.\n\n", h.InstanceType, h.InstanceID, h.AZ, h.AMI, rep.Host.Kernel)
	} else if rep.Host.Kernel != "" {
		fmt.Fprintf(&b, "Host: %d CPUs, kernel %s.\n\n", rep.Host.CPUs, rep.Host.Kernel)
	}
	if rep.InfraError != "" {
		fmt.Fprintf(&b, "**Infra error:** %s\n\n", rep.InfraError)
		if console != "" {
			fmt.Fprintf(&b, "<details><summary>Console output (last lines)</summary>\n\n```\n%s\n```\n\n</details>\n\n", tail(console, 40))
		}
	}
	for _, c := range compares {
		if c.Group != "gate" {
			fmt.Fprintf(&b, "### Rows: %s\n\nThese rows do not gate.\n\n", c.Group)
		}
		switch {
		case c.Ran && c.Markdown != "":
			b.WriteString(c.Markdown)
			b.WriteString("\n")
		case c.Ran:
			fmt.Fprintf(&b, "perfrig compare wrote no table (exit %d): %s\n\n", c.Code, strings.TrimSpace(tail(c.Stderr, 5)))
		case c.Group == "gate" && c.Unselected:
			b.WriteString("No gated row ran: the selected rows do not gate.\n\n")
		case c.Group == "gate":
			b.WriteString("No gate result. See logs/ in the results.\n\n")
		default:
			fmt.Fprintf(&b, "No %s results.\n\n", c.Group)
		}
	}
	var errs []string
	for _, r := range rep.Rows {
		switch {
		case r.Error != "":
			errs = append(errs, fmt.Sprintf("- %s: %s (exit %d), see logs/%s.log", r.ID, r.Error, r.ExitCode, r.ID))
		case r.ExitCode != 0:
			errs = append(errs, fmt.Sprintf("- %s: perfrig exit %d, see logs/%s.log", r.ID, r.ExitCode, r.ID))
		}
	}
	if len(errs) > 0 {
		fmt.Fprintf(&b, "### perfrig errors\n\n%s\n\n", strings.Join(errs, "\n"))
	}
	return b.String()
}

// Result is the part of a perfrig result that the Slack text uses.
type Result struct {
	Workload   string     `json:"workload"`
	InfraError string     `json:"infra_error"`
	Retried    bool       `json:"retried"`
	Throughput Throughput `json:"throughput"`
	Runs       []Run      `json:"runs"`
}

// Run is one rep of a result.
type Run struct {
	Throughput Throughput `json:"throughput"`
}

// Throughput is the receive rate of a result or a rep.
type Throughput struct {
	Gbps float64 `json:"gbps"`
}

// SlackText returns the line about a failed gate job. at names the commit and
// runURL is the link to the workflow run.
func SlackText(s Suite, gateExit int, rep Report, gate []Result, compareGate, at, runURL string) string {
	name := s.Title
	var text string
	switch {
	case gateExit == 3:
		msg := rep.InfraError
		for _, r := range gate {
			if msg == "" && r.InfraError != "" {
				msg = r.InfraError
			}
		}
		text = fmt.Sprintf("%s INFRA on %s: %s.", name, at, strings.TrimSuffix(msg, "."))
	case len(gate) == 0:
		text = fmt.Sprintf("%s ERROR on %s: no gate result.", name, at)
	case gateExit == 0:
		text = fmt.Sprintf("%s ERROR on %s: the gate passed, but a later step failed.", name, at)
	default:
		var parts []string
		for _, r := range gate {
			runs := make([]string, len(r.Runs))
			for i, run := range r.Runs {
				runs[i] = fmt.Sprintf("%g", run.Throughput.Gbps)
			}
			p := fmt.Sprintf("%s median %g Gbps, runs %s", r.Workload, r.Throughput.Gbps, strings.Join(runs, " "))
			if r.Retried {
				p += ", retried"
			}
			parts = append(parts, p)
		}
		parts = append(parts, regressions(compareGate)...)
		text = fmt.Sprintf("%s FAIL on %s: %s.", name, at, strings.Join(parts, "; "))
	}
	return text + " <" + runURL + "|Run>"
}

// regressions returns the failed checks of "perfrig compare" output. A check
// line is "  METRIC GOT baseline BASE CHANGE REGRESSION" under a "STATUS KEY" line.
func regressions(out string) []string {
	var got []string
	workload := ""
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			// The line is "STATUS CLASS WORKLOAD streams=...". STATUS can have two words.
			for i := 1; i < len(f); i++ {
				if strings.HasPrefix(f[i], "streams=") {
					workload = f[i-1]
					break
				}
			}
			continue
		}
		if f[len(f)-1] == "REGRESSION" && len(f) >= 5 {
			got = append(got, fmt.Sprintf("%s %s %s (baseline %s, %s)", workload, f[0], f[1], f[3], f[4]))
		}
	}
	return got
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}
