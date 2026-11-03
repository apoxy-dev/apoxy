package perfsuite

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
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

// FloorExit is 0 (pass or no floor row selected), 1 (regression or no floor
// result) or 3 (infra error).
func FloorExit(rep Report, floor Compare) int {
	switch {
	case rep.InfraError != "":
		return 3
	case !floor.Ran && floor.Unselected:
		return 0
	case !floor.Ran:
		return 1
	case floor.Code == 0 || floor.Code == 3:
		return floor.Code
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
		if c.Group != "floor" {
			fmt.Fprintf(&b, "### Rows: %s\n\nThese rows have no floor.\n\n", c.Group)
		}
		switch {
		case c.Ran && c.Markdown != "":
			b.WriteString(c.Markdown)
			b.WriteString("\n")
		case c.Ran:
			fmt.Fprintf(&b, "perfrig compare wrote no table (exit %d): %s\n\n", c.Code, strings.TrimSpace(tail(c.Stderr, 5)))
		case c.Group == "floor" && c.Unselected:
			b.WriteString("No floor row ran: the selected rows have no floor.\n\n")
		case c.Group == "floor":
			b.WriteString("No floor result. See logs/ in the results.\n\n")
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

// NodeResult is the part of a perfrig result of one host of a multi-node run
// that the summary uses. Role is empty in a result of the netns rig.
type NodeResult struct {
	Workload string `json:"workload"`
	Role     string `json:"role"`
	Host     struct {
		Class  string `json:"class"`
		CPUs   int    `json:"cpus"`
		Kernel string `json:"kernel"`
		NIC    *struct {
			Dev         string   `json:"dev"`
			Driver      string   `json:"driver"`
			Version     string   `json:"version"`
			MTU         int      `json:"mtu"`
			RxQueues    int      `json:"rx_queues"`
			XDPFeatures []string `json:"xdp_features"`
		} `json:"nic"`
	} `json:"host"`
	RTT struct {
		Avg float64 `json:"avg"`
	} `json:"rtt_ms"`
	RelayRTT *struct {
		Avg float64 `json:"avg"`
	} `json:"relay_rtt_ms"`
	// Info and Throughput of the client have the window numbers of all roles.
	Info       map[string]float64 `json:"info"`
	Throughput struct {
		Gbps float64 `json:"gbps"`
	} `json:"throughput"`
	NIC map[string]int64 `json:"nic_counters"`
}

// nodeCounters are the NIC counters of the hosts table, in order.
var nodeCounters = []string{
	"bw_in_allowance_exceeded", "bw_out_allowance_exceeded", "pps_allowance_exceeded", "conntrack_allowance_exceeded",
	"rx_dropped", "tx_dropped", "rx_top_queue_pct",
}

// Nodes returns a table with one line for each host of the node rows, from the
// perfrig result JSON files. It is empty when no result has a role.
func Nodes(results []string) string {
	var nodes []NodeResult
	clients := map[string]NodeResult{}
	for _, data := range results {
		var n NodeResult
		if err := json.Unmarshal([]byte(data), &n); err != nil || n.Role == "" {
			continue
		}
		nodes = append(nodes, n)
		if n.Role == "client" {
			clients[n.Workload] = n
		}
	}
	if len(nodes) == 0 {
		return ""
	}
	order := map[string]int{"client": 0, "server": 1, "relay": 2}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Workload != nodes[j].Workload {
			return nodes[i].Workload < nodes[j].Workload
		}
		return order[nodes[i].Role] < order[nodes[j].Role]
	})
	var b strings.Builder
	b.WriteString("### Hosts of the node rows\n\n")
	b.WriteString("Cores/Gbps is the CPU of the vpcbench process. Host cores is the busy CPU of the host, also the kernel work. " +
		"Both are in the measured window. The NIC counters are the increase while the role ran. The allowance counters are the EC2 network limits. " +
		"Top queue is the percent of the RX packets that the busiest RX queue got.\n\n")
	b.WriteString("| Workload | Role | Host | NIC | RX queues | XDP | RTT ms server, relay | Cores/Gbps | Host cores | Host cores/Gbps " +
		"| bw_in | bw_out | pps | conntrack | rx_dropped | tx_dropped | Top queue % |\n")
	b.WriteString("|---|---|---|---|--:|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|\n")
	for _, n := range nodes {
		nic, queues, xdp := "-", "-", "-"
		if h := n.Host.NIC; h != nil {
			nic = strings.TrimSpace(h.Dev + " " + h.Driver + " " + h.Version)
			if h.MTU > 0 {
				nic += fmt.Sprintf(", mtu %d", h.MTU)
			}
			queues = strconv.Itoa(h.RxQueues)
			if len(h.XDPFeatures) > 0 {
				xdp = strings.Join(h.XDPFeatures, " ")
			}
		}
		rtt := "-"
		if n.Role == "client" {
			rtt = fmt.Sprintf("%.3f", n.RTT.Avg)
			if n.RelayRTT != nil {
				rtt += fmt.Sprintf(", %.3f", n.RelayRTT.Avg)
			}
		}
		c := clients[n.Workload]
		perGbps, hostCores, hostPerGbps := "-", "-", "-"
		if v, ok := c.Info[n.Role+"_cores_per_gbps"]; ok {
			perGbps = fmt.Sprintf("%.3f", v)
		}
		if v, ok := c.Info[n.Role+"_host_cores"]; ok && v >= 0 {
			hostCores = fmt.Sprintf("%.2f", v)
			if c.Throughput.Gbps > 0 {
				hostPerGbps = fmt.Sprintf("%.3f", v/c.Throughput.Gbps)
			}
		}
		fmt.Fprintf(&b, "| %s | %s | %s, %d CPUs, %s | %s | %s | %s | %s | %s | %s | %s |",
			n.Workload, n.Role, n.Host.Class, n.Host.CPUs, n.Host.Kernel, nic, queues, xdp, rtt, perGbps, hostCores, hostPerGbps)
		for _, k := range nodeCounters {
			if v, ok := n.NIC[k]; ok {
				fmt.Fprintf(&b, " %d |", v)
			} else {
				b.WriteString(" - |")
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	return b.String()
}

// Result is the part of a perfrig result that the Slack text uses.
type Result struct {
	// Key is the same as the key of the result in "perfrig compare" output.
	Key        string `json:"key"`
	Workload   string `json:"workload"`
	InfraError string `json:"infra_error"`
	Retried    bool   `json:"retried"`
	Runs       []Run  `json:"runs"`
}

// Run is one rep of a result.
type Run struct {
	Throughput Throughput `json:"throughput"`
}

// Throughput is the receive rate of a result or a rep.
type Throughput struct {
	Gbps float64 `json:"gbps"`
}

// SlackText returns the Slack text about a failed perf job: one line with the
// status, then one line for each failed case. at names the commit and runURL
// is the link to the workflow run.
func SlackText(s Suite, floorExit int, rep Report, floor []Result, compareFloor, at, runURL string) string {
	cases := parseCompare(compareFloor)
	class := ""
	for i, c := range cases {
		if i > 0 && c.class != class {
			class = ""
			break
		}
		class = c.class
	}
	if class == "" && len(cases) == 0 && rep.Host.EC2 != nil {
		class = rep.Host.EC2.InstanceType
	}
	head := func(status string) string {
		h := fmt.Sprintf("%s %s on %s", s.Title, status, at)
		if class != "" {
			h += " (" + class + ")"
		}
		return h + " <" + runURL + "|Run>"
	}
	switch {
	case floorExit == 3:
		msg := rep.InfraError
		for _, r := range floor {
			if msg == "" && r.InfraError != "" {
				msg = r.InfraError
			}
		}
		return head("INFRA") + "\n" + strings.TrimSuffix(msg, ".") + "."
	case len(floor) == 0:
		return head("ERROR") + "\nNo floor result."
	case floorExit == 0:
		return head("ERROR") + "\nThe floor check passed, but a later step failed."
	}
	results := map[string]Result{}
	for _, r := range floor {
		results[strings.Join(strings.Fields(r.Key), " ")] = r
	}
	labels := caseLabels(cases, class == "")
	lines := []string{head("FAIL")}
	warns := 0
	for _, c := range cases {
		switch c.status {
		case "WARN":
			warns++
			continue
		case "FAIL":
		default:
			continue
		}
		var checks []string
		for _, f := range c.failed {
			checks = append(checks, checkText(f))
		}
		if len(checks) == 0 {
			checks = c.notes
		}
		line := "• " + labels[c] + ": " + strings.Join(checks, ", ")
		if r, ok := results[c.key]; ok {
			var extra []string
			if len(r.Runs) > 0 {
				runs := make([]string, len(r.Runs))
				for i, run := range r.Runs {
					runs[i] = num(run.Throughput.Gbps, 2)
				}
				extra = append(extra, "runs "+strings.Join(runs, " "))
			}
			if r.Retried {
				extra = append(extra, "retried")
			}
			if len(extra) > 0 {
				line += "; " + strings.Join(extra, ", ")
			}
		}
		lines = append(lines, line)
	}
	if len(lines) == 1 {
		lines = append(lines, "No failed case in the compare output, see run.")
	}
	if warns > 0 {
		lines = append(lines, fmt.Sprintf("Warnings: %d case(s), see run.", warns))
	}
	return strings.Join(lines, "\n")
}

// compareCase is one result block of "perfrig compare" output.
type compareCase struct {
	status, class, workload string
	// key is the block line after the status.
	key string
	// settings are the "name=value" fields of the key, in order.
	settings []string
	// failed has the fields METRIC GOT baseline BASE CHANGE of each REGRESSION check.
	failed [][]string
	// notes are the lines under the block line that are not checks.
	notes []string
}

// parseCompare returns the blocks of "perfrig compare" output, one for each
// key. A block is a "STATUS CLASS WORKLOAD streams=..." line and the indented
// lines under it. STATUS can have two words.
func parseCompare(out string) []*compareCase {
	var cases []*compareCase
	seen := map[string]bool{}
	var cur *compareCase
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			cur = nil
			i := slices.IndexFunc(f, func(s string) bool { return strings.HasPrefix(s, "streams=") })
			if i < 3 {
				continue
			}
			key := strings.Join(f[i-2:], " ")
			if seen[key] {
				continue
			}
			seen[key] = true
			cur = &compareCase{status: strings.Join(f[:i-2], " "), class: f[i-2], workload: f[i-1], key: key, settings: f[i:]}
			cases = append(cases, cur)
			continue
		}
		switch {
		case cur == nil:
		case len(f) == 6 && f[2] == "baseline":
			if f[5] == "REGRESSION" {
				cur.failed = append(cur.failed, f[:5])
			}
		default:
			cur.notes = append(cur.notes, strings.Join(f, " "))
		}
	}
	return cases
}

// caseLabels names each case by its workload and the settings that are not
// the same in all cases of that workload. withClass adds the class first.
func caseLabels(cases []*compareCase, withClass bool) map[*compareCase]string {
	values := map[string]map[string]map[string]bool{}
	for _, c := range cases {
		if values[c.workload] == nil {
			values[c.workload] = map[string]map[string]bool{}
		}
		for _, kv := range c.settings {
			name, value, _ := strings.Cut(kv, "=")
			if values[c.workload][name] == nil {
				values[c.workload][name] = map[string]bool{}
			}
			values[c.workload][name][value] = true
		}
	}
	labels := map[*compareCase]string{}
	for _, c := range cases {
		parts := []string{c.workload}
		if withClass {
			parts = []string{c.class, c.workload}
		}
		for _, kv := range c.settings {
			name, _, _ := strings.Cut(kv, "=")
			if len(values[c.workload][name]) > 1 {
				parts = append(parts, kv)
			}
		}
		labels[c] = strings.Join(parts, " ")
	}
	return labels
}

// checkText returns the Slack text of the fields METRIC GOT baseline BASE CHANGE of a check.
func checkText(f []string) string {
	metric, got, base, change := f[0], f[1], f[3], f[4]
	if metric == "gbps" {
		return fmt.Sprintf("%s Gbps vs %s (%s)", numText(got, 2), numText(base, 2), change)
	}
	name := strings.NewReplacer("_per_gbps", "/Gbps", "_per_second", "/s", "_", " ").Replace(metric)
	return fmt.Sprintf("%s %s vs %s (%s)", name, numText(got, 4), numText(base, 4), change)
}

// numText rounds the number s to prec decimals. It returns s when s is not a number.
func numText(s string, prec int) string {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return s
	}
	return num(v, prec)
}

// num formats v with at most prec decimals and no trailing zeros.
func num(v float64, prec int) string {
	p := math.Pow10(prec)
	return strconv.FormatFloat(math.Round(v*p)/p, 'f', -1, 64)
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}
