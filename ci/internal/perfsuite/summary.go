package perfsuite

import (
	"encoding/json"
	"fmt"
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

// SlackText returns the line about a failed perf job. at names the commit and
// runURL is the link to the workflow run.
func SlackText(s Suite, floorExit int, rep Report, floor []Result, compareFloor, at, runURL string) string {
	name := s.Title
	var text string
	switch {
	case floorExit == 3:
		msg := rep.InfraError
		for _, r := range floor {
			if msg == "" && r.InfraError != "" {
				msg = r.InfraError
			}
		}
		text = fmt.Sprintf("%s INFRA on %s: %s.", name, at, strings.TrimSuffix(msg, "."))
	case len(floor) == 0:
		text = fmt.Sprintf("%s ERROR on %s: no floor result.", name, at)
	case floorExit == 0:
		text = fmt.Sprintf("%s ERROR on %s: the floor check passed, but a later step failed.", name, at)
	default:
		var parts []string
		for _, r := range floor {
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
		parts = append(parts, regressions(compareFloor)...)
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
