package main

import (
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
)

// appendSummary appends the markdown summary of the outcomes to the file at
// path, for example $GITHUB_STEP_SUMMARY.
func appendSummary(path string, outcomes []outcome) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	writeSummary(f, outcomes)
	return f.Close()
}

// writeSummary writes a markdown table with one row for each outcome, and the
// keys and checks under it. The info columns are empty when the workload
// result does not have the numbers.
func writeSummary(w io.Writer, outcomes []outcome) {
	fmt.Fprintln(w, "### perfrig results")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Status | Workload | Gbps | Runs | Floor | Baseline | Cores/Gbps client, server, relay | Retx % | Load RTT p50, p99 ms | RTT p90 omit, window ms | Drops omit, window |")
	fmt.Fprintln(w, "|---|---|--:|---|--:|---|---|--:|---|---|---|")
	for _, o := range outcomes {
		r := o.Result
		gbps := fmt.Sprintf("%.2f", r.Throughput.Gbps)
		if r.Retried {
			gbps += " (retried)"
		}
		runs := make([]string, len(r.Runs))
		for i, run := range r.Runs {
			runs[i] = fmt.Sprintf("%.2f", run.Throughput.Gbps)
		}
		floor, base := "-", "-"
		for _, c := range o.Checks {
			switch c.Metric {
			case "min_gbps":
				floor = fmt.Sprintf("%.2f", c.Baseline)
			case "gbps":
				base = fmt.Sprintf("%.2f (%+.1f%%)", c.Baseline, 100*c.Change())
			}
		}
		relay := "-"
		if r.CPU.Relay != nil {
			relay = fmt.Sprintf("%.2f", r.CPU.Relay.CoresPerGbps)
		}
		cores := fmt.Sprintf("%.2f, %.2f, %s", r.CPU.Client.CoresPerGbps, r.CPU.Server.CoresPerGbps, relay)
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			o.Status, workloadCell(r), gbps, strings.Join(runs, " "), floor, base, cores,
			infoCell(r.Info, "%.2f", "retrans_percent"),
			infoCell(r.Info, "%.1f", "load_rtt_ms.p50", "load_rtt_ms.p99"),
			infoCell(r.Info, "%.1f", "omit.rtt_ms.p90", "load_rtt_ms.p90"),
			dropsCell(r.Info, r.Role != ""))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "<details><summary>Keys and checks</summary>")
	fmt.Fprintln(w)
	for _, o := range outcomes {
		fmt.Fprintf(w, "- %s `%s`", o.Status, o.Result.Key)
		if o.Result.InfraError != "" {
			fmt.Fprintf(w, "; %s", o.Result.InfraError)
		}
		for _, c := range o.Checks {
			mark := "ok"
			if c.Regressed {
				mark = "REGRESSION"
			}
			fmt.Fprintf(w, "; %s %.4f (baseline %.4f, %+.1f%%, %s)", c.Metric, c.Got, c.Baseline, 100*c.Change(), mark)
		}
		if d := dropsDetail(o.Result.Info); d != "" {
			fmt.Fprintf(w, "; %s", d)
		}
		if d := nicDetail(o.Result.Host.NIC, o.Result.NIC); d != "" {
			fmt.Fprintf(w, "; %s", d)
		}
		if d := rigDetail(o.Result.Runs); d != "" {
			fmt.Fprintf(w, "; %s", d)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "</details>")
	fmt.Fprintln(w)
}

// workloadCell is the workload name and the settings that change most between rows.
func workloadCell(r Result) string {
	s := fmt.Sprintf("%s, %d flows", r.Workload, r.Settings.Streams)
	if r.Settings.LossPercent > 0 {
		s += fmt.Sprintf(", loss %g%%", r.Settings.LossPercent)
	}
	if r.Settings.Rate != "" {
		s += ", rate " + r.Settings.Rate
	}
	return s
}

// infoCell formats the info values of keys, with commas between them. It is
// "-" when a key is missing.
func infoCell(info map[string]float64, format string, keys ...string) string {
	vals := make([]string, len(keys))
	for i, k := range keys {
		v, ok := info[k]
		if !ok {
			return "-"
		}
		vals[i] = fmt.Sprintf(format, v)
	}
	return strings.Join(vals, ", ")
}

// dropPlaces are the drop counters of a vpcbench result, in the order of the
// path from the client to the server. server rcvbuf counts all sockets of the server
// netns, and the relay runs there, so the sum leaves out the socket counters (part).
var dropPlaces = []struct {
	key, name string
	part      bool
}{
	{"client_link_drops", "client link", false},
	{"client_tx_drops", "client tx", false},
	{"relay_rcvbuf_drops", "relay socket", true},
	{"relay_drops", "relay", false},
	{"server_rcvbuf_errors", "server rcvbuf", false},
	{"server_sock_drops", "server socket", true},
	{"server_rx_drops", "server rx", false},
	{"server_link_drops", "server link", false},
}

// dropsCell is the sum of the drops of all sides in the omit period and in the
// window. In a node result, the relay socket is on its own host, so the sum has it.
func dropsCell(info map[string]float64, node bool) string {
	sum := func(prefix string) (float64, bool) {
		total, found := 0.0, false
		for _, p := range dropPlaces {
			v, ok := info[prefix+p.key]
			found = found || ok
			part := p.part && !(node && p.key == "relay_rcvbuf_drops")
			// A counter is -1 when the side cannot read it.
			if v > 0 && !part {
				total += v
			}
		}
		return total, found
	}
	omit, ok1 := sum("omit.")
	window, ok2 := sum("")
	if !ok1 || !ok2 {
		return "-"
	}
	return fmt.Sprintf("%.0f, %.0f", omit, window)
}

// dropsDetail lists the drops of each place, the drops of the relay by reason,
// and the TCP retransmits of the server, in the omit period and in the window.
// It is empty when the result has no drop counters.
func dropsDetail(info map[string]float64) string {
	value := func(k string) string {
		v, ok := info[k]
		if !ok || v < 0 {
			return "-"
		}
		return fmt.Sprintf("%.0f", v)
	}
	var parts []string
	for _, p := range dropPlaces {
		if _, ok := info[p.key]; ok {
			part := fmt.Sprintf("%s %s/%s", p.name, value("omit."+p.key), value(p.key))
			if p.key == "relay_drops" {
				part += relayReasons(info)
			}
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	d := "drops omit/window: " + strings.Join(parts, ", ")
	if _, ok := info["server_retransmits"]; ok {
		d += fmt.Sprintf("; server retx omit/window: %s/%s", value("omit.server_retransmits"), value("server_retransmits"))
	}
	return d
}

// relayReasons lists the drop reasons of the relay that are not 0 in the omit
// period or in the window, in brackets. It is empty when the relay has none.
func relayReasons(info map[string]float64) string {
	const prefix = "relay_drop_reasons."
	reasons := map[string]bool{}
	for k, v := range info {
		if name, ok := strings.CutPrefix(strings.TrimPrefix(k, "omit."), prefix); ok && v > 0 {
			reasons[name] = true
		}
	}
	if len(reasons) == 0 {
		return ""
	}
	parts := make([]string, 0, len(reasons))
	for _, name := range slices.Sorted(maps.Keys(reasons)) {
		parts = append(parts, fmt.Sprintf("%s %.0f/%.0f", name, info["omit."+prefix+name], info[prefix+name]))
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// nicDetail describes the NIC of a node result and its drop counters in the
// window, in the order of nicCounterNames. It is empty with no NIC.
func nicDetail(nic *NIC, counters map[string]int64) string {
	if nic == nil {
		return ""
	}
	d := fmt.Sprintf("nic %s %s %s, %d rx queues, xdp %s", nic.Dev, nic.Driver, nic.Version, nic.RxQueues, orNone(strings.Join(nic.XDPFeatures, " ")))
	var parts []string
	for _, k := range nicCounterNames {
		if v, ok := counters[k]; ok {
			parts = append(parts, fmt.Sprintf("%s %d", k, v))
		}
	}
	if len(parts) > 0 {
		d += "; nic counters: " + strings.Join(parts, ", ")
	}
	return d
}

// rigDetail lists the rig counters that increased, but not the packets of the
// queues, with the increase in each run.
func rigDetail(runs []Run) string {
	keys := map[string]bool{}
	for _, r := range runs {
		for k := range r.Rig {
			if !strings.HasSuffix(k, "_packets") {
				keys[k] = true
			}
		}
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(keys)) {
		part := k
		for _, r := range runs {
			part += " " + strconv.FormatInt(r.Rig[k], 10)
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return ""
	}
	return "rig counters by run: " + strings.Join(parts, ", ")
}
