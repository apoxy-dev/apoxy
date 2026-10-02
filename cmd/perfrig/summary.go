package main

import (
	"fmt"
	"io"
	"os"
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
			dropsCell(r.Info))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "<details><summary>Keys and checks</summary>")
	fmt.Fprintln(w)
	for _, o := range outcomes {
		fmt.Fprintf(w, "- %s `%s`", o.Status, o.Result.Key)
		for _, c := range o.Checks {
			mark := "ok"
			if c.Regressed {
				mark = "REGRESSION"
			}
			fmt.Fprintf(w, "; %s %.4f (baseline %.4f, %+.1f%%, %s)", c.Metric, c.Got, c.Baseline, 100*c.Change(), mark)
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

// dropsCell is the sum of the drops of all sides in the omit period and in the window.
func dropsCell(info map[string]float64) string {
	sum := func(prefix string) (float64, bool) {
		total, found := 0.0, false
		for _, k := range []string{"client_tx_drops", "server_rx_drops", "relay_drops", "server_rcvbuf_errors"} {
			v, ok := info[prefix+k]
			found = found || ok
			// server_rcvbuf_errors is -1 when the server cannot read it.
			if v > 0 {
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
