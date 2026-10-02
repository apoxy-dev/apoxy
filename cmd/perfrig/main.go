// Command perfrig is a network performance rig. "perfrig run" joins two network
// namespaces with a veth pair, adds netem delay, jitter, loss and rate limits
// on both ends, runs a server and a client workload, and prints a JSON result
// with RTT, throughput and CPU. "perfrig compare" checks results against a
// baseline file. Exit code 3 is an infra error, for example CPU steal or a rig
// setup failure, and not a result of the workload.
//
//	perfrig run -workload iperf3-tcp -streams 4 -duration 30s -reps 3 -min-cpus 8 -max-steal 5
//	perfrig compare -baseline cmd/perfrig/baseline.json -summary "$GITHUB_STEP_SUMMARY" perf/
//	perfrig compare -baseline cmd/perfrig/baseline.json -update perf/
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "run":
		err = runCmd(ctx, os.Args[2:])
	case "compare":
		err = compareCmd(os.Args[2:])
	case "write":
		err = writeCmd(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		code := exitCode(err)
		slog.Error("Perf rig failed", "error", err, "exit_code", code)
		stop()
		os.Exit(code)
	}
}

// exitCode is 3 for an infra error with no regression, else 1.
func exitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errInfra) && !errors.Is(err, errRegression):
		return 3
	default:
		return 1
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: perfrig run [flags] | perfrig compare -baseline FILE [-update] RESULT...")
	os.Exit(2)
}

func runCmd(ctx context.Context, args []string) error {
	var cfg config
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	fs.StringVar(&cfg.Workload, "workload", "iperf3-tcp", "workload: "+strings.Join(workloadNames(), ", "))
	fs.DurationVar(&cfg.Duration, "duration", 30*time.Second, "measured run length")
	fs.DurationVar(&cfg.Omit, "omit", 2*time.Second, "warm-up time before the measurement (iperf3 -O)")
	fs.DurationVar(&cfg.Delay, "delay", 10*time.Millisecond, "one-way delay in each direction (10ms gives 20 ms RTT)")
	fs.DurationVar(&cfg.Jitter, "jitter", 0, "delay jitter in each direction")
	fs.Float64Var(&cfg.Loss, "loss", 0, "random loss in percent in each direction, for example 0.1")
	fs.StringVar(&cfg.Rate, "rate", "", "netem rate limit in each direction, for example 10gbit (empty: no limit)")
	fs.IntVar(&cfg.MTU, "mtu", 1500, "MTU of the veth pair")
	fs.IntVar(&cfg.QueueLimit, "queue-limit", 100000, "netem queue limit in packets")
	fs.IntVar(&cfg.Streams, "streams", 1, "parallel flows")
	fs.StringVar(&cfg.Bitrate, "bitrate", "", "target bitrate of each flow (iperf3 -b); iperf3-udp uses 2G when empty")
	fs.StringVar(&cfg.Window, "window", "", "socket buffer size (iperf3 -w); iperf3-udp uses 8M when empty")
	fs.IntVar(&cfg.Pings, "pings", 20, "ping count for the RTT measurement")
	fs.IntVar(&cfg.Reps, "reps", 1, "runs, each with new server and client processes; the result has the median of each number")
	fs.StringVar(&cfg.Baseline, "baseline", "", "baseline file: when the median fails the entry of the key, run -reps more runs one time and use the median of all runs")
	fs.IntVar(&cfg.MinCPUs, "min-cpus", 0, "infra error when the host has fewer CPUs (0: no check)")
	fs.Float64Var(&cfg.MaxSteal, "max-steal", -1, "infra error when the CPU steal of a run is above this percent (negative: no check)")
	fs.StringVar(&cfg.NetnsPrefix, "netns-prefix", "perf", "prefix of the netns names")
	fs.StringVar(&cfg.OutDir, "out-dir", "", "keep the workload files and raw output in this directory")
	out := fs.String("out", "", "write the result JSON to this file (default: stdout)")
	fs.StringVar(&cfg.Name, "name", "", "exec workload: result name")
	fs.Var((*argvFlag)(&cfg.ServerArgv), "server-argv", `exec workload: JSON argv in the server netns, for example '["iperf3","-s"]'; $NAME and ${NAME} expand from the workload variables`)
	fs.Var((*argvFlag)(&cfg.ClientArgv), "client-argv", "exec workload: JSON argv in the client netns")
	fs.Var((*argvFlag)(&cfg.SidecarArgv), "sidecar-argv", "exec workload: JSON argv of a process in the server netns that runs while the server runs, for example a relay")
	fs.StringVar(&cfg.Ready, "ready", "none", "exec workload: socket that the server opens (tcp:PORT, udp:PORT or none)")
	_ = fs.Parse(args)

	if cfg.Duration < time.Second || cfg.Streams < 1 || cfg.MTU < 68 || cfg.Pings < 1 || cfg.Reps < 1 {
		return errors.New("bad flags: need -duration >= 1s, -streams >= 1, -mtu >= 68, -pings >= 1 and -reps >= 1")
	}
	w, err := newWorkload(cfg)
	if err != nil {
		return err
	}
	if cfg.Bitrate == "" {
		cfg.Bitrate = w.DefaultBitrate
	}
	if cfg.Window == "" {
		cfg.Window = w.DefaultWindow
	}

	// After an infra error, execute also returns the result, with infra_error set.
	res, runErr := execute(ctx, cfg, w)
	if res == nil {
		return runErr
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	slog.Info("Workload done", "workload", res.Workload, "reps", res.Reps, "gbps", res.Throughput.Gbps,
		"rtt_ms", res.RTT.Avg, "client_cores_per_gbps", res.CPU.Client.CoresPerGbps,
		"server_cores_per_gbps", res.CPU.Server.CoresPerGbps, "infra_error", res.InfraError)
	if *out == "" {
		_, err = os.Stdout.Write(data)
	} else {
		err = os.WriteFile(*out, data, 0o644)
	}
	return errors.Join(runErr, err)
}

func compareCmd(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	path := fs.String("baseline", "", "baseline JSON file")
	update := fs.Bool("update", false, "write the results into the baseline file instead of comparing")
	summary := fs.String("summary", "", "append a markdown table of the results to this file, for example $GITHUB_STEP_SUMMARY")
	_ = fs.Parse(args)
	if *path == "" || fs.NArg() == 0 {
		return errors.New("usage: perfrig compare -baseline FILE [-update] [-summary FILE] RESULT_FILE_OR_DIR...")
	}
	results, err := loadResults(fs.Args())
	if err != nil {
		return err
	}
	b, err := loadBaseline(*path, *update)
	if err != nil {
		return err
	}
	if *update {
		updateBaseline(os.Stdout, b, results)
		return saveBaseline(*path, b)
	}
	var report bytes.Buffer
	outcomes, err := compareResults(&report, b, results)
	if *summary != "" {
		if serr := appendSummary(*summary, outcomes); serr != nil {
			slog.Warn("Failed to write the summary", "path", *summary, "error", serr)
		}
	}
	os.Stdout.Write(report.Bytes())
	if err != nil {
		// A failed Dagger exec can show only stderr, so write the report there too.
		os.Stderr.Write(report.Bytes())
	}
	return err
}
