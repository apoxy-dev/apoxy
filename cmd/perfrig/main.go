// Command perfrig is a network performance rig. "perfrig run" joins two network
// namespaces with a veth pair, adds netem delay, jitter, loss and rate limits
// on both ends, runs a server and a client workload, and prints a JSON result
// with RTT, throughput and CPU. "perfrig compare" checks results against a
// baseline file.
//
//	perfrig run -workload iperf3-tcp -streams 4 -duration 30s -reps 3
//	perfrig compare -baseline cmd/perfrig/baseline.json perf/
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
	default:
		usage()
	}
	if err != nil {
		slog.Error("Perf rig failed", "error", err)
		stop()
		os.Exit(1)
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
	fs.StringVar(&cfg.NetnsPrefix, "netns-prefix", "perf", "prefix of the netns names")
	fs.StringVar(&cfg.OutDir, "out-dir", "", "keep the workload files and raw output in this directory")
	out := fs.String("out", "", "write the result JSON to this file (default: stdout)")
	fs.StringVar(&cfg.Name, "name", "", "exec workload: result name")
	fs.StringVar(&cfg.ServerCmd, "server-cmd", "", "exec workload: shell command in the server netns")
	fs.StringVar(&cfg.ClientCmd, "client-cmd", "", "exec workload: shell command in the client netns")
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

	res, err := execute(ctx, cfg, w)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	slog.Info("Workload done", "workload", res.Workload, "reps", res.Reps, "gbps", res.Throughput.Gbps,
		"rtt_ms", res.RTT.Avg, "client_cores_per_gbps", res.CPU.Client.CoresPerGbps,
		"server_cores_per_gbps", res.CPU.Server.CoresPerGbps)
	if *out == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(*out, data, 0o644)
}

func compareCmd(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	path := fs.String("baseline", "", "baseline JSON file")
	update := fs.Bool("update", false, "write the results into the baseline file instead of comparing")
	_ = fs.Parse(args)
	if *path == "" || fs.NArg() == 0 {
		return errors.New("usage: perfrig compare -baseline FILE [-update] RESULT_FILE_OR_DIR...")
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
		for _, r := range results {
			e := entryFor(r)
			e.Tolerance = b.Entries[r.Key].Tolerance
			b.Entries[r.Key] = e
			fmt.Printf("SET %s\n", r.Key)
		}
		return saveBaseline(*path, b)
	}
	var report bytes.Buffer
	err = compareResults(&report, b, results)
	os.Stdout.Write(report.Bytes())
	if err != nil {
		// A failed Dagger exec can show only stderr, so write the report there too.
		os.Stderr.Write(report.Bytes())
	}
	return err
}
