package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// nodeRoles are the roles of "perfrig node". The relay role runs the sidecar argv.
var nodeRoles = map[string]bool{"client": true, "server": true, "relay": true}

// nodeFlag collects -node ROLE=IP flags.
type nodeFlag map[string]string

func (f nodeFlag) String() string {
	var parts []string
	for k, v := range f {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (f nodeFlag) Set(s string) error {
	role, ip, ok := strings.Cut(s, "=")
	if !ok || !nodeRoles[role] || ip == "" {
		return fmt.Errorf("want ROLE=IP with the role client, server or relay, got %q", s)
	}
	f[role] = ip
	return nil
}

// nodeCmd runs one role of an exec workload on this host, with the other roles
// on the hosts of the -node flags. Only the client result has the throughput.
func nodeCmd(ctx context.Context, args []string) error {
	var cfg config
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	role := fs.String("role", "", "role of this host: client, server or relay")
	nodes := nodeFlag{}
	fs.Var(nodes, "node", "ROLE=IP of another host, for example server=10.0.1.5; repeat for each host")
	wait := fs.Duration("wait-timeout", 5*time.Minute, "time for the other hosts to answer a ping")
	fs.DurationVar(&cfg.Duration, "duration", 30*time.Second, "measured run length")
	fs.DurationVar(&cfg.Omit, "omit", 2*time.Second, "warm-up time before the measurement")
	fs.IntVar(&cfg.Streams, "streams", 1, "parallel flows")
	fs.StringVar(&cfg.Bitrate, "bitrate", "", "target bitrate of each flow")
	fs.StringVar(&cfg.Window, "window", "", "socket buffer size")
	fs.IntVar(&cfg.Pings, "pings", 20, "ping count for the RTT measurement")
	fs.DurationVar(&cfg.Delay, "delay", 0, "netem delay on the egress of this host; 10ms on each host gives 20 ms RTT (0: no netem)")
	fs.IntVar(&cfg.QueueLimit, "queue-limit", 100000, "netem queue limit of each TX queue in packets, with -delay")
	fs.IntVar(&cfg.MinCPUs, "min-cpus", 0, "infra error when the host has fewer CPUs (0: no check)")
	fs.Float64Var(&cfg.MaxSteal, "max-steal", -1, "infra error when the CPU steal of the run is above this percent (negative: no check)")
	fs.StringVar(&cfg.HostClass, "host-class", "", "first word of the result key, for example the EC2 instance type (default: the arch)")
	fs.StringVar(&cfg.OutDir, "out-dir", "", "keep the workload files and raw output in this directory")
	fs.StringVar(&cfg.AppCPUs, "app-cpus", "", "pin the workload process to this CPU list (empty: no pin)")
	fs.BoolVar(&cfg.RelayXDP, "relay-xdp", false, "the relay host sets its link for XDP in driver mode during the row: at most half of the channels, MTU at most 3498 and IPv4 forwarding")
	fs.IntVar(&cfg.RelayChannels, "relay-channels", 0, "with -relay-xdp: the most channels of the relay link, so that few CPUs receive all packets (0: no limit)")
	fs.BoolVar(&cfg.RelayXDPGeneric, "relay-xdp-generic", false, "with -relay-xdp: the program runs in generic mode, so the relay host keeps its channels and MTU and sets only IPv4 forwarding")
	out := fs.String("out", "", "write the result JSON to this file (default: stdout)")
	fs.StringVar(&cfg.Name, "name", "", "result name")
	fs.Var((*argvFlag)(&cfg.ServerArgv), "server-argv", "JSON argv of the server role; $SERVER_IP, $RELAY_IP and $CLIENT_IP expand to the host addresses, and $DEV to the network device of this host")
	fs.Var((*argvFlag)(&cfg.ClientArgv), "client-argv", "JSON argv of the client role")
	fs.Var((*argvFlag)(&cfg.SidecarArgv), "sidecar-argv", "JSON argv of the relay role")
	_ = fs.Parse(args)

	if !nodeRoles[*role] {
		return fmt.Errorf("bad -role %q: want client, server or relay", *role)
	}
	if cfg.Duration < time.Second || cfg.Streams < 1 || cfg.Pings < 1 {
		return errors.New("bad flags: need -duration >= 1s, -streams >= 1 and -pings >= 1")
	}
	if cfg.Delay < 0 || (cfg.Delay > 0 && cfg.QueueLimit < 1) {
		return errors.New("bad flags: need -delay >= 0, and -queue-limit >= 1 with -delay")
	}
	if cfg.RelayChannels < 0 || (cfg.RelayChannels > 0 && !cfg.RelayXDP) {
		return errors.New("bad flags: need -relay-channels >= 0, and -relay-xdp with -relay-channels")
	}
	if cfg.RelayXDPGeneric && (!cfg.RelayXDP || cfg.RelayChannels > 0) {
		return errors.New("bad flags: need -relay-xdp and no -relay-channels with -relay-xdp-generic")
	}
	if strings.ContainsAny(cfg.HostClass, " \t\n") {
		return fmt.Errorf("bad -host-class %q: it must be one word", cfg.HostClass)
	}
	cfg.Workload = "exec"
	w, err := execWorkload(cfg)
	if err != nil {
		return err
	}
	if *role == "relay" && w.Sidecar == nil {
		return errors.New("the relay role needs -sidecar-argv")
	}
	res, runErr := executeNode(ctx, cfg, w, *role, nodes, *wait)
	if res == nil {
		return runErr
	}
	return errors.Join(runErr, writeResult(res, *out))
}

// executeNode waits for the other hosts, runs the role one time and measures
// the host. After an infra error, the result has InfraError.
func executeNode(ctx context.Context, cfg config, w Workload, role string, nodes nodeFlag, wait time.Duration) (*Result, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("perfrig node needs Linux")
	}
	if _, err := exec.LookPath("ping"); err != nil {
		return nil, fmt.Errorf("perfrig node needs ping: %w", err)
	}
	dev, err := defaultDev()
	if err != nil {
		return nil, err
	}
	ip, err := devIPv4(dev)
	if err != nil {
		return nil, err
	}
	if role == "relay" && cfg.RelayXDP {
		undo, err := prepareXDP(ctx, dev, ip, uint32(cfg.RelayChannels), cfg.RelayXDPGeneric, linkSettle)
		if err != nil {
			return nil, fmt.Errorf("set %s for XDP: %w", dev, err)
		}
		defer undo()
	}
	nic := nicFacts(ctx, dev)
	res := &Result{
		Workload:  w.Name,
		Role:      role,
		StartedAt: time.Now().UTC(),
		Host:      Host{Arch: hostArch(), Class: cfg.HostClass, Kernel: kernelRelease(), CPUs: runtime.NumCPU(), CPUModel: cpuModel(), NIC: nic},
		Settings:  Settings{DurationS: cfg.Duration.Seconds(), OmitS: cfg.Omit.Seconds(), MTU: nic.MTU, Streams: cfg.Streams, Bitrate: cfg.Bitrate, Window: cfg.Window},
		Sysctls:   readSysctls(),
	}
	if cfg.Delay > 0 {
		res.Settings.DelayMS, res.Settings.QueueLimit = float64(cfg.Delay)/float64(time.Millisecond), cfg.QueueLimit
	}
	res.Key = resultKey(res.Host.keyClass(), w.Name, res.Settings)
	infra := func(err error) (*Result, error) {
		res.InfraError = err.Error()
		return res, fmt.Errorf("%w: %w", errInfra, err)
	}
	if cfg.MinCPUs > 0 && res.Host.CPUs < cfg.MinCPUs {
		return infra(fmt.Errorf("the host has %d CPUs, fewer than -min-cpus %d", res.Host.CPUs, cfg.MinCPUs))
	}
	if cfg.Delay > 0 {
		if err := setNodeNetem(ctx, dev, cfg); err != nil {
			return nil, err
		}
		defer clearNodeNetem(dev)
	}
	slog.Info("Host facts", "role", role, "ip", ip, "dev", dev, "driver", nic.Driver, "version", nic.Version,
		"rx_queues", nic.RxQueues, "xdp_features", nic.XDPFeatures, "nodes", nodes.String())

	env := Env{
		ServerIP: nodes["server"], ClientIP: nodes["client"], RelayIP: nodes["relay"],
		Duration: cfg.Duration, Omit: cfg.Omit, Streams: cfg.Streams, Bitrate: cfg.Bitrate, Window: cfg.Window,
		Dir: cfg.OutDir, Dev: dev,
	}
	switch role {
	case "client":
		env.ClientIP = ip
	case "server":
		env.ServerIP = ip
	case "relay":
		env.RelayIP = ip
	}
	if env.Dir == "" {
		tmp, err := os.MkdirTemp("", "perfrig-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		env.Dir = tmp
	} else if err := os.MkdirAll(env.Dir, 0o755); err != nil {
		return nil, err
	}

	// The relay host has nothing to wait for. The server waits for the relay
	// and the client waits for both.
	var peers []string
	if role == "client" {
		if env.ServerIP == "" {
			return nil, errors.New("the client role needs -node server=IP")
		}
		peers = append(peers, env.ServerIP)
	}
	if role != "relay" && env.RelayIP != "" {
		peers = append(peers, env.RelayIP)
	}
	for _, peer := range peers {
		if err := waitPing(ctx, peer, wait); err != nil {
			return infra(err)
		}
	}
	if role == "client" {
		rtt, err := pingRTT(ctx, nil, env.ServerIP, cfg.Pings)
		if err != nil {
			return infra(err)
		}
		res.RTT = rtt
		slog.Info("Measured RTT to the server", "avg_ms", rtt.Avg, "min_ms", rtt.Min, "max_ms", rtt.Max)
		if env.RelayIP != "" {
			rtt, err := pingRTT(ctx, nil, env.RelayIP, cfg.Pings)
			if err != nil && cfg.RelayXDP {
				// The link of the relay host stops for a short time when the host sets it for XDP.
				if err = waitPing(ctx, env.RelayIP, wait); err == nil {
					rtt, err = pingRTT(ctx, nil, env.RelayIP, cfg.Pings)
				}
			}
			if err != nil {
				return infra(err)
			}
			res.RelayRTT = &rtt
			slog.Info("Measured RTT to the relay", "avg_ms", rtt.Avg, "min_ms", rtt.Min, "max_ms", rtt.Max)
		}
	}

	run, err := nodeRep(ctx, cfg, w, role, env, dev, wait)
	if err != nil {
		return nil, err
	}
	res.Runs = []Run{run}
	res.summarize()
	if err := stealErr(run, cfg.MaxSteal); err != nil {
		return infra(err)
	}
	return res, nil
}

// nodeRep runs the role one time and measures its process, the host and the NIC.
// The server ends when the client disconnects, the relay when the client stops it.
func nodeRep(ctx context.Context, cfg config, w Workload, role string, env Env, dev string, wait time.Duration) (Run, error) {
	var argv []string
	switch role {
	case "client":
		argv = w.Client(env)
	case "server":
		argv = w.Server(env)
	case "relay":
		argv = w.Sidecar(env)
	}
	var prefix []string
	if cfg.AppCPUs != "" {
		prefix = []string{"taskset", "-c", cfg.AppCPUs}
	}
	run := Run{Rep: 1, StartedAt: time.Now().UTC(), Load1Start: load1()}
	nic0 := nicCounters(ctx, dev)
	// A read after the row finds no queue packets on the relay host of an XDP row.
	peak := func() map[string]int64 { return nil }
	if role == "relay" && cfg.RelayXDP {
		peak = peakCounters(ctx, dev, time.Second)
	}
	host0, hostErr := readCPUTimes()
	start := time.Now()
	p, err := startProc(role, "", argv, env.vars(), prefix)
	if err != nil {
		return Run{}, err
	}
	// The client can wait for the other hosts before it starts the flows.
	timeout := time.Duration(math.MaxInt64)
	if role == "client" {
		timeout = cfg.Duration + cfg.Omit + wait + time.Minute
	}
	waitErr := p.wait(ctx, timeout)
	elapsed := time.Since(start).Seconds()
	host1, hostErr2 := readCPUTimes()
	nic1 := maxCounters(peak(), nicCounters(ctx, dev))
	writeOutput(env.Dir, cfg.OutDir != "", p)
	switch {
	case waitErr != nil && role == "client":
		return Run{}, fmt.Errorf("client failed: %w\n%s", waitErr, tail(p.out.String(), 20))
	case waitErr != nil && ctx.Err() == nil:
		return Run{}, fmt.Errorf("%s failed: %w", role, waitErr)
	case waitErr != nil:
		slog.Info("The row ended and stopped the process", "role", role, "error", waitErr)
	}

	run.CPU.WallS = round(elapsed, 3)
	cu, cs := p.cpu()
	gbps := 0.0
	if role == "client" {
		tp, err := w.Parse(p.out.Bytes(), nil)
		if err != nil {
			return Run{}, err
		}
		if tp.Seconds <= 0 {
			tp.Seconds = cfg.Duration.Seconds()
		}
		if tp.BitsPerSecond > 0 {
			tp.Gbps = round(tp.BitsPerSecond/1e9, 3)
		}
		run.Throughput = tp
		gbps = tp.BitsPerSecond / 1e9
		run.WorkloadResult = jsonObjectLine(p.out.Bytes())
		// The other hosts measure their CPU in the window and report it in the marks.
		if c := markCPU(run.WorkloadResult, "server"); c != nil {
			run.CPU.Server = ProcCPU{Cores: c.Cores, CoresPerGbps: c.CoresPerGbps}
		}
		run.CPU.Relay = markCPU(run.WorkloadResult, "relay")
	}
	switch role {
	case "client":
		run.CPU.Client = newProcCPU(cu, cs, elapsed, gbps)
		// The marks leave out the wait for the other hosts.
		if c := markCPU(run.WorkloadResult, "client"); c != nil {
			run.CPU.Client.Cores, run.CPU.Client.CoresPerGbps = c.Cores, c.CoresPerGbps
		}
	case "server":
		run.CPU.Server = newProcCPU(cu, cs, elapsed, gbps)
	case "relay":
		c := newProcCPU(cu, cs, elapsed, gbps)
		run.CPU.Relay = &RelayCPU{Cores: c.Cores}
	}
	if hostErr == nil && hostErr2 == nil {
		run.StealPercent = stealPercent(host0, host1)
		run.CPU.Host = HostCPU{
			UserS:   round(host1.User-host0.User, 3),
			SystemS: round(host1.System-host0.System, 3),
			IRQS:    round(host1.IRQ-host0.IRQ, 3),
			TotalS:  round(host1.total()-host0.total(), 3),
			Cores:   round((host1.total()-host0.total())/elapsed, 3),
		}
	}
	run.NIC = counterDeltas(nic0, nic1)
	run.Load1End = load1()
	slog.Info("Rep done", "role", role, "gbps", run.Throughput.Gbps, "seconds", run.CPU.WallS,
		"steal_percent", run.StealPercent, "nic_counters", run.NIC)
	return run, nil
}

// nodeNetemSteps returns the tc commands that delay the egress of dev with netem.
// A device with more than one TX queue gets one netem for each queue, so that
// the queues send in parallel as they do with no netem.
func nodeNetemSteps(dev string, txQueues int, cfg config) [][]string {
	netem := []string{"netem", "limit", strconv.Itoa(cfg.QueueLimit), "delay", formatMS(cfg.Delay)}
	if txQueues <= 1 {
		return [][]string{append([]string{"tc", "qdisc", "replace", "dev", dev, "root"}, netem...)}
	}
	steps := [][]string{{"tc", "qdisc", "replace", "dev", dev, "root", "handle", "1:", "mq"}}
	for q := 1; q <= txQueues; q++ {
		// The class of TX queue q-1 is 1:q in hex.
		parent := "1:" + strconv.FormatInt(int64(q), 16)
		steps = append(steps, append([]string{"tc", "qdisc", "replace", "dev", dev, "parent", parent}, netem...))
	}
	return steps
}

// setNodeNetem adds the netem delay of cfg to the egress of dev.
func setNodeNetem(ctx context.Context, dev string, cfg config) error {
	loadNetem(ctx)
	queues, _ := filepath.Glob("/sys/class/net/" + dev + "/queues/tx-*")
	for _, s := range nodeNetemSteps(dev, len(queues), cfg) {
		if out, err := command(ctx, s...); err != nil {
			clearNodeNetem(dev)
			if netemMissing(out) {
				return errNetemMissing
			}
			return err
		}
	}
	slog.Info("Added netem to the egress of the host", "dev", dev, "tx_queues", len(queues), "delay", cfg.Delay, "limit", cfg.QueueLimit)
	return nil
}

// clearNodeNetem gives dev its default qdisc again. It runs also after the row
// ends and stops the process, so it does not use the context of the row.
func clearNodeNetem(dev string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := command(ctx, "tc", "qdisc", "del", "dev", dev, "root"); err != nil {
		slog.Warn("Failed to remove netem from the host", "dev", dev, "error", err)
	}
}

// readSysctls returns the host values of the rig sysctls and the congestion control.
func readSysctls() map[string]string {
	got := map[string]string{}
	for _, s := range rigSysctls {
		out, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(s.key, ".", "/"))
		if err != nil {
			got[s.key] = "unknown"
			continue
		}
		got[s.key] = strings.Join(strings.Fields(string(out)), " ")
	}
	if out, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control"); err == nil {
		got["net.ipv4.tcp_congestion_control"] = strings.TrimSpace(string(out))
	}
	return got
}
