package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	clientIP  = "10.200.0.1"
	serverIP  = "10.200.0.2"
	relayIP   = "10.200.0.3"
	clientDev = "perf-c"
	serverDev = "perf-s"
	relayDev  = "perf-r"
	bridgeDev = "perf-br"

	// bufMax is the socket buffer limit: 128 MiB holds 20 ms of data at 50 Gbps.
	bufMax = "134217728"

	// vethQueues is the queue count of each veth of the relay rig, as the NIC
	// of the bench host has. With one queue, agents use one lane.
	vethQueues = 8
)

var errNetemMissing = errors.New("the kernel has no netem qdisc (sch_netem): " +
	"load it on the host with 'sudo modprobe sch_netem' " +
	"(on Ubuntu, first install linux-modules-extra-$(uname -r))")

// rigSysctls tune each netns for the BDP of 20 ms at multi-Gbps rates.
// Global keys (on older kernels all net.core.*) are not visible in a child
// netns; the host must set them (see .github/workflows/perf.yaml).
var rigSysctls = []struct{ key, value string }{
	{"net.ipv4.tcp_rmem", "4096 131072 " + bufMax},
	{"net.ipv4.tcp_wmem", "4096 16384 " + bufMax},
	{"net.core.rmem_max", bufMax},
	{"net.core.wmem_max", bufMax},
	// veth receive queues in the per-CPU backlog. netem sends bursts into it.
	{"net.core.netdev_max_backlog", "250000"},
}

// rig is two network namespaces joined by a veth pair, with netem on both ends.
// With -relay-netns, the sidecar runs in a relay netns, and a bridge in a
// fourth netns joins the client, the server and the relay.
type rig struct {
	client, server string
	relay, bridge  string // Empty without -relay-netns.
	cfg            config
}

func newRig(cfg config) *rig {
	r := &rig{client: cfg.NetnsPrefix + "-client", server: cfg.NetnsPrefix + "-server", cfg: cfg}
	if cfg.RelayNetns {
		r.relay, r.bridge = cfg.NetnsPrefix+"-relay", cfg.NetnsPrefix+"-bridge"
	}
	return r
}

// sidecarNetns is the netns of the sidecar.
func (r *rig) sidecarNetns() string {
	if r.relay != "" {
		return r.relay
	}
	return r.server
}

func (r *rig) setup(ctx context.Context) error {
	r.teardown()
	for _, s := range r.links() {
		if _, err := command(ctx, s...); err != nil {
			return err
		}
	}
	r.setRPS(ctx)
	if r.relay != "" {
		if err := r.tuneRelay(ctx); err != nil {
			return err
		}
	}

	loadNetem(ctx)
	for _, e := range []struct{ ns, dev string }{{r.client, clientDev}, {r.server, serverDev}} {
		out, err := command(ctx, netemArgs(e.ns, e.dev, r.cfg)...)
		if err != nil {
			if netemMissing(out) {
				return errNetemMissing
			}
			return err
		}
	}
	return nil
}

// loadNetem loads sch_netem. The kernel also loads it on demand, and it can be
// built in, so a failure is not an error.
func loadNetem(ctx context.Context) {
	if _, err := exec.LookPath("modprobe"); err == nil {
		if _, err := command(ctx, "modprobe", "sch_netem"); err != nil {
			slog.Debug("Failed to load sch_netem", "error", err)
		}
	}
}

// links returns the commands that add the netns and the links.
func (r *rig) links() [][]string {
	mtu, queues := strconv.Itoa(r.cfg.MTU), strconv.Itoa(vethQueues)
	ends := []struct{ ns, dev, ip string }{{r.client, clientDev, clientIP}, {r.server, serverDev, serverIP}}
	var steps [][]string
	if r.relay == "" {
		steps = [][]string{
			{"ip", "netns", "add", r.client},
			{"ip", "netns", "add", r.server},
			{"ip", "link", "add", clientDev, "netns", r.client, "type", "veth", "peer", "name", serverDev, "netns", r.server},
		}
	} else {
		ends = append(ends, struct{ ns, dev, ip string }{r.relay, relayDev, relayIP})
		steps = [][]string{
			{"ip", "netns", "add", r.bridge},
			{"ip", "-n", r.bridge, "link", "add", bridgeDev, "mtu", mtu, "type", "bridge"},
			{"ip", "-n", r.bridge, "link", "set", "dev", bridgeDev, "up"},
		}
		// The bridge port of each veth has the same name as its peer.
		for _, e := range ends {
			steps = append(steps,
				[]string{"ip", "netns", "add", e.ns},
				[]string{"ip", "-n", r.bridge, "link", "add", e.dev, "mtu", mtu, "numtxqueues", queues, "numrxqueues", queues,
					"type", "veth", "peer", "name", e.dev, "numtxqueues", queues, "numrxqueues", queues, "netns", e.ns},
				[]string{"ip", "-n", r.bridge, "link", "set", "dev", e.dev, "master", bridgeDev, "up"})
		}
	}
	for _, e := range ends {
		steps = append(steps, []string{"ip", "-n", e.ns, "addr", "add", e.ip + "/24", "dev", e.dev})
	}
	for _, e := range ends {
		steps = append(steps, []string{"ip", "-n", e.ns, "link", "set", "dev", e.dev, "mtu", mtu, "up"})
	}
	for _, e := range ends {
		steps = append(steps, []string{"ip", "-n", e.ns, "link", "set", "dev", "lo", "up"})
	}
	return steps
}

// tuneRelay makes the links of the relay rig like NIC links. The relay netns
// forwards, so that XDP can send packets on.
func (r *rig) tuneRelay(ctx context.Context) error {
	if err := writeIn(ctx, r.relay, "/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
		return err
	}
	for _, s := range r.relaySteps() {
		if _, err := command(ctx, s...); err != nil {
			return err
		}
	}
	return nil
}

// relaySteps returns the offload settings of the relay rig. The bridge port of the relay
// sends single packets with a checksum, as a wire does. Each end receives with GRO, as a NIC does.
func (r *rig) relaySteps() [][]string {
	steps := [][]string{{"ip", "netns", "exec", r.bridge, "ethtool", "-K", relayDev, "tx", "off"}}
	for _, e := range []rigLink{{r.relay, relayDev}, {r.client, clientDev}, {r.server, serverDev}} {
		if e.dev != relayDev {
			// A veth receives forwarded packets with GRO only when its peer has TSO off.
			steps = append(steps, []string{"ip", "netns", "exec", r.bridge, "ethtool", "-K", e.dev, "tso", "off"})
		}
		// Each end segments its UDP GSO packets, as ENA does. A packet that a bridge port
		// segments is one burst into the veth ring of 256 packets, and a full ring drops.
		steps = append(steps,
			[]string{"ip", "netns", "exec", e.ns, "ethtool", "-K", e.dev, "tx-udp-segmentation", "off"},
			[]string{"ip", "netns", "exec", e.ns, "ethtool", "-K", e.dev, "gro", "on"})
	}
	return steps
}

// setRPS sets the RPS and XPS masks of the veths.
func (r *rig) setRPS(ctx context.Context) {
	for _, w := range r.steering(runtime.NumCPU()) {
		if err := writeIn(ctx, w.ns, w.pattern, w.value); err != nil {
			slog.Warn("Failed to set packet steering on the veth", "netns", w.ns, "files", w.pattern, "error", err)
		}
	}
}

// sysfsWrite is a value for the sysfs files of pattern in a netns.
type sysfsWrite struct{ ns, pattern, value string }

// steering returns the RPS and XPS masks of the veths on a host with cpus CPUs. The RPS CPUs,
// by default all CPUs, receive one flow each. Without RPS, netem on a veth reorders packets.
func (r *rig) steering(cpus int) []sysfsWrite {
	rps, ring := cpuMask(cpus), cpuMask(min(vethQueues, cpus))
	if r.cfg.RPSCPUs != "" {
		m, err := cpuListMask(r.cfg.RPSCPUs, 0)
		if err != nil {
			slog.Warn("Bad RPS CPU list", "list", r.cfg.RPSCPUs, "error", err)
		} else {
			rps = m
			ring, _ = cpuListMask(r.cfg.RPSCPUs, vethQueues)
		}
	}
	var writes []sysfsWrite
	for _, e := range r.veths() {
		queues := "/sys/class/net/" + e.dev + "/queues/"
		switch {
		case r.relay == "":
			writes = append(writes, sysfsWrite{e.ns, queues + "rx-*/rps_cpus", rps})
		case e.ns == r.bridge:
			// A port has one CPU for each TX queue, and the flow hash selects the two, so one
			// CPU sends into each veth ring. More CPUs fill the ring of 256 packets, and it drops.
			writes = append(writes, sysfsWrite{e.ns, queues + "rx-*/rps_cpus", ring})
		default:
			// The end in a netns sends on queue 0. A port selects its TX queue from the
			// queue of the sender, and not from the flow hash, when that queue is not 0.
			writes = append(writes, sysfsWrite{e.ns, queues + "rx-*/rps_cpus", rps},
				sysfsWrite{e.ns, queues + "tx-0/xps_cpus", cpuMask(cpus)})
		}
	}
	return writes
}

// rigLink is one link of the rig in its netns.
type rigLink struct{ ns, dev string }

// veths returns each end of the veth pairs of the rig.
func (r *rig) veths() []rigLink {
	ends := []rigLink{{r.client, clientDev}, {r.server, serverDev}}
	if r.relay != "" {
		ends = append(ends, rigLink{r.relay, relayDev}, rigLink{r.bridge, clientDev}, rigLink{r.bridge, serverDev}, rigLink{r.bridge, relayDev})
	}
	return ends
}

// cpuMask returns the rps_cpus mask for n CPUs, in 32-bit hex groups with commas between them.
func cpuMask(n int) string {
	var groups []string
	for ; n > 0; n -= 32 {
		groups = append([]string{strconv.FormatUint(1<<min(n, 32)-1, 16)}, groups...)
	}
	return strings.Join(groups, ",")
}

// cpuListMask returns the rps_cpus mask of a CPU list such as "0-15,20". A limit
// above 0 keeps only the first limit CPUs.
func cpuListMask(list string, limit int) (string, error) {
	var cpus []int
	for _, part := range strings.Split(list, ",") {
		lo, hi, ok := strings.Cut(strings.TrimSpace(part), "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 {
			return "", fmt.Errorf("bad CPU %q", part)
		}
		b := a
		if ok {
			if b, err = strconv.Atoi(hi); err != nil || b < a {
				return "", fmt.Errorf("bad CPU range %q", part)
			}
		}
		for n := a; n <= b; n++ {
			cpus = append(cpus, n)
		}
	}
	slices.Sort(cpus)
	if cpus = slices.Compact(cpus); limit > 0 {
		cpus = cpus[:min(limit, len(cpus))]
	}
	bits := make([]uint32, cpus[len(cpus)-1]/32+1)
	for _, n := range cpus {
		bits[n/32] |= 1 << (n % 32)
	}
	groups := make([]string, 0, len(bits))
	for i := len(bits) - 1; i >= 0; i-- {
		groups = append(groups, strconv.FormatUint(uint64(bits[i]), 16))
	}
	return strings.Join(groups, ","), nil
}

// teardown deletes the netns. This also deletes the links.
func (r *rig) teardown() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, ns := range []string{r.client, r.server, r.relay, r.bridge} {
		if ns != "" {
			_, _ = command(ctx, "ip", "netns", "del", ns)
		}
	}
}

// netemArgs returns the tc command that sets netem on the egress of dev.
func netemArgs(ns, dev string, cfg config) []string {
	args := []string{"tc", "-n", ns, "qdisc", "replace", "dev", dev, "root", "netem", "limit", strconv.Itoa(cfg.QueueLimit)}
	if cfg.Delay > 0 || cfg.Jitter > 0 {
		args = append(args, "delay", formatMS(cfg.Delay))
		if cfg.Jitter > 0 {
			args = append(args, formatMS(cfg.Jitter))
		}
	}
	if cfg.Loss > 0 {
		args = append(args, "loss", formatFloat(cfg.Loss)+"%")
	}
	if cfg.Rate != "" {
		args = append(args, "rate", cfg.Rate)
	}
	return args
}

func netemMissing(tcOutput string) bool {
	out := strings.ToLower(tcOutput)
	return strings.Contains(out, "qdisc kind is unknown") ||
		strings.Contains(out, "specified qdisc not found") ||
		strings.Contains(out, "no such file or directory")
}

func formatMS(d time.Duration) string {
	return formatFloat(float64(d)/float64(time.Millisecond)) + "ms"
}

// tune sets rigSysctls in both netns and returns the values in the client netns.
func (r *rig) tune(ctx context.Context) map[string]string {
	got := map[string]string{}
	for _, s := range rigSysctls {
		path := "/proc/sys/" + strings.ReplaceAll(s.key, ".", "/")
		visible := true
		for _, ns := range []string{r.client, r.server} {
			// Exit code 3 tells that the key is not in this netns.
			err := writeIn(ctx, ns, path, s.value)
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && exitErr.ExitCode() == 3 {
				visible = false
				break
			}
			if err != nil {
				slog.Warn("Failed to set sysctl", "netns", ns, "key", s.key, "error", err)
			}
		}
		if visible {
			out, err := command(ctx, "ip", "netns", "exec", r.client, "cat", path)
			if err != nil {
				got[s.key] = "unknown"
				continue
			}
			got[s.key] = strings.Join(strings.Fields(out), " ")
			continue
		}
		slog.Warn("Sysctl is global; set it on the host", "key", s.key, "value", s.value)
		got[s.key] = "global, not visible"
	}
	if out, err := command(ctx, "ip", "netns", "exec", r.client, "cat", "/proc/sys/net/ipv4/tcp_congestion_control"); err == nil {
		got["net.ipv4.tcp_congestion_control"] = strings.TrimSpace(out)
	}
	return got
}

// ping measures the RTT from the client netns to the server.
func (r *rig) ping(ctx context.Context, count int) (RTT, error) {
	return pingRTT(ctx, []string{"ip", "netns", "exec", r.client}, serverIP, count)
}

// pingRTT measures the RTT to ip with count pings, run with the command prefix.
func pingRTT(ctx context.Context, prefix []string, ip string, count int) (RTT, error) {
	// The first packet waits for neighbor resolution. Do not count it.
	_, _ = command(ctx, append(slices.Clone(prefix), "ping", "-c", "1", "-W", "2", ip)...)
	out, err := command(ctx, append(slices.Clone(prefix), "ping", "-q",
		"-c", strconv.Itoa(count), "-i", "0.1", "-W", "2", ip)...)
	// ping exits with an error when replies are lost. The summary is still valid.
	rtt, perr := parsePing(out)
	if perr != nil {
		return RTT{}, fmt.Errorf("measure RTT to %s: %w (ping: %v)", ip, perr, err)
	}
	return rtt, nil
}

// waitPing waits until ip answers a ping, at most until timeout ends.
func waitPing(ctx context.Context, ip string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := command(ctx, "ping", "-c", "1", "-W", "2", ip); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not answer a ping in %s", ip, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// parsePing reads the summary of iputils ping or busybox ping.
func parsePing(out string) (RTT, error) {
	var rtt RTT
	found := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "% packet loss"); i >= 0 {
			j := strings.LastIndexByte(line[:i], ' ')
			if v, err := strconv.ParseFloat(line[j+1:i], 64); err == nil {
				rtt.LossPercent = v
			}
		}
		_, after, ok := strings.Cut(line, "min/avg/max")
		if !ok {
			continue
		}
		_, after, ok = strings.Cut(after, "=")
		if !ok {
			continue
		}
		fields := strings.Fields(after)
		if len(fields) == 0 {
			continue
		}
		parts := strings.Split(fields[0], "/")
		if len(parts) < 3 {
			return RTT{}, fmt.Errorf("bad ping summary: %q", line)
		}
		var v [4]float64
		for i, p := range parts[:min(len(parts), 4)] {
			f, err := strconv.ParseFloat(p, 64)
			if err != nil {
				return RTT{}, fmt.Errorf("bad ping summary: %q", line)
			}
			v[i] = f
		}
		rtt.Min, rtt.Avg, rtt.Max, rtt.Mdev = v[0], v[1], v[2], v[3]
		found = true
	}
	if !found {
		return RTT{}, errors.New("no RTT summary in ping output")
	}
	return rtt, nil
}

// command runs a program and returns its combined output.
func command(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
