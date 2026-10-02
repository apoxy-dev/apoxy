package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	clientIP  = "10.200.0.1"
	serverIP  = "10.200.0.2"
	clientDev = "perf-c"
	serverDev = "perf-s"

	// bufMax is the socket buffer limit: 128 MiB holds 20 ms of data at 50 Gbps.
	bufMax = "134217728"
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
type rig struct {
	client, server string
	cfg            config
}

func newRig(cfg config) *rig {
	return &rig{client: cfg.NetnsPrefix + "-client", server: cfg.NetnsPrefix + "-server", cfg: cfg}
}

func (r *rig) setup(ctx context.Context) error {
	r.teardown()
	mtu := strconv.Itoa(r.cfg.MTU)
	steps := [][]string{
		{"ip", "netns", "add", r.client},
		{"ip", "netns", "add", r.server},
		{"ip", "link", "add", clientDev, "netns", r.client, "type", "veth", "peer", "name", serverDev, "netns", r.server},
		{"ip", "-n", r.client, "addr", "add", clientIP + "/24", "dev", clientDev},
		{"ip", "-n", r.server, "addr", "add", serverIP + "/24", "dev", serverDev},
		{"ip", "-n", r.client, "link", "set", "dev", clientDev, "mtu", mtu, "up"},
		{"ip", "-n", r.server, "link", "set", "dev", serverDev, "mtu", mtu, "up"},
		{"ip", "-n", r.client, "link", "set", "dev", "lo", "up"},
		{"ip", "-n", r.server, "link", "set", "dev", "lo", "up"},
	}
	for _, s := range steps {
		if _, err := command(ctx, s...); err != nil {
			return err
		}
	}
	r.setRPS(ctx)

	// The kernel loads sch_netem on demand when modprobe can find it. Try it here
	// too; a failure is not an error because netem can be built in.
	if _, err := exec.LookPath("modprobe"); err == nil {
		if _, err := command(ctx, "modprobe", "sch_netem"); err != nil {
			slog.Debug("modprobe sch_netem failed", "error", err)
		}
	}
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

// setRPS lets all CPUs receive on the veths, one CPU per flow. Without RPS, netem on a veth reorders packets.
func (r *rig) setRPS(ctx context.Context) {
	mask := cpuMask(runtime.NumCPU())
	for _, e := range []struct{ ns, dev string }{{r.client, clientDev}, {r.server, serverDev}} {
		_, err := command(ctx, "ip", "netns", "exec", e.ns, "sh", "-c",
			`for q in /sys/class/net/"$2"/queues/rx-*; do printf '%s\n' "$1" > "$q/rps_cpus" || exit 1; done`, "sh", mask, e.dev)
		if err != nil {
			slog.Warn("Failed to set RPS on the veth", "netns", e.ns, "dev", e.dev, "error", err)
		}
	}
}

// cpuMask returns the rps_cpus mask for n CPUs, in 32-bit hex groups with commas between them.
func cpuMask(n int) string {
	var groups []string
	for ; n > 0; n -= 32 {
		groups = append([]string{strconv.FormatUint(1<<min(n, 32)-1, 16)}, groups...)
	}
	return strings.Join(groups, ",")
}

// teardown deletes both netns. This also deletes the veth pair.
func (r *rig) teardown() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, ns := range []string{r.client, r.server} {
		_, _ = command(ctx, "ip", "netns", "del", ns)
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
			_, err := command(ctx, "ip", "netns", "exec", ns, "sh", "-c",
				`test -e "$2" || exit 3; printf '%s\n' "$1" > "$2"`, "sh", s.value, path)
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
	// The first packet waits for neighbor resolution. Do not count it.
	_, _ = command(ctx, "ip", "netns", "exec", r.client, "ping", "-c", "1", "-W", "2", serverIP)
	out, err := command(ctx, "ip", "netns", "exec", r.client, "ping", "-q",
		"-c", strconv.Itoa(count), "-i", "0.1", "-W", "2", serverIP)
	// ping exits with an error when replies are lost. The summary is still valid.
	rtt, perr := parsePing(out)
	if perr != nil {
		return RTT{}, fmt.Errorf("measure RTT: %w (ping: %v)", perr, err)
	}
	return rtt, nil
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
