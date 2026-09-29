package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// config holds the flags of "perfrig run".
type config struct {
	Workload    string
	Duration    time.Duration
	Omit        time.Duration
	Delay       time.Duration
	Jitter      time.Duration
	Loss        float64
	Rate        string
	MTU         int
	QueueLimit  int
	Streams     int
	Bitrate     string
	Window      string
	Pings       int
	NetnsPrefix string
	OutDir      string

	// Exec workload flags.
	Name      string
	ServerCmd string
	ClientCmd string
	Ready     string
}

func (c config) settings() Settings {
	return Settings{
		DurationS:   c.Duration.Seconds(),
		OmitS:       c.Omit.Seconds(),
		DelayMS:     float64(c.Delay) / float64(time.Millisecond),
		JitterMS:    float64(c.Jitter) / float64(time.Millisecond),
		LossPercent: c.Loss,
		Rate:        c.Rate,
		MTU:         c.MTU,
		QueueLimit:  c.QueueLimit,
		Streams:     c.Streams,
		Bitrate:     c.Bitrate,
		Window:      c.Window,
	}
}

// execute builds the rig, runs the workload once and removes the rig.
func execute(ctx context.Context, cfg config, w Workload) (*Result, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("perfrig run needs Linux")
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("perfrig run needs root: run it in a privileged container or with sudo")
	}
	for _, bin := range []string{"ip", "tc", "ping"} {
		if _, err := exec.LookPath(bin); err != nil {
			return nil, fmt.Errorf("perfrig run needs %s (iproute2 and ping): %w", bin, err)
		}
	}
	res := &Result{
		Workload:  w.Name,
		StartedAt: time.Now().UTC(),
		Host:      Host{Arch: hostArch(), Kernel: kernelRelease(), CPUs: runtime.NumCPU()},
		Settings:  cfg.settings(),
	}
	res.Key = resultKey(res.Host.Arch, w.Name, res.Settings)
	if w.Tools != nil {
		tools, err := w.Tools(ctx)
		if err != nil {
			return nil, err
		}
		res.Tools = tools
	}

	dir := cfg.OutDir
	if dir == "" {
		tmp, err := os.MkdirTemp("", "perfrig-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		dir = tmp
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	r := newRig(cfg)
	defer r.teardown()
	if err := r.setup(ctx); err != nil {
		return nil, err
	}
	res.Sysctls = r.tune(ctx)
	rtt, err := r.ping(ctx, cfg.Pings)
	if err != nil {
		return nil, err
	}
	res.RTT = rtt
	slog.Info("Measured RTT", "avg_ms", rtt.Avg, "min_ms", rtt.Min, "max_ms", rtt.Max)

	env := Env{
		ServerIP: serverIP,
		ClientIP: clientIP,
		Duration: cfg.Duration,
		Omit:     cfg.Omit,
		Streams:  cfg.Streams,
		Bitrate:  cfg.Bitrate,
		Window:   cfg.Window,
		Dir:      dir,
	}
	server, err := startProc("server", r.server, w.Server(env), env.vars())
	if err != nil {
		return nil, err
	}
	defer server.stop()
	if err := waitReady(ctx, server, w.Ready, 30*time.Second); err != nil {
		return nil, err
	}

	slog.Info("Starting workload", "workload", w.Name, "key", res.Key)
	hostBefore, hostErr := readCPUTimes()
	start := time.Now()
	client, err := startProc("client", r.client, w.Client(env), env.vars())
	if err != nil {
		return nil, err
	}
	clientErr := client.wait(ctx, cfg.Duration+cfg.Omit+time.Minute)
	elapsed := time.Since(start).Seconds()
	hostAfter, hostErr2 := readCPUTimes()
	// Let the server write its report and exit, then stop it.
	_ = server.wait(ctx, 10*time.Second)

	writeOutput(dir, cfg.OutDir != "", client, server)
	if clientErr != nil {
		return nil, fmt.Errorf("client failed: %w\n%s", clientErr, tail(client.out.String(), 20))
	}
	tp, err := w.Parse(client.out.Bytes(), server.out.Bytes())
	if err != nil {
		return nil, err
	}
	if tp.Seconds <= 0 {
		tp.Seconds = cfg.Duration.Seconds()
	}
	if tp.BitsPerSecond > 0 {
		tp.Gbps = round(tp.BitsPerSecond/1e9, 3)
	}
	res.Throughput = tp

	// Rusage includes the warm-up, so divide by the client wall time, not tp.Seconds.
	gbps := tp.BitsPerSecond / 1e9
	cu, cs := client.cpu()
	su, ss := server.cpu()
	res.CPU.WallS = round(elapsed, 3)
	res.CPU.Client = newProcCPU(cu, cs, elapsed, gbps)
	res.CPU.Server = newProcCPU(su, ss, elapsed, gbps)
	if hostErr == nil && hostErr2 == nil {
		res.CPU.Host = HostCPU{
			UserS:   round(hostAfter.User-hostBefore.User, 3),
			SystemS: round(hostAfter.System-hostBefore.System, 3),
			IRQS:    round(hostAfter.IRQ-hostBefore.IRQ, 3),
			TotalS:  round(hostAfter.total()-hostBefore.total(), 3),
			Cores:   round((hostAfter.total()-hostBefore.total())/elapsed, 3),
		}
	}
	return res, nil
}

func waitReady(ctx context.Context, p *proc, s Socket, timeout time.Duration) error {
	if s.Port == 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			return nil
		}
	}
	deadline := time.Now().Add(timeout)
	for {
		if p.exited() {
			return fmt.Errorf("server exited before it opened %s: %v\n%s", s, p.err, tail(p.out.String(), 20))
		}
		if socketOpen(p.cmd.Process.Pid, s) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("server did not open %s in %s", s, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// proc is a workload process in a netns. "ip netns exec" replaces itself with
// the command, so the rusage of proc covers the command and the children that
// it waited for.
type proc struct {
	name string
	cmd  *exec.Cmd
	out  bytes.Buffer
	done chan struct{}
	err  error
}

func startProc(name, ns string, argv, env []string) (*proc, error) {
	p := &proc{name: name, done: make(chan struct{})}
	p.cmd = exec.Command("ip", append([]string{"netns", "exec", ns}, argv...)...)
	p.cmd.Env = append(os.Environ(), env...)
	p.cmd.Stdout = &p.out
	p.cmd.Stderr = os.Stderr
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	slog.Debug("Starting process", "side", name, "netns", ns, "argv", argv)
	if err := p.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

func (p *proc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// wait waits for the process to exit. On timeout it stops the process.
func (p *proc) wait(ctx context.Context, timeout time.Duration) error {
	select {
	case <-p.done:
		return p.err
	case <-ctx.Done():
		p.stop()
		return ctx.Err()
	case <-time.After(timeout):
		p.stop()
		return fmt.Errorf("%s did not exit in %s", p.name, timeout)
	}
}

// stop sends SIGINT to the process group, then SIGKILL after 5 s.
func (p *proc) stop() {
	if p.exited() {
		return
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGINT)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
	}
}

// cpu returns user and system seconds. Call it after the process exits.
func (p *proc) cpu() (user, system float64) {
	if p.cmd.ProcessState == nil {
		return 0, 0
	}
	ru, ok := p.cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok {
		return 0, 0
	}
	return time.Duration(ru.Utime.Nano()).Seconds(), time.Duration(ru.Stime.Nano()).Seconds()
}

func writeOutput(dir string, keep bool, procs ...*proc) {
	if !keep {
		return
	}
	for _, p := range procs {
		if !p.exited() {
			continue
		}
		path := filepath.Join(dir, p.name+".out")
		if err := os.WriteFile(path, p.out.Bytes(), 0o644); err != nil {
			slog.Warn("Failed to write workload output", "path", path, "error", err)
		}
	}
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// tail returns the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
