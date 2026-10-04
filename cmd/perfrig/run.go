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
	"strconv"
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
	Reps        int
	Baseline    string
	MinCPUs     int
	MaxSteal    float64
	NetnsPrefix string
	HostClass   string
	OutDir      string
	// AppCPUs pins the workload processes to these CPUs (taskset -c). Empty: no pin.
	AppCPUs string
	// RPSCPUs are the CPUs that receive on the veths. Empty: all CPUs.
	RPSCPUs string

	// Exec workload flags.
	Name        string
	ServerArgv  []string
	ClientArgv  []string
	SidecarArgv []string
	Ready       string
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

// errSteal is CPU steal above -max-steal in a rep.
var errSteal = errors.New("too much CPU steal")

// stealErr returns an errSteal error when the steal of run is above max. A negative max is no check.
func stealErr(run Run, max float64) error {
	if max < 0 || run.StealPercent <= max {
		return nil
	}
	return fmt.Errorf("%w: %.2f%% in rep %d, -max-steal is %g%%", errSteal, run.StealPercent, run.Rep, max)
}

// execute builds the rig, runs the workload cfg.Reps times and removes the
// rig. Each rep has new server and client processes. When the median fails the
// baseline entry of the key, it runs cfg.Reps more times one time. After an
// infra error, it returns the result with InfraError set and an errInfra error.
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
		Host:      Host{Arch: hostArch(), Class: cfg.HostClass, Kernel: kernelRelease(), CPUs: runtime.NumCPU(), CPUModel: cpuModel()},
		Settings:  cfg.settings(),
	}
	res.Key = resultKey(res.Host.keyClass(), w.Name, res.Settings)
	var base *Baseline
	if cfg.Baseline != "" {
		b, err := loadBaseline(cfg.Baseline, false)
		if err != nil {
			return nil, err
		}
		base = &b
	}
	infra := func(err error) (*Result, error) {
		res.InfraError = err.Error()
		return res, fmt.Errorf("%w: %w", errInfra, err)
	}
	if cfg.MinCPUs > 0 && res.Host.CPUs < cfg.MinCPUs {
		return infra(fmt.Errorf("the host has %d CPUs, fewer than -min-cpus %d", res.Host.CPUs, cfg.MinCPUs))
	}
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
		return infra(fmt.Errorf("rig setup: %w", err))
	}
	res.Sysctls = r.tune(ctx)
	rtt, err := r.ping(ctx, cfg.Pings)
	if err != nil {
		return infra(err)
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
	slog.Info("Starting workload", "workload", w.Name, "key", res.Key, "reps", cfg.Reps)
	runReps := func(from, to int) error {
		defer res.summarize()
		for rep := from; rep <= to; rep++ {
			run, err := runRep(ctx, cfg, w, r, env, rep)
			if err != nil {
				return fmt.Errorf("rep %d: %w", rep, err)
			}
			res.Runs = append(res.Runs, run)
			if err := stealErr(run, cfg.MaxSteal); err != nil {
				return err
			}
		}
		return nil
	}
	repsErr := runReps(1, cfg.Reps)
	if repsErr == nil && base != nil && needsRetry(*base, *res) {
		slog.Warn("Median failed the baseline, running the reps again", "key", res.Key, "gbps", res.Throughput.Gbps)
		res.Retried = true
		repsErr = runReps(cfg.Reps+1, 2*cfg.Reps)
	}
	switch {
	case errors.Is(repsErr, errSteal):
		return infra(repsErr)
	case repsErr != nil:
		return nil, repsErr
	}
	return res, nil
}

// runRep starts the server and the client one time and measures them. When
// there can be more than one rep, each rep has its own directory in env.Dir.
func runRep(ctx context.Context, cfg config, w Workload, r *rig, env Env, rep int) (Run, error) {
	if cfg.Reps > 1 || cfg.Baseline != "" {
		env.Dir = filepath.Join(env.Dir, "rep-"+strconv.Itoa(rep))
		if err := os.MkdirAll(env.Dir, 0o755); err != nil {
			return Run{}, err
		}
	}
	run := Run{Rep: rep, StartedAt: time.Now().UTC(), Load1Start: load1()}
	var side sideProcs
	var prefix []string
	if cfg.AppCPUs != "" {
		prefix = []string{"taskset", "-c", cfg.AppCPUs}
	}
	if w.Sidecar != nil {
		sidecar, err := startProc("sidecar", r.server, w.Sidecar(env), env.vars(), prefix)
		if err != nil {
			return Run{}, err
		}
		defer sidecar.stop()
		side = append(side, sidecar)
	}
	server, err := startProc("server", r.server, w.Server(env), env.vars(), prefix)
	if err != nil {
		return Run{}, err
	}
	defer server.stop()
	side = append(side, server)
	if err := waitReady(ctx, server, w.Ready, 30*time.Second); err != nil {
		return Run{}, err
	}

	hostBefore, hostErr := readCPUTimes()
	su0, ss0, serverErr := side.cpuNow()
	start := time.Now()
	client, err := startProc("client", r.client, w.Client(env), env.vars(), prefix)
	if err != nil {
		return Run{}, err
	}
	clientErr := client.wait(ctx, cfg.Duration+cfg.Omit+time.Minute)
	elapsed := time.Since(start).Seconds()
	hostAfter, hostErr2 := readCPUTimes()
	su1, ss1, serverErr2 := side.cpuNow()
	// Let the server write its report and exit, then stop it and the sidecar.
	_ = server.wait(ctx, 10*time.Second)
	for _, p := range side {
		p.stop()
	}

	writeOutput(env.Dir, cfg.OutDir != "", append([]*proc{client}, side...)...)
	if clientErr != nil {
		return Run{}, fmt.Errorf("client failed: %w\n%s", clientErr, tail(client.out.String(), 20))
	}
	tp, err := w.Parse(client.out.Bytes(), server.out.Bytes())
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

	// CPU times include the warm-up, so divide by the client wall time, not tp.Seconds.
	gbps := tp.BitsPerSecond / 1e9
	cu, cs := client.cpu()
	run.CPU.WallS = round(elapsed, 3)
	run.CPU.Client = newProcCPU(cu, cs, elapsed, gbps)
	if err := errors.Join(serverErr, serverErr2); err != nil {
		slog.Warn("Failed to measure server CPU", "error", err)
	} else {
		run.CPU.Server = newProcCPU(su1-su0, ss1-ss0, elapsed, gbps)
	}
	if hostErr == nil && hostErr2 == nil {
		run.StealPercent = stealPercent(hostBefore, hostAfter)
		run.CPU.Host = HostCPU{
			UserS:   round(hostAfter.User-hostBefore.User, 3),
			SystemS: round(hostAfter.System-hostBefore.System, 3),
			IRQS:    round(hostAfter.IRQ-hostBefore.IRQ, 3),
			TotalS:  round(hostAfter.total()-hostBefore.total(), 3),
			Cores:   round((hostAfter.total()-hostBefore.total())/elapsed, 3),
		}
	}
	run.WorkloadResult = jsonObjectLine(client.out.Bytes())
	run.CPU.Relay = relayCPU(run.WorkloadResult)
	run.Load1End = load1()
	slog.Info("Rep done", "rep", rep, "gbps", tp.Gbps, "load1_start", run.Load1Start, "load1_end", run.Load1End,
		"steal_percent", run.StealPercent)
	return run, nil
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

// waitDelay is the time that Wait waits for the output pipes after the process exits.
const waitDelay = 2 * time.Second

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

func startProc(name, ns string, argv, env, prefix []string) (*proc, error) {
	p := &proc{name: name, done: make(chan struct{})}
	full := append(append(append([]string{}, prefix...), "ip", "netns", "exec", ns), argv...)
	p.cmd = exec.Command(full[0], full[1:]...)
	p.cmd.Env = append(os.Environ(), env...)
	p.cmd.Stdout = &p.out
	p.cmd.Stderr = os.Stderr
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// A child of the process can keep stdout open after the process exits.
	// Wait then closes the pipe after this delay.
	p.cmd.WaitDelay = waitDelay
	slog.Debug("Starting process", "side", name, "netns", ns, "argv", argv)
	if err := p.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	go func() {
		p.err = p.cmd.Wait()
		if errors.Is(p.err, exec.ErrWaitDelay) {
			slog.Warn("A child process kept the output open after the process exited", "side", name)
			p.err = nil
		}
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

// sideProcs are the processes in the server netns: the sidecar, if any, and the server.
type sideProcs []*proc

// cpuNow returns the sum of cpuNow of each process.
func (ps sideProcs) cpuNow() (user, system float64, err error) {
	for _, p := range ps {
		u, s, perr := p.cpuNow()
		user, system, err = user+u, system+s, errors.Join(err, perr)
	}
	return user, system, err
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

// cpuNow returns the user and system seconds that the process tree used until
// now. After the process exits, it returns the rusage of the process.
func (p *proc) cpuNow() (user, system float64, err error) {
	if !p.exited() {
		user, system, err = treeCPU(p.cmd.Process.Pid)
		if !errors.Is(err, errNoProcess) {
			return user, system, err
		}
		// The process exited after the check. Wait until Wait returns.
		select {
		case <-p.done:
		case <-time.After(time.Second):
			return 0, 0, err
		}
	}
	user, system = p.cpu()
	return user, system, nil
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
