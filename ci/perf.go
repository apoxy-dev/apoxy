package main

import (
	"context"
	"strconv"
	"time"

	"dagger/apoxy-cli/internal/dagger"
)

// perfRigImage has iperf3 3.19 (the rig needs 3.16 or later), iproute2 and
// iputils ping.
const perfRigImage = "alpine:3.22"

// perfBaseline is the baseline file of the x86 CI runner.
const perfBaseline = "cmd/perfrig/baseline.json"

// Perf runs the netns + netem rig (cmd/perfrig) with one workload in a
// privileged container and returns the result JSON. Empty arguments use the
// perfrig defaults: iperf3-tcp, 30s, 10ms delay each way (20 ms RTT), 1 flow.
func (m *ApoxyCli) Perf(
	ctx context.Context,
	src *dagger.Directory,
	// Workload: iperf3-tcp, iperf3-udp or exec.
	// +optional
	workload string,
	// Measured run length, for example 30s.
	// +optional
	duration string,
	// One-way delay in each direction, for example 10ms.
	// +optional
	delay string,
	// Random loss in percent in each direction, for example 0.1.
	// +optional
	loss string,
	// Parallel flows.
	// +optional
	streams int,
	// More "perfrig run" flags, for example -jitter=1ms, -rate=10gbit,
	// -mtu=1280, -bitrate=2G or -window=4M.
	// +optional
	args []string,
) (string, error) {
	cmd := []string{"perfrig", "run"}
	add := func(flag, v string) {
		if v != "" {
			cmd = append(cmd, "-"+flag+"="+v)
		}
	}
	add("workload", workload)
	add("duration", duration)
	add("delay", delay)
	add("loss", loss)
	if streams > 0 {
		add("streams", strconv.Itoa(streams))
	}
	cmd = append(cmd, args...)

	return m.perfRigContainer(ctx, src).
		// Run the rig on each call. Do not use a cached result.
		WithEnvVariable("PERFRIG_RUN_AT", time.Now().UTC().Format(time.RFC3339Nano)).
		WithExec(cmd, dagger.ContainerWithExecOpts{InsecureRootCapabilities: true}).
		Stdout(ctx)
}

// PerfCompare compares perf results (a directory of Perf JSON files) with
// cmd/perfrig/baseline.json. It fails when throughput drops or CPU per Gbps
// rises by more than the baseline tolerance. A result with no baseline entry
// passes.
func (m *ApoxyCli) PerfCompare(
	ctx context.Context,
	src *dagger.Directory,
	results *dagger.Directory,
) (string, error) {
	return m.BuilderContainer(ctx, src).
		WithEnvVariable("CGO_ENABLED", "0").
		WithDirectory("/perf", results).
		WithExec([]string{"go", "run", "./cmd/perfrig", "compare", "-baseline", perfBaseline, "/perf"}).
		Stdout(ctx)
}

// perfRigContainer returns a container with perfrig and its tools. It runs on
// the engine platform (x86_64 in CI, arm64 on a Mac).
func (m *ApoxyCli) perfRigContainer(ctx context.Context, src *dagger.Directory) *dagger.Container {
	bin := m.BuilderContainer(ctx, src).
		WithEnvVariable("CGO_ENABLED", "0").
		WithExec([]string{"go", "build", "-o", "/out/perfrig", "./cmd/perfrig"}).
		File("/out/perfrig")
	return dag.Container().
		From(perfRigImage).
		WithExec([]string{"apk", "add", "--no-cache", "iperf3", "iproute2", "iputils-ping"}).
		WithFile("/usr/local/bin/perfrig", bin)
}
