package main

import (
	"context"
	"fmt"
	"slices"
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

// vpcRow is one perfrig run of PerfVPC. The result key has no CC, driver or
// transport, so the name holds them.
type vpcRow struct {
	id, name string
	gate     bool
	// direct runs the flows with no relay.
	direct bool
	// server and client are more vpcbench flags. args are more perfrig run flags.
	server, client string
	args           []string
}

// vpcRows are the gated row and the info rows. Info rows run one time and gate nothing.
var vpcRows = []vpcRow{
	{id: "gate", name: "vpc-netstack-psp-relay", gate: true, client: " -cc bbr"},
	{id: "netstack-quic-relay", name: "vpc-netstack-quic-relay", server: " -transport quic", client: " -transport quic -cc bbr"},
	{id: "tun-psp-relay-cubic", name: "vpc-tun-psp-relay-cubic", server: " -driver tun", client: " -driver tun -cc cubic"},
	{id: "netstack-psp-relay-loss0.1", name: "vpc-netstack-psp-relay", client: " -cc bbr", args: []string{"-loss=0.1"}},
	{id: "netstack-psp-direct", name: "vpc-netstack-psp-direct", direct: true, client: " -cc bbr"},
	{id: "netstack-psp-relay-cubic", name: "vpc-netstack-psp-relay-cubic", client: " -cc cubic"},
	{id: "netstack-psp-relay-rate1000mbit", name: "vpc-netstack-psp-relay", client: " -cc bbr", args: []string{"-rate=1000mbit", "-queue-limit=2640"}},
}

// argv returns the perf-vpc-row command of the row.
func (r vpcRow) argv(duration string, reps, minCPUs int) []string {
	// The relay shares the server netns. The server command stops it when the server exits.
	server := "vpcbench relay -listen $SERVER_IP:4443 & vpcbench server -relay $SERVER_IP:4443 -listen $SERVER_IP:4433" + r.server + "; kill $!; wait"
	client := "vpcbench client -relay $SERVER_IP:4443 -server $SERVER_IP:4433"
	if r.direct {
		server = "vpcbench server -via direct -listen $SERVER_IP:4433" + r.server
		client = "vpcbench client -via direct -server $SERVER_IP:4433"
	}
	client += r.client + " -streams $STREAMS -omit ${OMIT_S}s -duration ${DURATION_S}s"
	dir, rowReps := "info", 1
	if r.gate {
		dir, rowReps = "gate", reps
	}
	argv := []string{"perf-vpc-row", r.id,
		"-workload=exec", "-name=" + r.name, "-netns-prefix=perf", "-ready=tcp:4433",
		"-delay=10ms", "-streams=4", "-omit=5s", "-duration=" + duration,
		"-reps=" + strconv.Itoa(rowReps), "-min-cpus=" + strconv.Itoa(minCPUs), "-max-steal=5",
		"-out-dir=work/" + r.id, "-out=results/" + dir + "/" + r.id + ".json",
		"-server-cmd=" + server, "-client-cmd=" + client,
	}
	if r.gate {
		argv = append(argv, "-baseline=baseline.json")
	}
	return append(argv, r.args...)
}

// perfVPCRowScript runs one row. It keeps the perfrig exit code in codes/ID, so the next rows still run.
const perfVPCRowScript = `#!/bin/sh
# Usage: perf-vpc-row ID PERFRIG_RUN_FLAGS...
id=$1
shift
# The tun driver needs /dev/net/tun, and some container runtimes do not add it.
[ -c /dev/net/tun ] || { mkdir -p /dev/net && mknod /dev/net/tun c 10 200; }
perfrig run "$@" 2> "logs/$id.log"
echo $? > "codes/$id"
`

// perfVPCCompareScript compares the gate and the info results, and writes summary.md.
// gate-exit is 0 (pass), 1 (regression or no result) or 3 (infra error).
const perfVPCCompareScript = `#!/bin/sh
# The work dirs have the throwaway CA and agent keys of each run. Do not keep them.
find work \( -name '*-cred.json' -o -name 'vpcbench-ca.pem' \) -delete
printf '## VPC gate\n\n' >> summary.md
perfrig compare -baseline baseline.json -summary summary.md results/gate > compare-gate.txt 2> compare-gate.err
echo $? > gate-exit
ls results/gate/*.json > /dev/null 2>&1 || printf 'No gate result. See logs/gate.log.\n\n' >> summary.md
printf '## VPC info rows\n\nThese rows do not gate.\n\n' >> summary.md
if ls results/info/*.json > /dev/null 2>&1; then
  perfrig compare -baseline baseline.json -summary summary.md results/info > compare-info.txt 2> compare-info.err
  echo $? > info-exit
else
  printf 'No info results.\n\n' >> summary.md
fi
for f in codes/*; do
  id=${f#codes/}
  code=$(cat "$f")
  [ "$code" = 0 ] || echo "- $id: perfrig exit $code, see logs/$id.log"
done > errors.md
if [ -s errors.md ]; then
  { printf '## perfrig errors\n\n'; cat errors.md; echo; } >> summary.md
fi
`

// PerfVPC runs the VPC gate row and the info rows on the netns rig, one at a time.
// It returns the results, logs, summary.md and gate-exit. A failed row does not fail it.
func (m *ApoxyCli) PerfVPC(
	ctx context.Context,
	src *dagger.Directory,
	// Measured run length of each row. The baseline keys include it.
	// +default="30s"
	duration string,
	// Reps of the gated row. Info rows run one time.
	// +default=3
	reps int,
	// Infra error when the host has fewer CPUs. Lower it only for smoke runs.
	// +default=8
	minCpus int,
	// Run only these row IDs, for example gate (default: all rows).
	// +optional
	rows []string,
) (*dagger.Directory, error) {
	run := vpcRows
	if len(rows) > 0 {
		run = nil
		for _, id := range rows {
			i := slices.IndexFunc(vpcRows, func(r vpcRow) bool { return r.id == id })
			if i < 0 {
				return nil, fmt.Errorf("unknown row %q", id)
			}
			run = append(run, vpcRows[i])
		}
	}
	vpcbench := m.BuilderContainer(ctx, src).
		WithEnvVariable("CGO_ENABLED", "0").
		WithExec([]string{"go", "build", "-o", "/out/vpcbench", "./cmd/vpcbench"}).
		File("/out/vpcbench")
	exe := dagger.ContainerWithNewFileOpts{Permissions: 0o755}
	ctr := m.perfRigContainer(ctx, src).
		WithFile("/usr/local/bin/vpcbench", vpcbench).
		WithNewFile("/usr/local/bin/perf-vpc-row", perfVPCRowScript, exe).
		WithNewFile("/usr/local/bin/perf-vpc-compare", perfVPCCompareScript, exe).
		WithFile("/perf/baseline.json", src.File(perfBaseline)).
		WithWorkdir("/perf").
		WithExec([]string{"mkdir", "-p", "results/gate", "results/info", "logs", "codes", "work"}).
		// Run the rig on each call. Do not use a cached result.
		WithEnvVariable("PERFRIG_RUN_AT", time.Now().UTC().Format(time.RFC3339Nano))
	for _, r := range run {
		ctr = ctr.WithExec(r.argv(duration, reps, minCpus), dagger.ContainerWithExecOpts{InsecureRootCapabilities: true})
	}
	return ctr.WithExec([]string{"perf-vpc-compare"}).Directory("/perf"), nil
}
