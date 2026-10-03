package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dagger/apoxy-cli/internal/dagger"
	"dagger/apoxy-cli/internal/perfsuite"
)

// perfBaseline is the baseline file of the perf suites.
const perfBaseline = "cmd/perfrig/baseline.json"

// perfCompareImage runs "perfrig compare".
const perfCompareImage = "alpine:3.22"

// motoImage is a local AWS fake for the tests of the aws module.
const motoImage = "motoserver/moto:5.2.3"

// PerfCompare compares perf results (a directory of perfrig JSON files) with
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

// PerfNetns runs the netns + netem rig rows with iperf3 (cmd/perfrig), all of
// which gate. It returns the results with summary.md and gate-exit: 0 pass, 1
// regression or no result, 3 infra error. A failed row does not fail it.
func (m *ApoxyCli) PerfNetns(
	ctx context.Context,
	src *dagger.Directory,
	// local: a privileged container on the engine host. ec2: a new EC2 instance.
	// +default="local"
	where string,
	// Measured run length of each row. The baseline keys include it.
	// +default="30s"
	duration string,
	// +default=1
	reps int,
	// Infra error when the host has fewer CPUs. Lower it only for local smoke runs.
	// +default=16
	minCpus int,
	// Run only these row IDs (default: all rows).
	// +optional
	rows []string,
	// ec2: names the run in S3 and the tags, for example RUN_ID-ATTEMPT-JOB.
	// +optional
	runTag string,
	// ec2: the bench bucket.
	// +optional
	bucket string,
	// +default="us-west-2"
	region string,
	// +optional
	awsAccessKeyId *dagger.Secret,
	// +optional
	awsSecretAccessKey *dagger.Secret,
	// +optional
	awsSessionToken *dagger.Secret,
) (*dagger.Directory, error) {
	o := perfsuite.Options{Duration: duration, Reps: reps, MinCPUs: minCpus, Only: rows}
	e := perfEC2{runTag: runTag, bucket: bucket, region: region, id: awsAccessKeyId, secret: awsSecretAccessKey, token: awsSessionToken}
	return m.perfRun(ctx, src, perfsuite.Netns, where, o, e)
}

// PerfVpc runs the VPC rows (cmd/vpcbench through the relay, 4 flows, 20 ms
// RTT): one gated row and info rows that run one time. It returns the results
// with summary.md and gate-exit: 0 pass, 1 regression or no gate result, 3
// infra error. A failed row does not fail it.
func (m *ApoxyCli) PerfVpc(
	ctx context.Context,
	src *dagger.Directory,
	// local: a privileged container on the engine host. ec2: a new EC2 instance.
	// +default="local"
	where string,
	// Measured run length of each row. The baseline keys include it.
	// +default="30s"
	duration string,
	// Reps of the gated row.
	// +default=3
	reps int,
	// Infra error when the host has fewer CPUs. Lower it only for local smoke runs.
	// +default=16
	minCpus int,
	// Run only these row IDs, for example gate (default: all rows).
	// +optional
	rows []string,
	// ec2: names the run in S3 and the tags, for example RUN_ID-ATTEMPT-JOB.
	// +optional
	runTag string,
	// ec2: the bench bucket.
	// +optional
	bucket string,
	// +default="us-west-2"
	region string,
	// +optional
	awsAccessKeyId *dagger.Secret,
	// +optional
	awsSecretAccessKey *dagger.Secret,
	// +optional
	awsSessionToken *dagger.Secret,
) (*dagger.Directory, error) {
	o := perfsuite.Options{Duration: duration, Reps: reps, MinCPUs: minCpus, Only: rows}
	e := perfEC2{runTag: runTag, bucket: bucket, region: region, id: awsAccessKeyId, secret: awsSecretAccessKey, token: awsSessionToken}
	return m.perfRun(ctx, src, perfsuite.VPC, where, o, e)
}

// PerfCleanup terminates the instances of a PerfNetns or PerfVpc run on EC2
// and deletes its inputs in S3. Run it after the run step in all cases: a
// cancel stops the run before its own cleanup. With nothing left, it does
// nothing.
func (m *ApoxyCli) PerfCleanup(
	ctx context.Context,
	// The run tag of the run.
	runTag string,
	// The bench bucket.
	bucket string,
	// +default="us-west-2"
	region string,
	awsAccessKeyId *dagger.Secret,
	awsSecretAccessKey *dagger.Secret,
	// +optional
	awsSessionToken *dagger.Secret,
) (string, error) {
	return dag.Perf().Ec2Cleanup(ctx, runTag, bucket, awsAccessKeyId, awsSecretAccessKey, dagger.PerfEc2CleanupOpts{
		Region:       region,
		SessionToken: awsSessionToken,
	})
}

// perfEC2 has the EC2 arguments of a perf run.
type perfEC2 struct {
	runTag, bucket, region string
	id, secret, token      *dagger.Secret
}

func (m *ApoxyCli) perfRun(ctx context.Context, src *dagger.Directory, s perfsuite.Suite, where string, o perfsuite.Options, e perfEC2) (*dagger.Directory, error) {
	var goarch string
	switch where {
	case "local":
		p, err := dag.DefaultPlatform(ctx)
		if err != nil {
			return nil, err
		}
		goarch = archOf(p)
	case "ec2":
		if e.runTag == "" || e.bucket == "" || e.id == nil || e.secret == nil {
			return nil, errors.New("ec2 needs --run-tag, --bucket, --aws-access-key-id and --aws-secret-access-key")
		}
		goarch = "amd64"
		o.Host = true
	default:
		return nil, fmt.Errorf("bad where %q: want local or ec2", where)
	}
	plan, err := s.Plan(o)
	if err != nil {
		return nil, err
	}
	bins := m.perfBins(src, goarch, append([]string{"perfagent", "perfrig"}, s.Bins...))
	files := dag.Directory().WithFile("baseline.json", src.File(perfBaseline))
	var out *dagger.Directory
	if where == "local" {
		out = dag.Perf().Local(bins, plan, dagger.PerfLocalOpts{Files: files})
	} else {
		out = dag.Perf().Ec2(bins, plan, e.runTag, e.bucket, e.id, e.secret, dagger.PerfEc2Opts{
			Files:        files,
			Region:       e.region,
			SessionToken: e.token,
		})
	}
	return m.perfSummarize(ctx, src, s, out)
}

// perfGo is a Go container with no C toolchain, for the perf binaries and tests.
func perfGo(src *dagger.Directory) *dagger.Container {
	return dag.Container().
		From("golang:1.26.8-bookworm").
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod")).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/go/build-cache", dag.CacheVolume("go-build")).
		WithEnvVariable("GOCACHE", "/go/build-cache").
		WithEnvVariable("CGO_ENABLED", "0").
		WithDirectory("/src", src, dagger.ContainerWithDirectoryOpts{Exclude: []string{"secrets/**"}}).
		WithWorkdir("/src")
}

// perfBins builds static linux binaries of the commands for goarch.
func (m *ApoxyCli) perfBins(src *dagger.Directory, goarch string, cmds []string) *dagger.Directory {
	ctr := perfGo(src).
		WithEnvVariable("GOOS", "linux").
		WithEnvVariable("GOARCH", goarch)
	for _, c := range cmds {
		ctr = ctr.WithExec([]string{"go", "build", "-o", "/out/" + c, "./cmd/" + c})
	}
	return ctr.Directory("/out")
}

// perfSummarize compares each result group with the baseline and adds
// summary.md, gate-exit and compare-GROUP.txt to the outputs.
func (m *ApoxyCli) perfSummarize(ctx context.Context, src *dagger.Directory, s perfsuite.Suite, out *dagger.Directory) (*dagger.Directory, error) {
	// The perf module gives an infra error in agent.json. Its own errors fail the call.
	out, err := out.Sync(ctx)
	if err != nil {
		return nil, err
	}
	var rep perfsuite.Report
	data, err := out.File("agent.json").Contents(ctx)
	if err == nil {
		rep, err = perfsuite.ParseReport(data)
	}
	if err != nil {
		rep.InfraError = fmt.Sprintf("read agent.json: %v", err)
	}
	console := ""
	if names, _ := out.Glob(ctx, "console.txt"); len(names) > 0 {
		console, _ = out.File("console.txt").Contents(ctx)
	}

	p, err := dag.DefaultPlatform(ctx)
	if err != nil {
		return nil, err
	}
	perfrig := m.perfBins(src, archOf(p), []string{"perfrig"}).File("perfrig")
	ctr := dag.Container().From(perfCompareImage).
		WithFile("/usr/local/bin/perfrig", perfrig).
		WithDirectory("/perf", out).
		WithFile("/perf/baseline.json", src.File(perfBaseline)).
		WithWorkdir("/perf")
	var compares []perfsuite.Compare
	for _, g := range s.Groups() {
		c := perfsuite.Compare{Group: g}
		matches, err := out.Glob(ctx, "results/"+g+"/*.json")
		if err != nil {
			return nil, err
		}
		if len(matches) > 0 {
			md := "summary-" + g + ".md"
			run := ctr.WithExec([]string{"perfrig", "compare", "-baseline", "baseline.json", "-summary", md, "results/" + g},
				dagger.ContainerWithExecOpts{Expect: dagger.ReturnTypeAny})
			c.Ran = true
			if c.Code, err = run.ExitCode(ctx); err != nil {
				return nil, err
			}
			c.Stdout, _ = run.Stdout(ctx)
			c.Stderr, _ = run.Stderr(ctx)
			c.Markdown, _ = run.File(md).Contents(ctx)
			out = out.WithNewFile("compare-"+g+".txt", c.Stdout+c.Stderr)
		}
		compares = append(compares, c)
	}
	exit := perfsuite.GateExit(rep, compares[0])
	return out.
		WithNewFile("summary.md", perfsuite.Summary(s, rep, compares, console)).
		WithNewFile("gate-exit", strconv.Itoa(exit)+"\n"), nil
}

// PerfSummary returns summary.md of PerfNetns or PerfVpc results, for $GITHUB_STEP_SUMMARY.
func (m *ApoxyCli) PerfSummary(results *dagger.Directory) *dagger.File {
	return results.File("summary.md")
}

// PerfCheck fails when the gate of PerfNetns or PerfVpc results did not pass.
func (m *ApoxyCli) PerfCheck(ctx context.Context, results *dagger.Directory) (string, error) {
	code, err := results.File("gate-exit").Contents(ctx)
	if err != nil {
		return "", fmt.Errorf("the results have no gate-exit: %w", err)
	}
	switch strings.TrimSpace(code) {
	case "0":
		return "The gate passed.", nil
	case "3":
		return "", errors.New("the gate has an infra error: see the job summary")
	default:
		return "", fmt.Errorf("the gate failed (exit %s): see the job summary and compare-gate.txt", strings.TrimSpace(code))
	}
}

// PerfNotify posts one Slack line about a failed gate job of PerfNetns or PerfVpc results.
func (m *ApoxyCli) PerfNotify(
	ctx context.Context,
	results *dagger.Directory,
	// netns or vpc.
	suite string,
	webhook *dagger.Secret,
	// Link to the workflow run.
	runUrl string,
	// Commit of the run.
	sha string,
) (string, error) {
	var s perfsuite.Suite
	switch suite {
	case perfsuite.Netns.Name:
		s = perfsuite.Netns
	case perfsuite.VPC.Name:
		s = perfsuite.VPC
	default:
		return "", fmt.Errorf("bad suite %q: want netns or vpc", suite)
	}
	exit := -1
	if code, err := results.File("gate-exit").Contents(ctx); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(code)); err == nil {
			exit = n
		}
	}
	var rep perfsuite.Report
	if data, err := results.File("agent.json").Contents(ctx); err == nil {
		rep, _ = perfsuite.ParseReport(data)
	}
	var gate []perfsuite.Result
	names, err := results.Glob(ctx, "results/gate/*.json")
	if err != nil {
		return "", err
	}
	for _, n := range names {
		data, err := results.File(n).Contents(ctx)
		if err != nil {
			return "", err
		}
		var r perfsuite.Result
		if err := json.Unmarshal([]byte(data), &r); err != nil {
			return "", fmt.Errorf("parse %s: %w", n, err)
		}
		gate = append(gate, r)
	}
	compareGate := ""
	if names, _ := results.Glob(ctx, "compare-gate.txt"); len(names) > 0 {
		compareGate, _ = results.File("compare-gate.txt").Contents(ctx)
	}
	text := perfsuite.SlackText(s, exit, rep, gate, compareGate, "apoxy@"+sha[:min(len(sha), 7)], runUrl)
	url, err := webhook.Plaintext(ctx)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	for i := range 3 {
		if i > 0 {
			time.Sleep(time.Duration(i) * 2 * time.Second)
		}
		var resp *http.Response
		resp, err = client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			// The error has the webhook URL. Do not return it.
			err = errors.New("post to the Slack webhook failed")
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return text, nil
		}
		err = fmt.Errorf("the Slack webhook returned HTTP %d", resp.StatusCode)
	}
	return "", err
}

// PerfAwsTest runs the tests of the aws module against a local AWS fake.
func (m *ApoxyCli) PerfAwsTest(ctx context.Context, src *dagger.Directory) (string, error) {
	moto := dag.Container().From(motoImage).WithExposedPort(5000).AsService()
	return perfGo(src).
		WithServiceBinding("moto", moto).
		WithEnvVariable("AWS_ENDPOINT_URL", "http://moto:5000").
		WithWorkdir("/src/ci/modules/aws").
		WithExec([]string{"go", "test", "-count=1", "-v", "./awsx/..."}).
		Stdout(ctx)
}
