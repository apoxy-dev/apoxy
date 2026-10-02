// Module perf runs perf rows with perfagent (cmd/perfagent), on a new EC2
// instance or in a privileged container on the engine host. Both return the
// same directory: agent.json, agent.log, results/, logs/ and work/, and
// console.txt when the instance failed. An infra failure is not an error of
// the function: agent.json then has infra_error.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"dagger/perf/internal/dagger"
	"dagger/perf/perfspec"
)

const (
	// Ubuntu 24.04 amd64 server, 20260904, us-west-2 (Canonical).
	defaultImage = "ami-04678417fc39d7171"
	// rigImage has iperf3 3.19 (perfrig needs 3.16 or later), iproute2 and iputils ping.
	rigImage = "alpine:3.22"
	// poweroff is the life of an instance. A systemd timer powers it off and
	// the reaper terminates it after this time.
	poweroff = 60 * time.Minute
	// uploadSlack is the time after the deadline for the uploads of perfagent.
	uploadSlack = 8 * time.Minute
	pollEvery   = 20 * time.Second
)

type Perf struct{}

// Local runs the plan with perfagent in a privileged container on the engine host.
func (m *Perf) Local(
	ctx context.Context,
	// perfagent and the binaries of the rows, for the engine platform.
	bins *dagger.Directory,
	// Files for the run directory, for example baseline.json.
	// +optional
	files *dagger.Directory,
	// The rows and the host setup, as a perfagent spec in JSON with no run_id,
	// deadline, bins, files or upload.
	plan string,
	// Time for the rows.
	// +default="40m"
	deadline string,
) (*dagger.Directory, error) {
	spec, d, err := parse(plan, deadline)
	if err != nil {
		return nil, err
	}
	spec.RunID = "local"
	spec.Deadline = time.Now().Add(d).UTC()
	if spec.Bins, err = hashAll(ctx, bins, true); err != nil {
		return nil, err
	}
	if files != nil {
		if spec.Files, err = hashAll(ctx, files, false); err != nil {
			return nil, err
		}
	}
	js, err := spec.JSON()
	if err != nil {
		return nil, err
	}
	ctr := dag.Container().From(rigImage).
		WithExec([]string{"apk", "add", "--no-cache", "iperf3", "iproute2", "iputils-ping"}).
		WithDirectory("/perf/bin", bins).
		WithNewFile("/perf/spec.json", js)
	if files != nil {
		ctr = ctr.WithDirectory("/perf/run", files)
	}
	ctr = ctr.WithExec(
		[]string{"/perf/bin/" + perfspec.Agent, "-root", "/perf", "-out", "/out", "-spec", "/perf/spec.json"},
		dagger.ContainerWithExecOpts{InsecureRootCapabilities: true, Expect: dagger.ReturnTypeAny})
	code, err := ctr.ExitCode(ctx)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		stderr, _ := ctr.Stderr(ctx)
		return infra(spec.RunID, fmt.Errorf("perfagent exited with code %d: %s", code, tail(stderr, 20))), nil
	}
	out := ctr.Directory("/out")
	var results *dagger.File
	if has(ctx, out, "results.tgz") {
		results = out.File("results.tgz")
	}
	return collect(ctx, out.File("agent.json"), out.File("agent.log"), results)
}

// Ec2 runs the plan on a new EC2 instance. It puts the binaries, the files and
// the spec in S3 under runs/RUN_TAG/in/, launches the instance with cloud-init
// user data that starts perfagent, and waits for runs/RUN_TAG/out/agent.json.
// It then terminates the instance and deletes the inputs. It terminates
// expired bench instances at the start and at the end.
func (m *Perf) Ec2(
	ctx context.Context,
	// perfagent and the binaries of the rows, for linux/amd64.
	bins *dagger.Directory,
	// Files for the run directory, for example baseline.json.
	// +optional
	files *dagger.Directory,
	// The rows and the host setup, as a perfagent spec in JSON with no run_id,
	// deadline, bins, files or upload.
	plan string,
	// Names the run in the S3 keys and the tags, for example RUN_ID-ATTEMPT-JOB.
	runTag string,
	bucket string,
	// +default="us-west-2"
	region string,
	accessKeyId *dagger.Secret,
	secretAccessKey *dagger.Secret,
	// +optional
	sessionToken *dagger.Secret,
	// Time for the rows, from the launch. The presigned URLs expire 10m after
	// it, or when the session ends.
	// +default="40m"
	deadline string,
	// +default="ami-04678417fc39d7171"
	image string,
	// +default="c7a.8xlarge"
	instanceType string,
	// KEY=VALUE tag of the subnets and the security group. With no tagged
	// subnet, the instance goes into the default VPC, with the tagged group
	// of that VPC, else its default group.
	// +default="apoxy-perf=true"
	subnetTag string,
	// Replaces the AWS endpoints, for example with a local AWS fake.
	// +optional
	endpoint string,
) (*dagger.Directory, error) {
	spec, d, err := parse(plan, deadline)
	if err != nil {
		return nil, err
	}
	keys, err := perfspec.NewKeys(runTag)
	if err != nil {
		return nil, err
	}
	if d+uploadSlack >= poweroff {
		return nil, fmt.Errorf("deadline %s plus %s is not less than the instance life %s", d, uploadSlack, poweroff)
	}
	spec.RunID = runTag
	a := dag.Aws(dagger.AwsOpts{
		Region:          region,
		AccessKeyID:     accessKeyId,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Endpoint:        endpoint,
	})
	r := &ec2Run{aws: a, bucket: a.Bucket(bucket), keys: keys, expires: (d + 10*time.Minute).String()}
	r.reap(ctx)
	defer r.reap(context.WithoutCancel(ctx))
	// The inputs have presigned URLs. Delete them in all cases.
	defer r.cleanup(context.WithoutCancel(ctx))

	agentURL, err := r.inputs(ctx, &spec, bins, files)
	if err != nil {
		return infra(runTag, err), nil
	}
	launched := time.Now()
	spec.Deadline = launched.Add(d).UTC()
	id, err := r.launch(ctx, spec, agentURL, image, instanceType, subnetTag, launched)
	if err != nil {
		return infra(runTag, err), nil
	}
	inst := a.Instance(id)
	defer func() {
		if err := inst.Terminate(context.WithoutCancel(ctx)); err != nil {
			slog.Warn("Failed to terminate the instance", "instance", id, "error", err)
		}
	}()
	slog.Info("Launched the bench instance", "instance", id, "deadline", spec.Deadline)

	if err := r.wait(ctx, inst, spec.Deadline.Add(uploadSlack)); err != nil {
		console, cerr := inst.Console(context.WithoutCancel(ctx))
		dir := infra(runTag, err)
		if cerr == nil {
			dir = dir.WithNewFile("console.txt", console)
		}
		return dir, nil
	}
	b := r.bucket
	var results *dagger.File
	if ok, err := b.Exists(ctx, keys.Output("results.tgz")); err == nil && ok {
		results = b.Download(keys.Output("results.tgz"))
	}
	var agentLog *dagger.File
	if ok, err := b.Exists(ctx, keys.Output("agent.log")); err == nil && ok {
		agentLog = b.Download(keys.Output("agent.log"))
	}
	dir, err := collect(ctx, b.Download(keys.Output("agent.json")), agentLog, results)
	if err != nil {
		return infra(runTag, fmt.Errorf("get the outputs: %w", err)), nil
	}
	return dir, nil
}

// ec2Run is the state of one Ec2 call.
type ec2Run struct {
	aws     *dagger.Aws
	bucket  *dagger.AwsBucket
	keys    perfspec.Keys
	expires string
}

func (r *ec2Run) reap(ctx context.Context) {
	ids, err := r.aws.Reap(ctx)
	if err != nil {
		slog.Warn("Failed to terminate expired bench instances", "error", err)
		return
	}
	if len(ids) > 0 {
		slog.Info("Terminated expired bench instances", "instances", ids)
	}
}

func (r *ec2Run) cleanup(ctx context.Context) {
	n, err := r.bucket.Delete(ctx, r.keys.Inputs())
	if err != nil {
		slog.Warn("Failed to delete the run inputs", "prefix", r.keys.Inputs(), "error", err)
		return
	}
	slog.Info("Deleted the run inputs", "objects", n)
}

func (r *ec2Run) presign(ctx context.Context, key, method string) (string, error) {
	return r.bucket.Presign(key, dagger.AwsBucketPresignOpts{Method: method, Expires: r.expires}).Plaintext(ctx)
}

// inputs puts the binaries and files in S3, fills the spec with their URLs and
// the upload URLs, and returns the URL of perfagent.
func (r *ec2Run) inputs(ctx context.Context, spec *perfspec.Spec, bins, files *dagger.Directory) (string, error) {
	put := func(dir *dagger.Directory, key func(string) string, skipAgent bool) ([]perfspec.File, string, error) {
		names, err := fileNames(ctx, dir)
		if err != nil {
			return nil, "", err
		}
		var out []perfspec.File
		var agentURL string
		for _, n := range names {
			sum, err := r.bucket.Upload(ctx, key(n), dir.File(n))
			if err != nil {
				return nil, "", err
			}
			u, err := r.presign(ctx, key(n), "GET")
			if err != nil {
				return nil, "", err
			}
			if skipAgent && n == perfspec.Agent {
				agentURL = u
				continue
			}
			out = append(out, perfspec.File{Name: n, URL: u, SHA256: sum})
		}
		return out, agentURL, nil
	}
	var agentURL string
	var err error
	if spec.Bins, agentURL, err = put(bins, r.keys.Bin, true); err != nil {
		return "", err
	}
	if agentURL == "" {
		return "", fmt.Errorf("the bins have no %s", perfspec.Agent)
	}
	if files != nil {
		if spec.Files, _, err = put(files, r.keys.File, false); err != nil {
			return "", err
		}
	}
	for _, o := range []struct {
		name string
		dst  *string
	}{
		{"results.tgz", &spec.Upload.Results},
		{"agent.log", &spec.Upload.Log},
		{"agent.json", &spec.Upload.Report},
	} {
		if *o.dst, err = r.presign(ctx, r.keys.Output(o.name), "PUT"); err != nil {
			return "", err
		}
	}
	return agentURL, nil
}

// launch puts the spec in S3 and launches the instance.
func (r *ec2Run) launch(ctx context.Context, spec perfspec.Spec, agentURL, image, instanceType, subnetTag string, at time.Time) (string, error) {
	js, err := spec.JSON()
	if err != nil {
		return "", err
	}
	if err := r.bucket.PutSecret(ctx, r.keys.Spec(), dag.SetSecret("perf-spec-"+spec.RunID, js)); err != nil {
		return "", err
	}
	specURL, err := r.presign(ctx, r.keys.Spec(), "GET")
	if err != nil {
		return "", err
	}
	ud, err := perfspec.CloudInit(agentURL, specURL, poweroff)
	if err != nil {
		return "", err
	}
	return r.aws.Launch(ctx, image, instanceType, dag.SetSecret("perf-user-data-"+spec.RunID, ud),
		perfspec.Tags(spec.RunID, at.Add(poweroff)), dagger.AwsLaunchOpts{SubnetTag: subnetTag})
}

// wait waits for agent.json until the time. It fails early when the instance stops.
func (r *ec2Run) wait(ctx context.Context, inst *dagger.AwsInstance, until time.Time) error {
	key := r.keys.Output("agent.json")
	done := func() bool {
		ok, err := r.bucket.Exists(ctx, key)
		if err != nil {
			slog.Warn("Failed to look for agent.json", "error", err)
		}
		return ok
	}
	for {
		if done() {
			return nil
		}
		state, err := inst.State(ctx)
		if err != nil {
			slog.Warn("Failed to read the instance state", "error", err)
		}
		switch state {
		case "shutting-down", "terminated", "stopping", "stopped":
			// perfagent puts agent.json before it powers off the host.
			if done() {
				return nil
			}
			return fmt.Errorf("the instance is %s and perfagent put no agent.json", state)
		}
		if time.Now().After(until) {
			return fmt.Errorf("perfagent put no agent.json by %s, %s after the deadline", until.Format(time.RFC3339), uploadSlack)
		}
		slog.Info("Waiting for perfagent", "state", state)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollEvery):
		}
	}
}

func parse(plan, deadline string) (perfspec.Spec, time.Duration, error) {
	spec, err := perfspec.ParsePlan(plan)
	if err != nil {
		return spec, 0, err
	}
	d, err := time.ParseDuration(deadline)
	if err != nil || d <= 0 {
		return spec, 0, fmt.Errorf("bad deadline %q", deadline)
	}
	return spec, d, nil
}

// infra returns an output directory with only an agent.json that has the error.
func infra(runID string, err error) *dagger.Directory {
	slog.Error("The perf run has an infra error", "run", runID, "error", err)
	return dag.Directory().WithNewFile("agent.json", perfspec.InfraReport(runID, err))
}

var unpacks atomic.Int32

// collect unpacks the results and adds agent.json and agent.log. results and
// agentLog can be nil.
func collect(ctx context.Context, agentJSON, agentLog, results *dagger.File) (*dagger.Directory, error) {
	dir := dag.Directory()
	if results != nil {
		tmp, err := os.MkdirTemp("", "results")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		path, err := results.Export(ctx, filepath.Join(tmp, "results.tgz"))
		if err != nil {
			return nil, err
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		// Workdir reads from the module workdir, so the files go there.
		name := fmt.Sprintf("unpack-%d", unpacks.Add(1))
		if err := perfspec.Untar(f, name); err != nil {
			return nil, fmt.Errorf("unpack the results: %w", err)
		}
		dir = dag.CurrentModule().Workdir(name)
	}
	dir = dir.WithFile("agent.json", agentJSON)
	if agentLog != nil {
		dir = dir.WithFile("agent.log", agentLog)
	}
	return dir.Sync(ctx)
}

// fileNames returns the names of the regular files at the top of dir.
func fileNames(ctx context.Context, dir *dagger.Directory) ([]string, error) {
	ents, err := dir.Entries(ctx)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if !strings.HasSuffix(e, "/") {
			names = append(names, e)
		}
	}
	return names, nil
}

func has(ctx context.Context, dir *dagger.Directory, name string) bool {
	names, err := fileNames(ctx, dir)
	if err != nil {
		return false
	}
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// hashAll returns the files at the top of dir with their SHA-256 and no URL.
func hashAll(ctx context.Context, dir *dagger.Directory, skipAgent bool) ([]perfspec.File, error) {
	names, err := fileNames(ctx, dir)
	if err != nil {
		return nil, err
	}
	var out []perfspec.File
	for _, n := range names {
		if skipAgent && n == perfspec.Agent {
			continue
		}
		sum, err := hashFile(ctx, dir.File(n))
		if err != nil {
			return nil, err
		}
		out = append(out, perfspec.File{Name: n, SHA256: sum})
	}
	return out, nil
}

func hashFile(ctx context.Context, f *dagger.File) (string, error) {
	tmp, err := os.MkdirTemp("", "hash")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	path, err := f.Export(ctx, filepath.Join(tmp, "f"))
	if err != nil {
		return "", err
	}
	r, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer r.Close()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}
