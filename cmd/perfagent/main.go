// Command perfagent runs perf rows ("perfrig run") on a bench host. It reads a
// spec, fetches the binaries and files of the spec and checks their SHA-256,
// sets up the host, and runs the rows one at a time until the deadline. Then
// it puts results.tgz, agent.log and agent.json to the presigned URLs of the
// spec, or writes them to the -out directory. agent.json comes last and tells
// that the run is done. With -ec2, the agent powers off the host at the end.
//
//	perfagent -ec2 -spec 'https://BUCKET.s3.REGION.amazonaws.com/runs/ID/spec.json?X-Amz-...'
//	perfagent -root /perf -out /out -spec /perf/spec.json
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// uploadTimeout is the time for the uploads after the rows.
const uploadTimeout = 5 * time.Minute

const imdsBase = "http://169.254.169.254"

// Report is agent.json.
type Report struct {
	RunID      string    `json:"run_id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Host       Host      `json:"host"`
	// InfraError tells why the run is not valid, for example a fetch failure or
	// the deadline. The row exit codes are in Rows.
	InfraError string      `json:"infra_error,omitempty"`
	Rows       []RowResult `json:"rows"`
	// ResultsSHA256 is the SHA-256 of results.tgz.
	ResultsSHA256 string `json:"results_sha256,omitempty"`
}

type agent struct {
	root string
	// out is the directory for the outputs. Empty: use the upload URLs.
	out    string
	ec2    bool
	client *http.Client
	imds   string
}

func main() {
	specArg := flag.String("spec", "", "spec file or HTTPS URL")
	root := flag.String("root", "/opt/perf", "work directory: bin/, run/ and agent.log")
	out := flag.String("out", "", "write the outputs to this directory, not to the upload URLs of the spec")
	ec2 := flag.Bool("ec2", false, "the host is an EC2 instance: read IMDSv2, install missing kernel modules, and power off at the end")
	flag.Parse()
	if *specArg == "" {
		fmt.Fprintln(os.Stderr, "usage: perfagent -spec FILE|URL [-root DIR] [-out DIR] [-ec2]")
		os.Exit(2)
	}

	code := 1
	if err := os.MkdirAll(*root, 0o755); err != nil {
		slog.Error("Failed to make the work directory", "dir", *root, "error", err)
	} else {
		code = runAgent(*root, *out, *ec2, *specArg)
	}
	if *ec2 {
		slog.Info("Powering off the host")
		if out, err := exec.Command("systemctl", "poweroff").CombinedOutput(); err != nil {
			slog.Error("Failed to power off the host", "error", err, "output", string(out))
		}
	}
	os.Exit(code)
}

func runAgent(root, out string, ec2 bool, specArg string) int {
	logf, err := os.Create(filepath.Join(root, "agent.log"))
	if err != nil {
		slog.Error("Failed to make the agent log", "error", err)
		return 1
	}
	defer logf.Close()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, logf), nil)))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := &agent{root: root, out: out, ec2: ec2, client: &http.Client{Timeout: 5 * time.Minute}, imds: imdsBase}
	if err := a.main(ctx, specArg); err != nil {
		slog.Error("Failed to put the outputs", "error", err)
		return 1
	}
	return 0
}

// main runs the spec and puts the outputs. It returns an error only when the
// outputs are not in place.
func (a *agent) main(ctx context.Context, specArg string) error {
	rep := Report{StartedAt: time.Now().UTC(), Host: hostFacts()}
	spec, err := loadSpec(ctx, a.client, specArg)
	if err == nil {
		err = spec.validate(a.out == "")
	}
	if err != nil {
		rep.InfraError = err.Error()
	} else {
		rep.RunID = spec.RunID
		if err := a.run(ctx, spec, &rep); err != nil {
			rep.InfraError = err.Error()
		}
	}
	if rep.InfraError != "" {
		slog.Error("The run has an infra error", "error", rep.InfraError)
	}
	// The uploads get their own time after the deadline or a signal.
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), uploadTimeout)
	defer cancel()
	return a.publish(uctx, spec, &rep)
}

// run fetches the files, sets up the host and runs the rows until the deadline.
func (a *agent) run(ctx context.Context, spec Spec, rep *Report) error {
	ctx, cancel := context.WithDeadline(ctx, spec.Deadline)
	defer cancel()
	binDir, runDir := filepath.Join(a.root, "bin"), filepath.Join(a.root, "run")
	for _, d := range []string{binDir, filepath.Join(runDir, "results"), filepath.Join(runDir, "logs"), filepath.Join(runDir, "work")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	hostClass := ""
	if a.ec2 {
		facts, err := readIMDS(ctx, a.imds)
		rep.Host.EC2 = facts
		if err != nil {
			return err
		}
		hostClass = facts.InstanceType
		slog.Info("Read the instance facts", "instance_id", facts.InstanceID, "type", facts.InstanceType, "az", facts.AZ, "ami", facts.AMI)
	}
	for _, f := range spec.Bins {
		if err := fetch(ctx, a.client, f, binDir, 0o755); err != nil {
			return err
		}
	}
	for _, f := range spec.Files {
		if err := fetch(ctx, a.client, f, runDir, 0o644); err != nil {
			return err
		}
	}
	slog.Info("Fetched the files", "bins", len(spec.Bins), "files", len(spec.Files))
	if err := setSysctls(spec.Sysctls); err != nil {
		return err
	}
	if err := loadModules(ctx, spec.Modules, rep.Host.Kernel, a.ec2); err != nil {
		return err
	}
	if spec.Tun {
		if err := ensureTun(); err != nil {
			return err
		}
	}
	rep.Rows = runRows(ctx, filepath.Join(binDir, "perfrig"), binDir, runDir, hostClass, spec.Nodes, spec.Rows)
	if err := ctx.Err(); errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("the rows did not end before the deadline %s: %w", spec.Deadline.Format(time.RFC3339), err)
	} else if err != nil {
		return fmt.Errorf("the rows stopped: %w", err)
	}
	return nil
}

// publish packs the run directory and puts results.tgz, agent.log and then
// agent.json. A failed upload of results.tgz or agent.log is an infra error
// in agent.json.
func (a *agent) publish(ctx context.Context, spec Spec, rep *Report) error {
	putFile := func(name, url string, data []byte) error {
		switch {
		case a.out != "":
			if err := os.MkdirAll(a.out, 0o755); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(a.out, name), data, 0o644)
		case url != "":
			return put(ctx, a.client, url, data)
		default:
			return errors.New("no upload URL")
		}
	}
	var errs []error
	runDir := filepath.Join(a.root, "run")
	if _, err := os.Stat(runDir); err == nil {
		n, err := removeFiles(runDir, spec.Remove)
		if err != nil {
			return fmt.Errorf("remove files before the upload: %w", err)
		}
		var tgz bytes.Buffer
		if err := pack(runDir, &tgz); err != nil {
			return fmt.Errorf("pack the results: %w", err)
		}
		slog.Info("Putting the results", "bytes", tgz.Len(), "removed_files", n)
		if err := putFile("results.tgz", spec.Upload.Results, tgz.Bytes()); err != nil {
			errs = append(errs, fmt.Errorf("put results.tgz: %w", err))
		} else {
			rep.ResultsSHA256 = sha256Hex(tgz.Bytes())
		}
	}
	logData, err := os.ReadFile(filepath.Join(a.root, "agent.log"))
	if err == nil {
		err = putFile("agent.log", spec.Upload.Log, logData)
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("put agent.log: %w", err))
	}
	if err := errors.Join(errs...); err != nil {
		slog.Error("Failed to put an output", "error", err)
		rep.InfraError = errors.Join(errorOrNil(rep.InfraError), err).Error()
	}
	rep.FinishedAt = time.Now().UTC()
	report, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := putFile("agent.json", spec.Upload.Report, append(report, '\n')); err != nil {
		return fmt.Errorf("put agent.json: %w", err)
	}
	return nil
}

func errorOrNil(s string) error {
	if s == "" {
		return nil
	}
	return errors.New(s)
}
