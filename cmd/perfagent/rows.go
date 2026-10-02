package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// RowResult is the outcome of one row. The perfrig result is in
// results/GROUP/ID.json and its log in logs/ID.log.
type RowResult struct {
	ID    string `json:"id"`
	Group string `json:"group"`
	// ExitCode is the perfrig exit code: 0 pass, 1 fail, 3 infra error. It is
	// -1 when perfrig did not start or did not exit.
	ExitCode int     `json:"exit_code"`
	Seconds  float64 `json:"seconds"`
	Error    string  `json:"error,omitempty"`
}

// rowStopDelay is the time that perfrig gets after SIGINT to remove its netns.
var rowStopDelay = 30 * time.Second

// rowArgs returns the perfrig argv of a row. The agent flags come last, so
// they replace the same flags in the row args.
func rowArgs(r Row, hostClass string) []string {
	args := append([]string{"run"}, r.Args...)
	if hostClass != "" {
		args = append(args, "-host-class="+hostClass)
	}
	return append(args,
		"-out="+filepath.Join("results", r.Group, r.ID+".json"),
		"-out-dir="+filepath.Join("work", r.ID))
}

// runRows runs the rows one at a time in runDir, until ctx ends.
func runRows(ctx context.Context, perfrig, binDir, runDir, hostClass string, rows []Row) []RowResult {
	var out []RowResult
	for _, r := range rows {
		res := runRow(ctx, perfrig, binDir, runDir, hostClass, r)
		slog.Info("Row done", "row", r.ID, "exit_code", res.ExitCode, "seconds", res.Seconds, "error", res.Error)
		out = append(out, res)
	}
	return out
}

func runRow(ctx context.Context, perfrig, binDir, runDir, hostClass string, r Row) RowResult {
	res := RowResult{ID: r.ID, Group: r.Group, ExitCode: -1}
	if err := ctx.Err(); err != nil {
		res.Error = "not run: " + err.Error()
		return res
	}
	for _, d := range []string{filepath.Join(runDir, "results", r.Group), filepath.Join(runDir, "work", r.ID)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			res.Error = err.Error()
			return res
		}
	}
	logf, err := os.Create(filepath.Join(runDir, "logs", r.ID+".log"))
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer logf.Close()

	start := time.Now()
	cmd := exec.CommandContext(ctx, perfrig, rowArgs(r, hostClass)...)
	cmd.Dir = runDir
	// The rows find the fetched tools first. In Env, the last PATH wins.
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Stdout = logf
	cmd.Stderr = logf
	// perfrig removes its netns on SIGINT.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = rowStopDelay
	err = cmd.Run()
	res.Seconds = time.Since(start).Round(time.Millisecond).Seconds()
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		res.Error = fmt.Sprintf("stopped: %v", ctx.Err())
		if errors.As(err, &exitErr) && exitErr.Exited() {
			res.ExitCode = exitErr.ExitCode()
		}
	case errors.As(err, &exitErr) && exitErr.Exited():
		res.ExitCode = exitErr.ExitCode()
	case err != nil:
		res.Error = err.Error()
	default:
		res.ExitCode = 0
	}
	return res
}
