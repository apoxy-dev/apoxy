// Package commands holds the built-in diag commands. Each file
// registers one command; the dispatcher composes them into a Registry.
package commands

import (
	"context"
	"encoding/json"
	"flag"
	"runtime"
	"time"

	"github.com/apoxy-dev/apoxy/build"
	"github.com/apoxy-dev/apoxy/pkg/diag"
)

// Agent returns a Command that reports static + slow-changing agent
// state and the manifest of every other command in r. It is the first
// command an operator runs against an unfamiliar agent.
func Agent(r *diag.Registry) diag.Command { return &agentCmd{r: r, started: time.Now()} }

type agentCmd struct {
	r       *diag.Registry
	started time.Time
}

func (a *agentCmd) Spec() diag.Spec {
	return diag.Spec{
		Name:      "agent",
		Desc:      "Agent identity, build, runtime, and the manifest of every available diag command.",
		CeilingMs: 5_000,
	}
}

type agentResult struct {
	Version    string      `json:"version"`
	BuildDate  string      `json:"build_date"`
	CommitHash string      `json:"commit_hash"`
	GoVersion  string      `json:"go_version"`
	GOOS       string      `json:"goos"`
	GOARCH     string      `json:"goarch"`
	NumCPU     int         `json:"num_cpu"`
	UptimeSec  float64     `json:"uptime_sec"`
	Flags      []flagState `json:"flags"`
	Commands   []diag.Spec `json:"commands"`
}

type flagState struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Default string `json:"default"`
}

func (a *agentCmd) Run(_ context.Context, _ json.RawMessage, _ diag.Emitter) (any, error) {
	return agentResult{
		Version:    build.BuildVersion,
		BuildDate:  build.BuildDate,
		CommitHash: build.CommitHash,
		GoVersion:  runtime.Version(),
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		NumCPU:     runtime.NumCPU(),
		UptimeSec:  time.Since(a.started).Seconds(),
		Flags:      collectFlags(),
		Commands:   a.r.Specs(),
	}, nil
}

func collectFlags() []flagState {
	var out []flagState
	flag.VisitAll(func(f *flag.Flag) {
		out = append(out, flagState{Name: f.Name, Value: f.Value.String(), Default: f.DefValue})
	})
	return out
}
