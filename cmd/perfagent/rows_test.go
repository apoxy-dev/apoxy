package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain runs the test binary as a fake perfrig when the agent starts it.
func TestMain(m *testing.M) {
	if os.Getenv("PERFAGENT_FAKE_PERFRIG") == "1" {
		os.Exit(fakePerfrig(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakePerfrig acts on -fake=pass|fail|infra|hang, writes -out and prints its args.
func fakePerfrig(args []string) int {
	flags := map[string]string{}
	for _, a := range args[1:] {
		k, v, _ := strings.Cut(strings.TrimPrefix(a, "-"), "=")
		flags[k] = v
	}
	fmt.Println(strings.Join(args, " "))
	if out := flags["out"]; out != "" && flags["fake"] != "hang" {
		if err := os.WriteFile(out, []byte(`{"key": "`+flags["host-class"]+`"}`), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	switch flags["fake"] {
	case "pass":
		return 0
	case "infra":
		return 3
	case "hang":
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		return 3
	default:
		return 1
	}
}

func TestRowArgs(t *testing.T) {
	cases := []struct {
		name      string
		row       Row
		hostClass string
		nodes     map[string]string
		want      []string
	}{
		{
			name:  "node row with the other hosts",
			row:   Row{ID: "direct-2node", Group: "info", Cmd: "node", Args: []string{"-role=client"}},
			nodes: map[string]string{"server": "10.0.1.5", "relay": "10.0.1.6"},
			want:  []string{"node", "-role=client", "-node=relay=10.0.1.6", "-node=server=10.0.1.5", "-out=results/info/direct-2node.json", "-out-dir=work/direct-2node"},
		},
		{
			name:  "run row gets no node flags",
			row:   Row{ID: "a", Group: "info", Cmd: "run", Args: []string{"-loss=0.1"}},
			nodes: map[string]string{"server": "10.0.1.5"},
			want:  []string{"run", "-loss=0.1", "-out=results/info/a.json", "-out-dir=work/a"},
		},
		{
			name: "no host class",
			row:  Row{ID: "netstack-psp-relay", Group: "floor", Args: []string{"-workload=exec"}},
			want: []string{"run", "-workload=exec", "-out=results/floor/netstack-psp-relay.json", "-out-dir=work/netstack-psp-relay"},
		},
		{
			name:      "host class after the row args",
			row:       Row{ID: "loss", Group: "info", Args: []string{"-host-class=x", "-loss=0.1"}},
			hostClass: "c7a.8xlarge",
			want:      []string{"run", "-host-class=x", "-loss=0.1", "-host-class=c7a.8xlarge", "-out=results/info/loss.json", "-out-dir=work/loss"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, rowArgs(tc.row, tc.hostClass, tc.nodes))
		})
	}
}

func TestRunRows(t *testing.T) {
	t.Setenv("PERFAGENT_FAKE_PERFRIG", "1")
	rowStopDelay = 5 * time.Second
	runDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(runDir, "logs"), 0o755))
	run := func(ctx context.Context, rows ...Row) []RowResult {
		return runRows(ctx, os.Args[0], t.TempDir(), runDir, "c7a.8xlarge", nil, rows)
	}

	got := run(context.Background(),
		Row{ID: "pass", Group: "floor", Args: []string{"-fake=pass"}},
		Row{ID: "fail", Group: "info", Args: []string{"-fake=fail"}},
		Row{ID: "infra", Group: "info", Args: []string{"-fake=infra"}},
	)
	// The context ends while the hang row runs. The next row does not start.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got = append(got, run(ctx,
		Row{ID: "hang", Group: "info", Args: []string{"-fake=hang"}},
		Row{ID: "late", Group: "info", Args: []string{"-fake=pass"}},
	)...)

	require.Len(t, got, 5)
	codes := map[string]int{}
	for _, r := range got {
		codes[r.ID] = r.ExitCode
	}
	assert.Equal(t, map[string]int{"pass": 0, "fail": 1, "infra": 3, "hang": 3, "late": -1}, codes)
	assert.Empty(t, got[0].Error)
	assert.Contains(t, got[3].Error, "stopped")
	assert.Contains(t, got[4].Error, "not run")

	out, err := os.ReadFile(filepath.Join(runDir, "results", "floor", "pass.json"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"key": "c7a.8xlarge"}`, string(out))
	log, err := os.ReadFile(filepath.Join(runDir, "logs", "pass.log"))
	require.NoError(t, err)
	assert.Contains(t, string(log), "-out-dir=work/pass")
}
