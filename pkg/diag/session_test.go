package diag_test

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/diag"
	"github.com/apoxy-dev/apoxy/pkg/diag/commands"
)

// TestEndToEnd wires a real Session (server side) against a real
// Dispatcher (agent side) over io.Pipe streams. This exercises the
// full nd-json round trip without needing a real http3 stack and
// catches protocol-level mismatches the dispatcher unit tests can't.
func TestEndToEnd(t *testing.T) {
	// Down: server → agent (commands).
	downR, downW := io.Pipe()
	// Up: agent → server (responses).
	upR, upW := io.Pipe()

	// Agent side
	reg := diag.NewRegistry()
	commands.RegisterAll(reg)
	disp := diag.New(reg)

	dispCtx, cancelDisp := context.WithCancel(context.Background())
	defer cancelDisp()
	dispDone := make(chan struct{})
	go func() {
		_ = disp.Run(dispCtx, downR, upW)
		close(dispDone)
	}()

	// Server side
	sess := diag.NewSession(downW, upR)
	sess.Start()
	defer sess.Close()

	t.Run("agent_command_returns_manifest", func(t *testing.T) {
		ch, err := sess.Invoke(context.Background(), "agent", nil)
		if err != nil {
			t.Fatalf("invoke: %v", err)
		}
		var raw json.RawMessage
		select {
		case resp := <-ch:
			if resp.Error != nil {
				t.Fatalf("agent returned error: %+v", resp.Error)
			}
			raw = resp.Result
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for response")
		}

		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		cmds, _ := got["commands"].([]any)
		if len(cmds) < 2 {
			t.Fatalf("expected ≥2 commands in manifest, got %d (%v)", len(cmds), got)
		}
		seen := map[string]bool{}
		for _, c := range cmds {
			m, _ := c.(map[string]any)
			if name, _ := m["name"].(string); name != "" {
				seen[name] = true
			}
		}
		for _, want := range []string{"agent", "clock"} {
			if !seen[want] {
				t.Errorf("manifest missing %q (have %v)", want, seen)
			}
		}
	})

	t.Run("clock_command_returns_wall_time", func(t *testing.T) {
		ch, err := sess.Invoke(context.Background(), "clock", nil)
		if err != nil {
			t.Fatalf("invoke: %v", err)
		}
		select {
		case resp := <-ch:
			if resp.Error != nil {
				t.Fatalf("clock returned error: %+v", resp.Error)
			}
			var got map[string]any
			if err := json.Unmarshal(resp.Result, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if _, ok := got["wall_unix_ns"]; !ok {
				t.Errorf("clock result missing wall_unix_ns: %v", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout")
		}
	})

	t.Run("unknown_command_returns_error", func(t *testing.T) {
		ch, err := sess.Invoke(context.Background(), "nope", nil)
		if err != nil {
			t.Fatalf("invoke: %v", err)
		}
		select {
		case resp := <-ch:
			if resp.Error == nil || resp.Error.Code != "unknown_command" {
				t.Fatalf("expected unknown_command error, got %+v", resp)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout")
		}
	})
}
