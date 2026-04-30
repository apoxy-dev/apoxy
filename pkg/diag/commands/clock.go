package commands

import (
	"context"
	"encoding/json"
	"runtime"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/diag"
)

// Clock returns a Command that reports the agent's current notion of
// time. Useful for diagnosing TLS / JWT failures rooted in clock skew.
func Clock() diag.Command { return clockCmd{} }

type clockCmd struct{}

func (clockCmd) Spec() diag.Spec {
	return diag.Spec{
		Name:      "clock",
		Desc:      "Wall, monotonic, and runtime-reported time as observed by the agent.",
		CeilingMs: 1_000,
	}
}

type clockResult struct {
	WallUnixNs    int64  `json:"wall_unix_ns"`
	WallRFC3339   string `json:"wall_rfc3339"`
	MonotonicNs   int64  `json:"monotonic_ns"`
	TimezoneName  string `json:"timezone_name"`
	TimezoneOffS  int    `json:"timezone_offset_s"`
	GoVersion     string `json:"go_version"`
}

func (clockCmd) Run(_ context.Context, _ json.RawMessage, _ diag.Emitter) (any, error) {
	now := time.Now()
	zoneName, zoneOff := now.Zone()
	// time.Since(epoch) yields the monotonic delta; we report it raw so
	// the caller can compare two reads without trusting the wall clock.
	mono := time.Since(time.Unix(0, 0))
	return clockResult{
		WallUnixNs:   now.UnixNano(),
		WallRFC3339:  now.UTC().Format(time.RFC3339Nano),
		MonotonicNs:  int64(mono),
		TimezoneName: zoneName,
		TimezoneOffS: zoneOff,
		GoVersion:    runtime.Version(),
	}, nil
}
