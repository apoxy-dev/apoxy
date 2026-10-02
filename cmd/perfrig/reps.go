package main

import (
	"bytes"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"time"
)

// Run is one rep: new server and client processes on the same rig.
type Run struct {
	Rep       int       `json:"rep"`
	StartedAt time.Time `json:"started_at"`
	// Load1 is the 1-minute load average of the host at the start and at the end.
	Load1Start float64    `json:"load1_start"`
	Load1End   float64    `json:"load1_end"`
	Throughput Throughput `json:"throughput"`
	CPU        CPU        `json:"cpu"`
	// WorkloadResult is the last line of the client stdout when it is a JSON object.
	WorkloadResult json.RawMessage `json:"workload_result,omitempty"`
}

// throughputFields are the workload result fields that Throughput has.
var throughputFields = map[string]bool{
	"seconds": true, "bits_per_second": true, "packets_per_second": true,
	"retransmits": true, "lost_percent": true, "jitter_ms": true,
}

// summarize sets Reps, Throughput, CPU and Info to the medians of the runs.
// Each field is the median of that field.
func (res *Result) summarize() {
	runs := res.Runs
	res.Reps = len(runs)
	m := func(f func(Run) float64) float64 { return medianOf(runs, f) }
	tp := Throughput{
		Seconds:          m(func(r Run) float64 { return r.Throughput.Seconds }),
		BitsPerSecond:    m(func(r Run) float64 { return r.Throughput.BitsPerSecond }),
		PacketsPerSecond: m(func(r Run) float64 { return r.Throughput.PacketsPerSecond }),
		Retransmits:      int64(math.Round(m(func(r Run) float64 { return float64(r.Throughput.Retransmits) }))),
		LostPercent:      m(func(r Run) float64 { return r.Throughput.LostPercent }),
		JitterMS:         m(func(r Run) float64 { return r.Throughput.JitterMS }),
	}
	if tp.BitsPerSecond > 0 {
		tp.Gbps = round(tp.BitsPerSecond/1e9, 3)
	}
	res.Throughput = tp
	res.CPU = CPU{
		WallS:  round(m(func(r Run) float64 { return r.CPU.WallS }), 3),
		Client: medianProcCPU(runs, func(r Run) ProcCPU { return r.CPU.Client }),
		Server: medianProcCPU(runs, func(r Run) ProcCPU { return r.CPU.Server }),
		Host: HostCPU{
			UserS:   round(m(func(r Run) float64 { return r.CPU.Host.UserS }), 3),
			SystemS: round(m(func(r Run) float64 { return r.CPU.Host.SystemS }), 3),
			IRQS:    round(m(func(r Run) float64 { return r.CPU.Host.IRQS }), 3),
			TotalS:  round(m(func(r Run) float64 { return r.CPU.Host.TotalS }), 3),
			Cores:   round(m(func(r Run) float64 { return r.CPU.Host.Cores }), 3),
		},
		Relay: medianRelayCPU(runs),
	}
	res.Info = medianInfo(runs)
}

func medianProcCPU(runs []Run, f func(Run) ProcCPU) ProcCPU {
	m := func(g func(ProcCPU) float64) float64 { return medianOf(runs, func(r Run) float64 { return g(f(r)) }) }
	return ProcCPU{
		UserS:        round(m(func(c ProcCPU) float64 { return c.UserS }), 3),
		SystemS:      round(m(func(c ProcCPU) float64 { return c.SystemS }), 3),
		TotalS:       round(m(func(c ProcCPU) float64 { return c.TotalS }), 3),
		Cores:        round(m(func(c ProcCPU) float64 { return c.Cores }), 4),
		CoresPerGbps: round(m(func(c ProcCPU) float64 { return c.CoresPerGbps }), 6),
	}
}

// medianRelayCPU returns the median relay CPU of the runs that have one, or nil.
func medianRelayCPU(runs []Run) *RelayCPU {
	var cores, perGbps []float64
	for _, r := range runs {
		if r.CPU.Relay != nil {
			cores = append(cores, r.CPU.Relay.Cores)
			perGbps = append(perGbps, r.CPU.Relay.CoresPerGbps)
		}
	}
	if len(cores) == 0 {
		return nil
	}
	return &RelayCPU{Cores: round(median(cores), 4), CoresPerGbps: round(median(perGbps), 6)}
}

// medianInfo returns the median of each workload result number over the runs that have it.
func medianInfo(runs []Run) map[string]float64 {
	values := map[string][]float64{}
	for _, r := range runs {
		for k, v := range workloadNumbers(r.WorkloadResult) {
			values[k] = append(values[k], v)
		}
	}
	if len(values) == 0 {
		return nil
	}
	info := make(map[string]float64, len(values))
	for k, v := range values {
		info[k] = median(v)
	}
	return info
}

// workloadNumbers returns the numbers of a workload result by key path, for
// example "load_rtt_ms.p99". It skips the Throughput fields and the wall clock
// times (keys that end in "_unix_ms").
func workloadNumbers(line json.RawMessage) map[string]float64 {
	var top map[string]any
	if len(line) == 0 || json.Unmarshal(line, &top) != nil {
		return nil
	}
	out := map[string]float64{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch v := v.(type) {
		case float64:
			out[prefix] = v
		case map[string]any:
			for k, x := range v {
				if (prefix == "" && throughputFields[k]) || strings.HasSuffix(k, "_unix_ms") {
					continue
				}
				if prefix != "" {
					k = prefix + "." + k
				}
				walk(k, x)
			}
		}
	}
	walk("", top)
	return out
}

// relayCPU reads the relay CPU of the measured window from a workload result.
// It returns nil when the result has no relay CPU.
func relayCPU(line json.RawMessage) *RelayCPU {
	var v struct {
		Cores        float64 `json:"relay_cores"`
		CoresPerGbps float64 `json:"relay_cores_per_gbps"`
	}
	if len(line) == 0 || json.Unmarshal(line, &v) != nil || v.Cores <= 0 {
		return nil
	}
	return &RelayCPU{Cores: round(v.Cores, 4), CoresPerGbps: round(v.CoresPerGbps, 6)}
}

// jsonObjectLine returns the last non-empty line of out when it is a JSON object.
func jsonObjectLine(out []byte) json.RawMessage {
	line := lastLine(out)
	if len(line) == 0 || line[0] != '{' || !json.Valid(line) {
		return nil
	}
	return bytes.Clone(line)
}

// lastLine returns the last non-empty line of out, with no spaces at the ends.
func lastLine(out []byte) []byte {
	lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
	return bytes.TrimSpace(lines[len(lines)-1])
}

func medianOf(runs []Run, f func(Run) float64) float64 {
	v := make([]float64, len(runs))
	for i, r := range runs {
		v[i] = f(r)
	}
	return median(v)
}

// median returns the middle value, or the mean of the 2 middle values.
func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}
