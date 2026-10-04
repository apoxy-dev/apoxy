package main

import (
	"fmt"
	"math"
	"runtime"
	"strconv"
	"time"
)

// Result is the JSON output of one run.
type Result struct {
	// Key names the settings that change the numbers. Baseline entries use it.
	Key      string `json:"key"`
	Workload string `json:"workload"`
	// Role is the role of this host in "perfrig node": client, server or relay.
	Role      string    `json:"role,omitempty"`
	StartedAt time.Time `json:"started_at"`
	Host      Host      `json:"host"`
	Settings  Settings  `json:"settings"`
	// InfraError tells why the run is not valid, for example CPU steal. Compare does not check the result.
	InfraError string            `json:"infra_error,omitempty"`
	Tools      map[string]string `json:"tools,omitempty"`
	Sysctls    map[string]string `json:"sysctls"`
	RTT        RTT               `json:"rtt_ms"`
	// RelayRTT is the ping RTT from the client host to the relay host, in "perfrig node".
	RelayRTT *RTT `json:"relay_rtt_ms,omitempty"`
	// Reps is the number of runs. Throughput, CPU and Info are the medians of
	// the runs, each field on its own.
	Reps int `json:"reps"`
	// Retried is true when the median of the first reps failed the baseline
	// and the reps ran one more time.
	Retried    bool       `json:"retried,omitempty"`
	Throughput Throughput `json:"throughput"`
	CPU        CPU        `json:"cpu"`
	// Info has the median of each number in the workload results. No check uses it.
	Info map[string]float64 `json:"info,omitempty"`
	// NIC has the median increase of each NIC drop counter, in "perfrig node".
	NIC  map[string]int64 `json:"nic_counters,omitempty"`
	Runs []Run            `json:"runs"`
}

// Host describes the machine that ran the rig.
type Host struct {
	Arch string `json:"arch"`
	// Class is the first word of the result key when set, for example an
	// EC2 instance type. Else the key starts with Arch.
	Class    string `json:"class,omitempty"`
	Kernel   string `json:"kernel"`
	CPUs     int    `json:"cpus"`
	CPUModel string `json:"cpu_model,omitempty"`
	// NIC is the network device of the host in "perfrig node".
	NIC *NIC `json:"nic,omitempty"`
}

// NIC describes the network device of a host.
type NIC struct {
	Dev      string `json:"dev"`
	Driver   string `json:"driver,omitempty"`
	Version  string `json:"version,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	MTU      int    `json:"mtu"`
	RxQueues int    `json:"rx_queues"`
	// XDPFeatures are the XDP features that the driver reports, for example
	// basic, redirect and xsk-zerocopy. Empty when the kernel has no netdev API.
	XDPFeatures []string `json:"xdp_features,omitempty"`
	// XDPZCMaxSegs is the segment limit of zero-copy AF_XDP, when the driver has it.
	XDPZCMaxSegs uint32 `json:"xdp_zc_max_segs,omitempty"`
}

// Settings are the rig and workload settings of one run.
type Settings struct {
	DurationS   float64 `json:"duration_s"`
	OmitS       float64 `json:"omit_s"`
	DelayMS     float64 `json:"delay_ms"`
	JitterMS    float64 `json:"jitter_ms"`
	LossPercent float64 `json:"loss_percent"`
	Rate        string  `json:"rate,omitempty"`
	MTU         int     `json:"mtu"`
	QueueLimit  int     `json:"queue_limit"`
	Streams     int     `json:"streams"`
	Bitrate     string  `json:"bitrate,omitempty"`
	Window      string  `json:"window,omitempty"`
}

// RTT is the ping result before the run, in milliseconds.
type RTT struct {
	Min         float64 `json:"min"`
	Avg         float64 `json:"avg"`
	Max         float64 `json:"max"`
	Mdev        float64 `json:"mdev"`
	LossPercent float64 `json:"loss_percent"`
}

// Throughput is what the receiver got. Exec workloads print it as a JSON line.
type Throughput struct {
	Seconds          float64 `json:"seconds"`
	BitsPerSecond    float64 `json:"bits_per_second"`
	Gbps             float64 `json:"gbps"`
	PacketsPerSecond float64 `json:"packets_per_second,omitempty"`
	Retransmits      int64   `json:"retransmits,omitempty"`
	LostPercent      float64 `json:"lost_percent,omitempty"`
	JitterMS         float64 `json:"jitter_ms,omitempty"`
}

// CPU is the CPU time of each side's process tree and of the full host.
type CPU struct {
	// WallS is the client run time, warm-up included. Cores use it.
	WallS  float64 `json:"wall_s"`
	Client ProcCPU `json:"client"`
	Server ProcCPU `json:"server"`
	// Host includes all load on the host while the client ran, also softirq time.
	Host HostCPU `json:"host"`
	// Relay is from the workload result, when it has one. No check uses it.
	Relay *RelayCPU `json:"relay,omitempty"`
}

// RelayCPU is the relay CPU in the measured window of the workload.
type RelayCPU struct {
	Cores        float64 `json:"cores"`
	CoresPerGbps float64 `json:"cores_per_gbps"`
}

// ProcCPU is the user and system time of one side while the client ran. The
// server can run before and after the client, so its time is a delta of samples.
type ProcCPU struct {
	UserS   float64 `json:"user_s"`
	SystemS float64 `json:"system_s"`
	TotalS  float64 `json:"total_s"`
	// Cores is TotalS divided by CPU.WallS.
	Cores        float64 `json:"cores"`
	CoresPerGbps float64 `json:"cores_per_gbps"`
}

// HostCPU is the busy time of all CPUs from /proc/stat.
type HostCPU struct {
	UserS   float64 `json:"user_s"`
	SystemS float64 `json:"system_s"`
	IRQS    float64 `json:"irq_s"`
	TotalS  float64 `json:"total_s"`
	Cores   float64 `json:"cores"`
}

func newProcCPU(user, system, seconds, gbps float64) ProcCPU {
	c := ProcCPU{UserS: round(user, 3), SystemS: round(system, 3), TotalS: round(user+system, 3)}
	if seconds > 0 {
		c.Cores = round((user+system)/seconds, 4)
		if gbps > 0 {
			c.CoresPerGbps = round((user+system)/seconds/gbps, 6)
		}
	}
	return c
}

func resultKey(arch, workload string, s Settings) string {
	return fmt.Sprintf("%s %s streams=%d duration=%gs omit=%gs delay=%gms jitter=%gms loss=%g%% rate=%s queue=%d mtu=%d bitrate=%s window=%s",
		arch, workload, s.Streams, s.DurationS, s.OmitS, s.DelayMS, s.JitterMS, s.LossPercent,
		orNone(s.Rate), s.QueueLimit, s.MTU, orNone(s.Bitrate), orNone(s.Window))
}

// keyClass returns the first word of the result key.
func (h Host) keyClass() string {
	if h.Class != "" {
		return h.Class
	}
	return h.Arch
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// hostArch returns the arch name that uname -m prints.
func hostArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

func round(v float64, digits int) float64 {
	p := math.Pow(10, float64(digits))
	return math.Round(v*p) / p
}

func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}
