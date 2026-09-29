package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const iperf3Port = 5201

// iperf3 3.16 and later run one thread for each stream.
const iperf3MinMajor, iperf3MinMinor = 3, 16

func iperf3Workload(name string, udp bool) Workload {
	w := Workload{
		Name:  name,
		Tools: iperf3Tools,
		Server: func(Env) []string {
			return []string{"iperf3", "-s", "-1", "-p", strconv.Itoa(iperf3Port)}
		},
		Client: func(e Env) []string {
			args := []string{
				"iperf3", "-c", e.ServerIP, "-p", strconv.Itoa(iperf3Port), "-J",
				"--connect-timeout", "5000",
				"-t", strconv.Itoa(max(seconds(e.Duration), 1)),
				"-O", strconv.Itoa(seconds(e.Omit)),
				"-P", strconv.Itoa(e.Streams),
			}
			if udp {
				args = append(args, "-u")
			}
			if e.Bitrate != "" {
				args = append(args, "-b", e.Bitrate)
			}
			if e.Window != "" {
				args = append(args, "-w", e.Window)
			}
			return args
		},
		// The iperf3 control connection is TCP also for UDP tests.
		Ready: Socket{Proto: "tcp", Port: iperf3Port},
		Parse: func(client, _ []byte) (Throughput, error) { return parseIperf3(client) },
	}
	if udp {
		// Without a larger receive buffer the receiver drops datagrams at 2 Gbps.
		w.DefaultBitrate = "2G"
		w.DefaultWindow = "8M"
	}
	return w
}

func iperf3Tools(ctx context.Context) (map[string]string, error) {
	out, err := command(ctx, "iperf3", "--version")
	if err != nil {
		return nil, err
	}
	v, err := parseIperf3Version(out)
	if err != nil {
		return nil, err
	}
	if !versionAtLeast(v, iperf3MinMajor, iperf3MinMinor) {
		return nil, fmt.Errorf("iperf3 %s is too old: the rig needs %d.%d or later", v, iperf3MinMajor, iperf3MinMinor)
	}
	return map[string]string{"iperf3": v}, nil
}

// parseIperf3Version reads "iperf 3.19.1 (cJSON 1.7.15)".
func parseIperf3Version(out string) (string, error) {
	f := strings.Fields(out)
	if len(f) < 2 || f[0] != "iperf" {
		return "", fmt.Errorf("unexpected iperf3 --version output: %q", strings.SplitN(out, "\n", 2)[0])
	}
	return strings.TrimRight(f[1], "+"), nil
}

// versionAtLeast compares the major and minor parts of a version like 3.19.1.
func versionAtLeast(v string, major, minor int) bool {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	maj, err1 := leadingInt(parts[0])
	mnr, err2 := leadingInt(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return maj > major || (maj == major && mnr >= minor)
}

// leadingInt reads the digits at the start of s, so "17rc1" gives 17.
func leadingInt(s string) (int, error) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return strconv.Atoi(s[:i])
}

type iperf3Output struct {
	Error string `json:"error"`
	End   struct {
		SumSent     *iperf3Sum `json:"sum_sent"`
		SumReceived *iperf3Sum `json:"sum_received"`
	} `json:"end"`
}

type iperf3Sum struct {
	Seconds       float64 `json:"seconds"`
	BitsPerSecond float64 `json:"bits_per_second"`
	Retransmits   int64   `json:"retransmits"`
	JitterMS      float64 `json:"jitter_ms"`
	LostPackets   int64   `json:"lost_packets"`
	Packets       int64   `json:"packets"`
	LostPercent   float64 `json:"lost_percent"`
}

// parseIperf3 reads the receiver side of an iperf3 -J client report.
func parseIperf3(out []byte) (Throughput, error) {
	var o iperf3Output
	if err := json.Unmarshal(out, &o); err != nil {
		return Throughput{}, fmt.Errorf("parse iperf3 JSON: %w", err)
	}
	if o.Error != "" {
		return Throughput{}, fmt.Errorf("iperf3: %s", o.Error)
	}
	rx := o.End.SumReceived
	if rx == nil || rx.Seconds <= 0 {
		return Throughput{}, errors.New("iperf3 JSON has no end.sum_received")
	}
	t := Throughput{
		Seconds:       rx.Seconds,
		BitsPerSecond: rx.BitsPerSecond,
		LostPercent:   rx.LostPercent,
		JitterMS:      rx.JitterMS,
	}
	if o.End.SumSent != nil {
		t.Retransmits = o.End.SumSent.Retransmits
	}
	// Only UDP reports packets. The receiver counts lost packets in Packets.
	if rx.Packets > 0 {
		t.PacketsPerSecond = float64(rx.Packets-rx.LostPackets) / rx.Seconds
	}
	return t, nil
}
