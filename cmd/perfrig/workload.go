package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Workload is a server command and a client command. The server runs in the
// server netns and the client in the client netns. Add a new workload to
// workloads, or use the exec workload with shell commands.
type Workload struct {
	Name string
	// Tools returns the versions of the programs that the workload needs.
	Tools func(ctx context.Context) (map[string]string, error)
	// Server and Client return the argv for each side.
	Server func(Env) []string
	Client func(Env) []string
	// Ready is the socket that the server opens. The client starts after the
	// socket is open. A zero Socket means start the client after 1 s.
	Ready Socket
	// Parse reads the throughput from the stdout of the client and the server.
	Parse func(client, server []byte) (Throughput, error)
	// DefaultBitrate and DefaultWindow apply when the flags are empty.
	DefaultBitrate string
	DefaultWindow  string
}

// Env is what a workload command can use. Both commands also get it as
// environment variables (see vars).
type Env struct {
	ServerIP string
	ClientIP string
	Duration time.Duration
	Omit     time.Duration
	Streams  int
	Bitrate  string
	Window   string
	// Dir is a directory for workload files, for example qlogs.
	Dir string
}

func (e Env) vars() []string {
	return []string{
		"SERVER_IP=" + e.ServerIP,
		"CLIENT_IP=" + e.ClientIP,
		"DURATION_S=" + strconv.Itoa(seconds(e.Duration)),
		"OMIT_S=" + strconv.Itoa(seconds(e.Omit)),
		"STREAMS=" + strconv.Itoa(e.Streams),
		"BITRATE=" + e.Bitrate,
		"WINDOW=" + e.Window,
		"WORK_DIR=" + e.Dir,
	}
}

// workloads are the built-in workloads.
var workloads = map[string]func() Workload{
	"iperf3-tcp": func() Workload { return iperf3Workload("iperf3-tcp", false) },
	"iperf3-udp": func() Workload { return iperf3Workload("iperf3-udp", true) },
}

func workloadNames() []string {
	names := []string{"exec"}
	for n := range workloads {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// execWorkload runs shell commands. The last stdout line of the client must be
// the JSON line that parseJSONLine reads.
func execWorkload(cfg config) (Workload, error) {
	if cfg.Name == "" || cfg.ServerCmd == "" || cfg.ClientCmd == "" {
		return Workload{}, errors.New("the exec workload needs -name, -server-cmd and -client-cmd")
	}
	ready, err := parseSocket(cfg.Ready)
	if err != nil {
		return Workload{}, err
	}
	return Workload{
		Name:   cfg.Name,
		Server: func(Env) []string { return []string{"sh", "-c", cfg.ServerCmd} },
		Client: func(Env) []string { return []string{"sh", "-c", cfg.ClientCmd} },
		Ready:  ready,
		Parse:  func(client, _ []byte) (Throughput, error) { return parseJSONLine(client) },
	}, nil
}

func newWorkload(cfg config) (Workload, error) {
	if cfg.Workload == "exec" {
		return execWorkload(cfg)
	}
	w, ok := workloads[cfg.Workload]
	if !ok {
		return Workload{}, fmt.Errorf("unknown workload %q: want one of %s", cfg.Workload, strings.Join(workloadNames(), ", "))
	}
	return w(), nil
}

// parseJSONLine reads the last non-empty line of the client stdout, for example
// {"seconds": 30, "bits_per_second": 2.1e9, "packets_per_second": 180000}.
func parseJSONLine(out []byte) (Throughput, error) {
	last := lastLine(out)
	if len(last) == 0 {
		return Throughput{}, errors.New("the client printed no result line")
	}
	var t Throughput
	if err := json.Unmarshal(last, &t); err != nil {
		return Throughput{}, fmt.Errorf("parse client result line %q: %w", last, err)
	}
	if t.BitsPerSecond <= 0 && t.PacketsPerSecond <= 0 {
		return Throughput{}, fmt.Errorf("client result line %q has no bits_per_second or packets_per_second", last)
	}
	return t, nil
}

// seconds rounds d up to whole seconds, because iperf3 takes whole seconds.
func seconds(d time.Duration) int {
	return int((d + time.Second - 1) / time.Second)
}
