package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Workload is a server command and a client command. The server runs in the
// server netns and the client in the client netns. Add a new workload to
// workloads, or use the exec workload with argv lists.
type Workload struct {
	Name string
	// Tools returns the versions of the programs that the workload needs.
	Tools func(ctx context.Context) (map[string]string, error)
	// Server and Client return the argv for each side.
	Server func(Env) []string
	Client func(Env) []string
	// Sidecar, when set, returns the argv of a process in the server netns, or
	// in the relay netns with -relay-netns, for example a relay. It starts
	// before the server and stops after the server exits. Its CPU counts as
	// server CPU.
	Sidecar func(Env) []string
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
	// RelayIP is the address of the relay netns, or ServerIP without one. In
	// "perfrig node", it is the relay host.
	RelayIP  string
	Duration time.Duration
	Omit     time.Duration
	Streams  int
	Bitrate  string
	Window   string
	// Dir is a directory for workload files, for example qlogs.
	Dir string
	// Dev is the network device of this host in "perfrig node". It is empty in the netns rig.
	Dev string
}

func (e Env) vars() []string {
	return []string{
		"SERVER_IP=" + e.ServerIP,
		"CLIENT_IP=" + e.ClientIP,
		"RELAY_IP=" + e.RelayIP,
		"DURATION_S=" + strconv.Itoa(seconds(e.Duration)),
		"OMIT_S=" + strconv.Itoa(seconds(e.Omit)),
		"STREAMS=" + strconv.Itoa(e.Streams),
		"BITRATE=" + e.Bitrate,
		"WINDOW=" + e.Window,
		"WORK_DIR=" + e.Dir,
		"DEV=" + e.Dev,
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

// execWorkload runs the argv lists of the flags, with no shell. perfrig
// expands $NAME and ${NAME} in each argument from the workload variables (see
// Env.vars). The last stdout line of the client must be the JSON line that
// parseJSONLine reads.
func execWorkload(cfg config) (Workload, error) {
	if cfg.Name == "" || len(cfg.ServerArgv) == 0 || len(cfg.ClientArgv) == 0 {
		return Workload{}, errors.New("the exec workload needs -name, -server-argv and -client-argv")
	}
	for _, argv := range [][]string{cfg.ServerArgv, cfg.ClientArgv, cfg.SidecarArgv} {
		if err := checkVars(argv); err != nil {
			return Workload{}, err
		}
	}
	ready, err := parseSocket(cfg.Ready)
	if err != nil {
		return Workload{}, err
	}
	w := Workload{
		Name:   cfg.Name,
		Server: func(e Env) []string { return e.expand(cfg.ServerArgv) },
		Client: func(e Env) []string { return e.expand(cfg.ClientArgv) },
		Ready:  ready,
		Parse:  func(client, _ []byte) (Throughput, error) { return parseJSONLine(client) },
	}
	if len(cfg.SidecarArgv) > 0 {
		w.Sidecar = func(e Env) []string { return e.expand(cfg.SidecarArgv) }
	}
	return w, nil
}

// expand replaces $NAME and ${NAME} in each argument with the workload variable.
func (e Env) expand(argv []string) []string {
	vars := map[string]string{}
	for _, kv := range e.vars() {
		k, v, _ := strings.Cut(kv, "=")
		vars[k] = v
	}
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = os.Expand(a, func(k string) string { return vars[k] })
	}
	return out
}

// checkVars returns an error when an argument names a variable that Env.vars does not set.
func checkVars(argv []string) error {
	known := map[string]bool{}
	for _, kv := range (Env{}).vars() {
		k, _, _ := strings.Cut(kv, "=")
		known[k] = true
	}
	for _, a := range argv {
		var bad string
		os.Expand(a, func(k string) string {
			if !known[k] && bad == "" {
				bad = k
			}
			return ""
		})
		if bad != "" {
			return fmt.Errorf("argument %q names $%s, which is not a workload variable", a, bad)
		}
	}
	return nil
}

// argvFlag is a flag with a JSON list of strings, for example '["iperf3","-s"]'.
type argvFlag []string

func (f *argvFlag) String() string {
	if f == nil || *f == nil {
		return ""
	}
	b, _ := json.Marshal([]string(*f))
	return string(b)
}

func (f *argvFlag) Set(s string) error {
	var argv []string
	if err := json.Unmarshal([]byte(s), &argv); err != nil {
		return fmt.Errorf("want a JSON list of strings, for example [\"iperf3\",\"-s\"]: %w", err)
	}
	*f = argv
	return nil
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
