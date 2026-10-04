package main

import (
	"flag"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseJSONLine(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    Throughput
		wantErr string
	}{
		{
			name: "last line",
			in:   "connected\nsending\n{\"seconds\": 30, \"bits_per_second\": 2.1e9, \"packets_per_second\": 180000}\n\n",
			want: Throughput{Seconds: 30, BitsPerSecond: 2.1e9, PacketsPerSecond: 180000},
		},
		{
			name: "extra fields",
			in:   `{"bits_per_second": 1e9, "gso": true}`,
			want: Throughput{BitsPerSecond: 1e9},
		},
		{
			name: "packets only",
			in:   `{"seconds": 10, "packets_per_second": 500000}`,
			want: Throughput{Seconds: 10, PacketsPerSecond: 500000},
		},
		{name: "empty", in: "\n\n", wantErr: "no result line"},
		{name: "not JSON", in: "done: 2 Gbps", wantErr: "parse client result line"},
		{name: "no rate", in: `{"seconds": 30}`, wantErr: "no bits_per_second"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseJSONLine([]byte(tc.in))
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNewWorkload(t *testing.T) {
	execCfg := config{Workload: "exec", Name: "quic", ServerArgv: []string{"srv"}, ClientArgv: []string{"cli"}, Ready: "udp:4433"}
	cases := []struct {
		name     string
		cfg      config
		wantName string
		wantErr  string
	}{
		{name: "iperf3 tcp", cfg: config{Workload: "iperf3-tcp"}, wantName: "iperf3-tcp"},
		{name: "iperf3 udp", cfg: config{Workload: "iperf3-udp"}, wantName: "iperf3-udp"},
		{name: "exec", cfg: execCfg, wantName: "quic"},
		{name: "unknown", cfg: config{Workload: "netperf"}, wantErr: "unknown workload"},
		{
			name:    "exec without commands",
			cfg:     config{Workload: "exec", Name: "quic"},
			wantErr: "needs -name, -server-argv and -client-argv",
		},
		{
			name:    "exec unknown variable",
			cfg:     func() config { c := execCfg; c.SidecarArgv = []string{"relay", "-listen", "$PEER_IP:4443"}; return c }(),
			wantErr: "names $PEER_IP",
		},
		{
			name:    "exec bad socket",
			cfg:     func() config { c := execCfg; c.Ready = "udp"; return c }(),
			wantErr: "bad socket",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := newWorkload(tc.cfg)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantName, w.Name)
			assert.NotNil(t, w.Server)
			assert.NotNil(t, w.Client)
			assert.NotNil(t, w.Parse)
		})
	}
}

func TestExecWorkloadArgv(t *testing.T) {
	env := Env{ServerIP: serverIP, ClientIP: clientIP, RelayIP: relayIP, Duration: 30 * time.Second, Omit: 5 * time.Second, Streams: 4, Dir: "/work"}
	cases := []struct {
		name string
		argv []string
		want []string
	}{
		{name: "no variables", argv: []string{"iperf3", "-s"}, want: []string{"iperf3", "-s"}},
		{
			name: "dollar and braces",
			argv: []string{"vpcbench", "client", "-server", "$SERVER_IP:4433", "-omit", "${OMIT_S}s", "-duration", "${DURATION_S}s", "-streams", "$STREAMS"},
			want: []string{"vpcbench", "client", "-server", "10.200.0.2:4433", "-omit", "5s", "-duration", "30s", "-streams", "4"},
		},
		{name: "relay", argv: []string{"vpcbench", "relay", "-listen", "$RELAY_IP:4443"}, want: []string{"vpcbench", "relay", "-listen", "10.200.0.3:4443"}},
		{name: "no word split", argv: []string{"a b", "$WORK_DIR/x y"}, want: []string{"a b", "/work/x y"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := newWorkload(config{Workload: "exec", Name: "x", ServerArgv: tc.argv, ClientArgv: tc.argv, SidecarArgv: tc.argv})
			require.NoError(t, err)
			assert.Equal(t, tc.want, w.Server(env))
			assert.Equal(t, tc.want, w.Client(env))
			require.NotNil(t, w.Sidecar)
			assert.Equal(t, tc.want, w.Sidecar(env))
		})
	}
}

func TestArgvFlag(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{name: "list", in: `["tunbench","relay","-transport","quic"]`, want: []string{"tunbench", "relay", "-transport", "quic"}},
		{name: "spaces in an argument", in: `["sh x", "a b"]`, want: []string{"sh x", "a b"}},
		{name: "shell string", in: "tunbench relay", wantErr: true},
		{name: "not strings", in: `[1, 2]`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			fs.Var((*argvFlag)(&got), "argv", "")
			err := fs.Parse([]string{"-argv", tc.in})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
