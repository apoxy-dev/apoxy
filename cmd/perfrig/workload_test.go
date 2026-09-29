package main

import (
	"testing"

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
	execCfg := config{Workload: "exec", Name: "quic", ServerCmd: "srv", ClientCmd: "cli", Ready: "udp:4433"}
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
			wantErr: "needs -name, -server-cmd and -client-cmd",
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
