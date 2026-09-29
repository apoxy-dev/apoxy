package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIperf3(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		require.NoError(t, err)
		return b
	}
	cases := []struct {
		name    string
		in      []byte
		want    Throughput
		wantErr string
	}{
		{
			name: "tcp",
			in:   read("iperf3-tcp.json"),
			want: Throughput{Seconds: 3.027189, BitsPerSecond: 1914822010.7829409},
		},
		{
			name: "udp",
			in:   read("iperf3-udp.json"),
			want: Throughput{
				Seconds:          3.023467,
				BitsPerSecond:    998426413.12109566,
				LostPercent:      0.29452469342832138,
				JitterMS:         0.0049890301178969918,
				PacketsPerSecond: float64(261357-764) / 3.023467,
			},
		},
		{
			name: "tcp retransmits",
			in: []byte(`{"end":{"sum_sent":{"seconds":30,"bits_per_second":3e9,"retransmits":42},
				"sum_received":{"seconds":30.02,"bits_per_second":2.9e9}}}`),
			want: Throughput{Seconds: 30.02, BitsPerSecond: 2.9e9, Retransmits: 42},
		},
		{name: "connect error", in: read("iperf3-error.json"), wantErr: "iperf3: unable to connect to server"},
		{name: "no receiver sum", in: []byte(`{"end":{"sum_sent":{"seconds":1}}}`), wantErr: "no end.sum_received"},
		{name: "not JSON", in: []byte("iperf3: error"), wantErr: "parse iperf3 JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseIperf3(tc.in)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.InDelta(t, tc.want.PacketsPerSecond, got.PacketsPerSecond, 1e-6)
			got.PacketsPerSecond = tc.want.PacketsPerSecond
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseIperf3Version(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		atLeast bool
		wantErr bool
	}{
		{name: "3.19.1", in: "iperf 3.19.1 (cJSON 1.7.15)\nLinux x 6.8.0 aarch64\n", want: "3.19.1", atLeast: true},
		{name: "3.16", in: "iperf 3.16 (cJSON 1.7.15)", want: "3.16", atLeast: true},
		{name: "3.16 plus", in: "iperf 3.16+ (cJSON 1.7.15)", want: "3.16", atLeast: true},
		{name: "3.12", in: "iperf 3.12 (cJSON 1.7.15)", want: "3.12", atLeast: false},
		{name: "4.0", in: "iperf 4.0", want: "4.0", atLeast: true},
		{name: "rc suffix", in: "iperf 3.17rc1", want: "3.17rc1", atLeast: true},
		{name: "iperf2", in: "iperf version 2.1.5 (15 Dec 2021) pthreads", want: "version", atLeast: false},
		{name: "empty", in: "", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseIperf3Version(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.atLeast, versionAtLeast(got, 3, 16))
		})
	}
}

func TestIperf3ClientArgs(t *testing.T) {
	env := Env{ServerIP: serverIP, Duration: 30 * time.Second, Omit: 2 * time.Second, Streams: 4}
	cases := []struct {
		name string
		udp  bool
		env  func(Env) Env
		want []string
	}{
		{
			name: "tcp",
			want: []string{"iperf3", "-c", serverIP, "-p", "5201", "-J", "--connect-timeout", "5000", "-t", "30", "-O", "2", "-P", "4"},
		},
		{
			name: "udp with bitrate and window",
			udp:  true,
			env:  func(e Env) Env { e.Bitrate, e.Window = "2G", "8M"; return e },
			want: []string{"iperf3", "-c", serverIP, "-p", "5201", "-J", "--connect-timeout", "5000", "-t", "30", "-O", "2", "-P", "4", "-u", "-b", "2G", "-w", "8M"},
		},
		{
			name: "part seconds round up",
			env:  func(e Env) Env { e.Duration, e.Omit = 1500*time.Millisecond, 0; return e },
			want: []string{"iperf3", "-c", serverIP, "-p", "5201", "-J", "--connect-timeout", "5000", "-t", "2", "-O", "0", "-P", "4"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := env
			if tc.env != nil {
				e = tc.env(e)
			}
			assert.Equal(t, tc.want, iperf3Workload("x", tc.udp).Client(e))
		})
	}
}
