package main

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetemArgs(t *testing.T) {
	base := []string{"tc", "-n", "ns", "qdisc", "replace", "dev", "eth0", "root", "netem", "limit", "1000"}
	cases := []struct {
		name string
		cfg  config
		want []string
	}{
		{
			name: "delay",
			cfg:  config{QueueLimit: 1000, Delay: 10 * time.Millisecond},
			want: append(base, "delay", "10ms"),
		},
		{
			name: "all",
			cfg: config{QueueLimit: 1000, Delay: 10 * time.Millisecond, Jitter: 500 * time.Microsecond,
				Loss: 0.1, Rate: "10gbit"},
			want: append(base, "delay", "10ms", "0.5ms", "loss", "0.1%", "rate", "10gbit"),
		},
		{
			name: "jitter only",
			cfg:  config{QueueLimit: 1000, Jitter: time.Millisecond},
			want: append(base, "delay", "0ms", "1ms"),
		},
		{
			name: "no impairment",
			cfg:  config{QueueLimit: 1000},
			want: base,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, netemArgs("ns", "eth0", tc.cfg))
		})
	}
}

func TestCPUMask(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{n: 1, want: "1"},
		{n: 4, want: "f"},
		{n: 10, want: "3ff"},
		{n: 32, want: "ffffffff"},
		{n: 33, want: "1,ffffffff"},
		{n: 64, want: "ffffffff,ffffffff"},
	}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.n), func(t *testing.T) {
			assert.Equal(t, tc.want, cpuMask(tc.n))
		})
	}
}

func TestCPUListMask(t *testing.T) {
	cases := []struct {
		list    string
		want    string
		wantErr bool
	}{
		{list: "0", want: "1"},
		{list: "0-3", want: "f"},
		{list: "0-15", want: "ffff"},
		{list: "16-31", want: "ffff0000"},
		{list: "0-15,20", want: "10ffff"},
		{list: "32,0", want: "1,1"},
		{list: "", wantErr: true},
		{list: "3-1", wantErr: true},
		{list: "a", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.list, func(t *testing.T) {
			got, err := cpuListMask(tc.list)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNetemMissing(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{out: "Error: Specified qdisc kind is unknown.", want: true},
		{out: "Error: Specified qdisc not found.", want: true},
		{out: "RTNETLINK answers: No such file or directory", want: true},
		{out: "Error: argument \"x\" is wrong: invalid delay", want: false},
		{out: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.out, func(t *testing.T) {
			assert.Equal(t, tc.want, netemMissing(tc.out))
		})
	}
}

func TestParsePing(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    RTT
		wantErr bool
	}{
		{
			name: "iputils",
			in: `PING 10.200.0.2 (10.200.0.2) 56(84) bytes of data.

--- 10.200.0.2 ping statistics ---
20 packets transmitted, 20 received, 0% packet loss, time 1905ms
rtt min/avg/max/mdev = 20.142/20.391/21.004/0.214 ms
`,
			want: RTT{Min: 20.142, Avg: 20.391, Max: 21.004, Mdev: 0.214},
		},
		{
			name: "iputils with loss",
			in: `--- 10.200.0.2 ping statistics ---
20 packets transmitted, 19 received, 5% packet loss, time 1905ms
rtt min/avg/max/mdev = 20.1/20.2/20.3/0.1 ms, pipe 2
`,
			want: RTT{Min: 20.1, Avg: 20.2, Max: 20.3, Mdev: 0.1, LossPercent: 5},
		},
		{
			name: "busybox",
			in: `PING 10.9.0.2 (10.9.0.2): 56 data bytes

--- 10.9.0.2 ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 21.760/23.701/25.901 ms
`,
			want: RTT{Min: 21.76, Avg: 23.701, Max: 25.901},
		},
		{
			name: "no replies",
			in: `--- 10.200.0.2 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2030ms
`,
			wantErr: true,
		},
		{name: "bad numbers", in: "rtt min/avg/max/mdev = a/b/c/d ms", wantErr: true},
		{name: "empty", in: "", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePing(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
