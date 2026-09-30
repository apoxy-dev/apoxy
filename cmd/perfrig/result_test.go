package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Baseline entries use the key. A change here makes all entries stop matching.
func TestResultKey(t *testing.T) {
	cases := []struct {
		name string
		cfg  config
		want string
	}{
		{
			name: "defaults",
			cfg:  config{Duration: 30 * time.Second, Delay: 10 * time.Millisecond, MTU: 1500, Streams: 4},
			want: "x86_64 w streams=4 duration=30s omit=0s delay=10ms jitter=0ms loss=0% rate=none queue=0 mtu=1500 bitrate=none window=none",
		},
		{
			name: "all set",
			cfg: config{Duration: 60 * time.Second, Omit: 5 * time.Second, Delay: 10 * time.Millisecond,
				Jitter: 500 * time.Microsecond, Loss: 0.1, Rate: "10gbit", QueueLimit: 100000, MTU: 1280, Streams: 1,
				Bitrate: "2G", Window: "8M"},
			want: "x86_64 w streams=1 duration=60s omit=5s delay=10ms jitter=0.5ms loss=0.1% rate=10gbit queue=100000 mtu=1280 bitrate=2G window=8M",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resultKey("x86_64", "w", tc.cfg.settings()))
		})
	}
}

func TestNewProcCPU(t *testing.T) {
	cases := []struct {
		name                  string
		user, sys, secs, gbps float64
		want                  ProcCPU
	}{
		{
			name: "normal", user: 3, sys: 9, secs: 30, gbps: 2,
			want: ProcCPU{UserS: 3, SystemS: 9, TotalS: 12, Cores: 0.4, CoresPerGbps: 0.2},
		},
		{name: "no traffic", user: 1, sys: 1, secs: 10, want: ProcCPU{UserS: 1, SystemS: 1, TotalS: 2, Cores: 0.2}},
		{name: "no time", user: 1, sys: 1, want: ProcCPU{UserS: 1, SystemS: 1, TotalS: 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, newProcCPU(tc.user, tc.sys, tc.secs, tc.gbps))
		})
	}
}
