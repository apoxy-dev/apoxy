package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProcStat(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    cpuTimes
		wantErr bool
	}{
		{
			name: "full line",
			in:   "cpu  19648 100 21103 623682 74618 50 15809 0 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n",
			want: cpuTimes{User: 197.48, System: 211.03, IRQ: 158.59},
		},
		{
			name: "old kernel with 7 values",
			in:   "cpu 100 0 200 300 0 0 50\n",
			want: cpuTimes{User: 1, System: 2, IRQ: 0.5},
		},
		{name: "short line", in: "cpu 1 2 3\n", wantErr: true},
		{name: "bad number", in: "cpu a 0 0 0 0 0 0 0\n", wantErr: true},
		{name: "no cpu line", in: "intr 1 2 3\n", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseProcStat(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.InDelta(t, tc.want.User, got.User, 1e-9)
			assert.InDelta(t, tc.want.System, got.System, 1e-9)
			assert.InDelta(t, tc.want.IRQ, got.IRQ, 1e-9)
		})
	}
}

func TestParseSocket(t *testing.T) {
	cases := []struct {
		in      string
		want    Socket
		wantErr bool
	}{
		{in: "tcp:5201", want: Socket{Proto: "tcp", Port: 5201}},
		{in: "udp:4433", want: Socket{Proto: "udp", Port: 4433}},
		{in: "none", want: Socket{}},
		{in: "", want: Socket{}},
		{in: "sctp:1", wantErr: true},
		{in: "tcp", wantErr: true},
		{in: "tcp:0", wantErr: true},
		{in: "udp:70000", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseSocket(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTableHasSocket(t *testing.T) {
	const tcp = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1451 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0200C80A:D2F0 0200C80A:1451 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 20 4 30 10 -1
`
	const tcp6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1151 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
`
	const udp = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:115C 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4 2 0000000000000000 0
`
	cases := []struct {
		name  string
		table string
		s     Socket
		want  bool
	}{
		{name: "tcp listen", table: tcp, s: Socket{Proto: "tcp", Port: 5201}, want: true},
		{name: "tcp other port", table: tcp, s: Socket{Proto: "tcp", Port: 5202}, want: false},
		{name: "tcp established only", table: tcp, s: Socket{Proto: "tcp", Port: 53999}, want: false},
		{name: "tcp6 listen", table: tcp6, s: Socket{Proto: "tcp", Port: 4433}, want: true},
		{name: "udp bound", table: udp, s: Socket{Proto: "udp", Port: 4444}, want: true},
		{name: "header only", table: "  sl  local_address\n", s: Socket{Proto: "tcp", Port: 5201}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tableHasSocket(tc.table, tc.s))
		})
	}
}
