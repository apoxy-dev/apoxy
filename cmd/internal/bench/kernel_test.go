// SPDX-License-Identifier: AGPL-3.0-only

package bench

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteIRQTable(t *testing.T) {
	kinds := make([][]irqTime, hardIRQ+1)
	for k := range kinds {
		kinds[k] = make([]irqTime, 2)
	}
	kinds[hardIRQ][0] = irqTime{NS: 5, Runs: 1}
	kinds[3][1] = irqTime{NS: 700, Runs: 9} // NET_RX on CPU 1.
	cases := []struct {
		name  string
		kinds [][]irqTime
		want  []string
	}{
		{name: "no timer", want: nil},
		{name: "a kind is missing", kinds: kinds[:hardIRQ], want: nil},
		{
			name: "two CPUs", kinds: kinds,
			want: []string{
				"0 5 1" + strings.Repeat(" 0 0", 10),
				"1 0 0" + strings.Repeat(" 0 0", 3) + " 700 9" + strings.Repeat(" 0 0", 6),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeIRQTable(&b, tc.kinds)
			lines := strings.Split(strings.TrimSpace(b.String()), "\n")
			assert.Equal(t, "# cpu, then the nanoseconds and the runs of: HARDIRQ HI TIMER NET_TX NET_RX BLOCK IRQ_POLL TASKLET SCHED HRTIMER RCU", lines[0])
			if tc.want == nil {
				assert.Len(t, lines, 1)
				return
			}
			assert.Equal(t, tc.want, lines[1:])
		})
	}
}

func TestSymbols(t *testing.T) {
	const kallsyms = `ffffffff81000300 T net_rx_action
ffffffff81000100 T handle_softirqs
ffffffff81000200 t napi_poll.constprop.0
ffffffff81000280 D not_text
ffffffffc0001000 t ena_io_poll	[ena]
0000000000000000 T hidden
bad line
`
	syms := readSymbols(strings.NewReader(kallsyms))
	names := []struct {
		name string
		addr uint64
		want string
	}{
		{name: "start of a symbol", addr: 0xffffffff81000100, want: "handle_softirqs"},
		{name: "in a symbol", addr: 0xffffffff810002ff, want: "napi_poll.constprop.0"},
		{name: "a data symbol is not a frame", addr: 0xffffffff81000290, want: "napi_poll.constprop.0"},
		{name: "module", addr: 0xffffffffc0001010, want: "ena_io_poll"},
		{name: "before the first symbol", addr: 0x10, want: "0x10"},
	}
	for _, tc := range names {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, syms.name(tc.addr))
		})
	}
	stacks := []struct {
		name  string
		syms  symbols
		addrs []uint64
		want  string
	}{
		{name: "root first", syms: syms, addrs: []uint64{0xffffffffc0001010, 0xffffffff81000210, 0xffffffff81000301, 0xffffffff81000110, 0, 0}, want: "handle_softirqs;net_rx_action;napi_poll.constprop.0;ena_io_poll"},
		{name: "full table", syms: syms, addrs: []uint64{0xffffffff81000301, 0xffffffff81000110}, want: "handle_softirqs;net_rx_action"},
		{name: "empty", syms: syms, addrs: []uint64{0, 0}, want: ""},
		{name: "no symbols", addrs: []uint64{0x20, 0x10}, want: "0x10;0x20"},
	}
	for _, tc := range stacks {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.syms.fold(tc.addrs))
		})
	}
}

func TestStackName(t *testing.T) {
	cases := []struct {
		id   uint32
		want string
	}{
		{id: stackUser, want: "[user]"},
		{id: stackLost, want: "[lost]"},
		{id: 0xffffffea, want: "[error -22]"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, stackName(tc.id))
	}
}
