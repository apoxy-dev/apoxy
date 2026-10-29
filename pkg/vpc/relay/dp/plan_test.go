// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// smt returns the siblings of cpus on a host where CPU c and CPU c+half are one physical core.
// With half 0, each CPU is its own core.
func smt(half int, cpus ...int) map[int][]int {
	m := map[int][]int{}
	for _, c := range cpus {
		switch {
		case half == 0:
			m[c] = []int{c}
		case c < half:
			m[c] = []int{c, c + half}
		default:
			m[c] = []int{c - half, c}
		}
	}
	return m
}

func span(lo, hi int) []int {
	var out []int
	for c := lo; c <= hi; c++ {
		out = append(out, c)
	}
	return out
}

func TestMakePlan(t *testing.T) {
	cases := []struct {
		name     string
		topo     cpuTopology
		nRx, nTx int
		want     cpuPlan
		err      bool
	}{
		{
			name: "a queue keeps its interrupt CPU, a second queue on that core moves",
			topo: cpuTopology{cpus: span(0, 7), siblings: smt(4, span(0, 7)...),
				irqs: map[int][]int{0: {100}, 1: {101}}, irqCPUs: map[int][]int{100: {0}, 101: {4}}},
			nRx: 2, nTx: 2,
			want: cpuPlan{irq: []int{0, 1}, rx: []int{4, 5}, wk: []int{2, 3}, kick: []int{6, 7}},
		},
		{
			name: "no SMT",
			topo: cpuTopology{cpus: span(0, 3), siblings: smt(0, span(0, 3)...),
				irqs: map[int][]int{0: {100}, 1: {101}}, irqCPUs: map[int][]int{100: {0}, 101: {1}}},
			nRx: 2, nTx: 4,
			want: cpuPlan{irq: []int{0, 1}, rx: []int{-1, -1}, wk: []int{2, 3}, kick: []int{-1, -1, -1, -1}},
		},
		{
			name: "at most one worker for each TX queue",
			topo: cpuTopology{cpus: span(0, 15), siblings: smt(8, span(0, 15)...),
				irqs: map[int][]int{0: {100}, 1: {101}}, irqCPUs: map[int][]int{100: {0}, 101: {1}}},
			nRx: 2, nTx: 2,
			want: cpuPlan{irq: []int{0, 1}, rx: []int{8, 9}, wk: []int{2, 3}, kick: []int{10, 11}},
		},
		{
			name: "no free core for a worker: one worker with no CPU",
			topo: cpuTopology{cpus: []int{0, 1, 4, 5}, siblings: smt(4, 0, 1, 4, 5),
				irqs: map[int][]int{0: {100}, 1: {101}}, irqCPUs: map[int][]int{100: {0}, 101: {1}}},
			nRx: 2, nTx: 2,
			want: cpuPlan{irq: []int{0, 1}, rx: []int{4, 5}, wk: []int{-1}, kick: []int{-1, -1}},
		},
		{
			name: "an interrupt outside the CPU set moves",
			topo: cpuTopology{cpus: []int{2, 3, 6, 7}, siblings: smt(4, 2, 3, 6, 7),
				irqs: map[int][]int{0: {100, 102}, 1: {101}}, irqCPUs: map[int][]int{100: {0}, 101: {7}, 102: {2}}},
			nRx: 2, nTx: 1,
			want: cpuPlan{irq: []int{2, 7}, rx: []int{6, 3}, wk: []int{-1}, kick: []int{-1}},
		},
		{
			name: "an interrupt on more than one CPU moves",
			topo: cpuTopology{cpus: span(0, 7), siblings: smt(4, span(0, 7)...),
				irqs: map[int][]int{0: {100}}, irqCPUs: map[int][]int{100: {0, 1, 2, 3}}},
			nRx: 1, nTx: 2,
			want: cpuPlan{irq: []int{0}, rx: []int{4}, wk: []int{1, 2}, kick: []int{5, 6}},
		},
		{
			name: "a core with one CPU in the set",
			topo: cpuTopology{cpus: []int{1, 4, 5}, siblings: smt(4, 1, 4, 5),
				irqs: map[int][]int{0: {100}}, irqCPUs: map[int][]int{100: {5}}},
			nRx: 1, nTx: 1,
			want: cpuPlan{irq: []int{5}, rx: []int{1}, wk: []int{4}, kick: []int{-1}},
		},
		{
			name: "more queues than physical cores: the queues share the core",
			topo: cpuTopology{cpus: []int{0, 4}, siblings: smt(4, 0, 4),
				irqs: map[int][]int{0: {100}, 1: {101}}, irqCPUs: map[int][]int{100: {0}, 101: {4}}},
			nRx: 2, nTx: 2,
			want: cpuPlan{irq: []int{0, 0}, rx: []int{4, 4}, wk: []int{-1}, kick: []int{-1, -1}},
		},
		{
			name: "c6in.large: one core with two SMT siblings and two queues",
			topo: cpuTopology{cpus: []int{0, 1}, siblings: smt(1, 0, 1),
				irqs: map[int][]int{0: {100}, 1: {101}}, irqCPUs: map[int][]int{100: {0}, 101: {1}}},
			nRx: 2, nTx: 2,
			want: cpuPlan{irq: []int{0, 0}, rx: []int{1, 1}, wk: []int{-1}, kick: []int{-1, -1}},
		},
		{
			name: "two cores and three queues",
			topo: cpuTopology{cpus: span(0, 3), siblings: smt(2, span(0, 3)...),
				irqs: map[int][]int{0: {100}, 1: {101}, 2: {102}}, irqCPUs: map[int][]int{100: {0}, 101: {1}, 102: {2}}},
			nRx: 3, nTx: 3,
			want: cpuPlan{irq: []int{0, 1, 0}, rx: []int{2, 3, 2}, wk: []int{-1}, kick: []int{-1, -1, -1}},
		},
		{
			name: "two cores and five queues: the queues share the cores in turn",
			topo: cpuTopology{cpus: span(0, 3), siblings: smt(2, span(0, 3)...),
				irqs:    map[int][]int{0: {100}, 1: {101}, 2: {102}, 3: {103}, 4: {104}},
				irqCPUs: map[int][]int{100: {3}, 101: {2}, 102: {0}, 103: {1}, 104: {0}}},
			nRx: 5, nTx: 2,
			want: cpuPlan{irq: []int{3, 2, 0, 1, 0}, rx: []int{1, 0, 2, 3, 2}, wk: []int{-1}, kick: []int{-1, -1}},
		},
		{
			name: "no CPU",
			topo: cpuTopology{irqs: map[int][]int{0: {100}}, irqCPUs: map[int][]int{100: {0}}},
			nRx:  1, nTx: 1, err: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := makePlan(tc.topo, tc.nRx, tc.nTx)
			if tc.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, p)
		})
	}
}

// host is a sysfs and a procfs in a temporary directory: the CPUs, the link fake0 with the
// interrupt of each queue, and the affinity of each interrupt.
type host struct {
	sys, proc string
}

func newHost(t *testing.T, siblings map[int][]int) *host {
	t.Helper()
	h := &host{sys: filepath.Join(t.TempDir(), "sys"), proc: filepath.Join(t.TempDir(), "proc")}
	for c, s := range siblings {
		var l []string
		for _, x := range s {
			l = append(l, strconv.Itoa(x))
		}
		h.write(t, filepath.Join(h.sys, "devices/system/cpu", "cpu"+strconv.Itoa(c), "topology/thread_siblings_list"), strings.Join(l, ",")+"\n")
	}
	require.NoError(t, os.MkdirAll(filepath.Join(h.sys, "class/net/fake0/device/msi_irqs"), 0o755))
	return h
}

func (h *host) write(t *testing.T, path, s string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(s), 0o644))
}

// irq adds the interrupt irq of the device of fake0 with the handler name and the affinity.
func (h *host) irq(t *testing.T, irq int, name, affinity string) {
	t.Helper()
	n := strconv.Itoa(irq)
	h.write(t, filepath.Join(h.sys, "class/net/fake0/device/msi_irqs", n), "msi\n")
	require.NoError(t, os.MkdirAll(filepath.Join(h.proc, "irq", n, name), 0o755))
	h.write(t, filepath.Join(h.proc, "irq", n, "smp_affinity_list"), affinity+"\n")
}

// threads returns the CPU of each worker and of each kicker of d.
func threads(d *Device) (wk, kick []int) {
	for _, w := range d.workers {
		wk = append(wk, w.cpu)
	}
	for _, t := range d.tx {
		kick = append(kick, t.cpu)
	}
	return wk, kick
}

// TestPlaceCPUs places the queue interrupts and the threads of a device with two RX and two TX
// queues on a host in a temporary directory. A failed setup puts back the affinities that it
// changed, and so does the stop of Run.
func TestPlaceCPUs(t *testing.T) {
	cases := []struct {
		name     string
		noDevice bool           // fake0 has no device, as veth.
		cpus     []int          // The CPU set of the relay.
		irqs     map[int]string // The affinity of interrupt 100+q of queue q.
		badIRQ   bool           // A move of the interrupt of queue 1 does not apply.
		err      bool           // placeCPUs fails.
		after    map[int][]int  // The CPUs of each interrupt after placeCPUs.
		rx       []int          // The CPUs of the RX goroutines.
		wk, kick []int          // The CPUs of the workers and the kickers.
		steer    map[uint32]int // The steering map after placeCPUs.
	}{
		{
			name: "two queues, two workers", cpus: span(0, 7), irqs: map[int]string{0: "0", 1: "4"},
			after: map[int][]int{100: {0}, 101: {1}}, rx: []int{4, 5}, wk: []int{2, 3}, kick: []int{6, 7},
			steer: map[uint32]int{engSPIA1: 0, engSPIA3: 1},
		},
		{
			name: "one free core: one worker", cpus: []int{0, 1, 2, 4, 5, 6}, irqs: map[int]string{0: "0", 1: "1"},
			after: map[int][]int{100: {0}, 101: {1}}, rx: []int{4, 5}, wk: []int{2}, kick: []int{6, -1},
			steer: map[uint32]int{engSPIA1: 0, engSPIA3: 0},
		},
		{
			name: "veth: no plan", noDevice: true, cpus: span(0, 7),
			rx: nil, wk: []int{-1, -1}, kick: []int{-1, -1}, steer: map[uint32]int{engSPIA1: 0, engSPIA3: 1},
		},
		{
			name: "more queues than cores: the queues share the core", cpus: []int{0, 4}, irqs: map[int]string{0: "0", 1: "4"},
			after: map[int][]int{100: {0}, 101: {0}}, rx: []int{4, 4}, wk: []int{-1}, kick: []int{-1, -1},
			steer: map[uint32]int{engSPIA1: 0, engSPIA3: 0},
		},
		{
			name: "a failed setup puts the affinities back", cpus: span(0, 7), irqs: map[int]string{0: "0-7"}, badIRQ: true, err: true,
			after: map[int][]int{100: span(0, 7)}, wk: []int{-1, -1}, kick: []int{-1, -1},
			steer: map[uint32]int{engSPIA1: 0, engSPIA3: 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHost(t, smt(4, tc.cpus...))
			for q, a := range tc.irqs {
				h.irq(t, 100+q, "fake0-Tx-Rx-"+strconv.Itoa(q), a)
			}
			if tc.badIRQ {
				// Writes to the affinity of interrupt 101 go nowhere, so the move fails its check.
				h.irq(t, 101, "fake0-Tx-Rx-1", "1")
				path := filepath.Join(h.proc, "irq/101/smp_affinity_list")
				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Symlink(os.DevNull, path))
			}
			if tc.noDevice {
				require.NoError(t, os.RemoveAll(filepath.Join(h.sys, "class/net/fake0/device")))
			}
			e := newEngine(t, 2, 2, 64)
			err := e.placeCPUs(h.sys, h.proc, tc.cpus)
			require.Equal(t, tc.err, err != nil, "error: %v", err)
			for irq, cpus := range tc.after {
				assert.Equal(t, cpus, irqCPUs(h.proc, irq), "interrupt %d", irq)
			}
			assert.Equal(t, tc.rx, e.plan.rx, "RX goroutines")
			wk, kick := threads(e.Device)
			assert.Equal(t, tc.wk, wk, "workers")
			assert.Equal(t, tc.kick, kick, "kickers")
			assert.Equal(t, steerMap(tc.steer), *e.p.steering.Load(), "steering map")
			if tc.err || tc.noDevice {
				assert.Nil(t, e.restore)
				return
			}
			// The stop of Run puts the affinities back. The CPUs of the topology need not be on the
			// test host, so the threads run unpinned.
			e.plan.rx = nil
			for _, w := range e.workers {
				w.cpu = -1
			}
			for _, q := range e.tx {
				q.cpu = -1
			}
			e.start(t)
			require.NoError(t, e.stop())
			for q, a := range tc.irqs {
				want, err := ParseCPUList(a)
				require.NoError(t, err)
				assert.Equal(t, want, irqCPUs(h.proc, 100+q), "interrupt %d after Run", 100+q)
			}
		})
	}
}

// TestLinkQueueIRQs reads the interrupts of each queue from the handler names of ENA and gVNIC.
func TestLinkQueueIRQs(t *testing.T) {
	cases := []struct {
		name     string
		names    map[int]string // The handler name of each interrupt.
		nRx, nTx int
		want     map[int][]int
		err      bool
	}{
		{name: "ENA", names: map[int]string{30: "fake0-Tx-Rx-1", 29: "fake0-Tx-Rx-0", 28: "ena-mgmnt@pci:0000:00:06.0"},
			nRx: 2, nTx: 2, want: map[int][]int{0: {29}, 1: {30}}},
		{name: "gVNIC", names: map[int]string{
			40: "gve-ntfy-blk0@pci:0000:00:04.0", 41: "gve-ntfy-blk1@pci:0000:00:04.0",
			42: "gve-ntfy-blk2@pci:0000:00:04.0", 43: "gve-ntfy-blk3@pci:0000:00:04.0",
			44: "gve-ntfy-blk4@pci:0000:00:04.0", 45: "gve-ntfy-blk5@pci:0000:00:04.0",
			46: "gve-ntfy-blk6@pci:0000:00:04.0", 47: "gve-ntfy-blk7@pci:0000:00:04.0",
			48: "gve-mgmnt@pci:0000:00:04.0"},
			nRx: 2, nTx: 2, want: map[int][]int{0: {44, 40, 42}, 1: {45, 41, 43}}},
		{name: "a queue with no interrupt", names: map[int]string{29: "fake0-Tx-Rx-0"}, nRx: 2, nTx: 2, err: true},
		{name: "gVNIC with an odd number of blocks", names: map[int]string{
			40: "gve-ntfy-blk0@pci:0000:00:04.0", 41: "gve-ntfy-blk1@pci:0000:00:04.0", 42: "gve-ntfy-blk2@pci:0000:00:04.0"},
			nRx: 1, nTx: 1, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHost(t, nil)
			for irq, name := range tc.names {
				h.irq(t, irq, name, "0")
			}
			got, err := linkQueueIRQs(h.sys, h.proc, "fake0", tc.nRx, tc.nTx)
			if tc.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseCPUList(t *testing.T) {
	cases := []struct {
		in   string
		want []int
		err  bool
	}{
		{in: "0", want: []int{0}},
		{in: "0-3,8", want: []int{0, 1, 2, 3, 8}},
		{in: "3,1,2-3", want: []int{1, 2, 3}},
		{in: " 0,16\n", want: []int{0, 16}},
		{in: "2-15,18-31", want: append(span(2, 15), span(18, 31)...)},
		{in: "", err: true},
		{in: "a", err: true},
		{in: "3-1", err: true},
		{in: "-1", err: true},
		{in: "1,,2", err: true},
		{in: strconv.Itoa(maxCPUs - 1), want: []int{maxCPUs - 1}},
		{in: strconv.Itoa(maxCPUs), err: true},
		{in: "0-" + strconv.Itoa(maxCPUs), err: true},
		{in: "9223372036854775807", err: true},
		{in: "9223372036854775807-9223372036854775807", err: true},
		{in: "0-9223372036854775807", err: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseCPUList(tc.in)
			if tc.err {
				assert.ErrorIs(t, err, ErrCPUList)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
