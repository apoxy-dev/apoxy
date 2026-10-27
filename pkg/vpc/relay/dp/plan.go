// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The CPU plan of the device (plan D-i). Each queue gets its own physical core for its interrupts:
// a queue keeps the CPU of its interrupt when that core has no other queue, else its interrupts
// move to the first free core. The RX goroutine of a queue runs on the SMT sibling of its interrupt
// CPU. One worker runs on each physical core with no queue interrupt, at most one for each TX
// queue and at least one, and the kicker of TX queue w on the sibling of worker w. A thread with no
// CPU in the plan runs where the scheduler puts it.

// cpuPlan is the CPU of each RX goroutine, worker and kicker (-1: none), and the interrupt CPU of
// each queue.
type cpuPlan struct {
	rx, wk, kick, irq []int
}

func (p cpuPlan) rxCPU(i int) int {
	if i < len(p.rx) {
		return p.rx[i]
	}
	return -1
}

// cpuTopology is what the plan reads of the host.
type cpuTopology struct {
	cpus     []int         // The CPU set of the relay, lowest first.
	siblings map[int][]int // The SMT siblings of each CPU of cpus, with the CPU, lowest first.
	irqs     map[int][]int // The interrupts of each queue, the RX interrupt first.
	irqCPUs  map[int][]int // The CPUs of each interrupt now.
}

// makePlan returns the plan of t for nRx RX queues and nTx TX queues. It fails when a queue has
// no physical core for its interrupts.
func makePlan(t cpuTopology, nRx, nTx int) (cpuPlan, error) {
	in := map[int]bool{}
	for _, c := range t.cpus {
		in[c] = true
	}
	// A physical core has the lowest CPU of its siblings as its name, and its lowest CPU in the
	// set as its lead.
	core := func(c int) int { return t.siblings[c][0] }
	var cores []int
	lead := map[int]int{}
	for _, c := range t.cpus {
		if _, ok := lead[core(c)]; !ok {
			lead[core(c)] = c
			cores = append(cores, core(c))
		}
	}
	other := func(c int) int { // Another CPU of the core of c in the set, or -1.
		for _, s := range t.siblings[c] {
			if s != c && in[s] {
				return s
			}
		}
		return -1
	}
	p := cpuPlan{irq: slices.Repeat([]int{-1}, nRx)}
	used := map[int]bool{} // The cores with a queue interrupt.
	for q := range nRx {
		irqs := t.irqs[q]
		if len(irqs) == 0 {
			continue
		}
		if cpus := t.irqCPUs[irqs[0]]; len(cpus) == 1 && in[cpus[0]] && !used[core(cpus[0])] {
			p.irq[q] = cpus[0]
			used[core(cpus[0])] = true
		}
	}
	for q := range nRx {
		if p.irq[q] >= 0 {
			continue
		}
		for _, c := range cores {
			if !used[c] {
				p.irq[q] = lead[c]
				used[c] = true
				break
			}
		}
		if p.irq[q] < 0 {
			return cpuPlan{}, fmt.Errorf("no free physical core for the interrupts of queue %d: %d queues, %d cores", q, nRx, len(cores))
		}
	}
	for _, c := range p.irq {
		p.rx = append(p.rx, other(c))
	}
	var free []int // The lead CPU of each core with no queue interrupt.
	for _, c := range cores {
		if !used[c] {
			free = append(free, lead[c])
		}
	}
	p.kick = slices.Repeat([]int{-1}, nTx)
	for w := range max(min(len(free), nTx), 1) {
		cpu := -1
		if w < len(free) {
			cpu = free[w]
			p.kick[w] = other(cpu)
		}
		p.wk = append(p.wk, cpu)
	}
	return p, nil
}

// placeCPUs makes the CPU plan of d from the sysfs at sys and the procfs at proc, places the queue
// interrupts, and sets the CPU of each thread. cpus is the CPU set of the relay. A link with no
// device (veth) has no queue interrupts: it gets no plan. When it fails, it puts back the
// interrupt affinities that it changed, and the relay must not start. Run puts them back when it
// stops.
func (d *Device) placeCPUs(sys, proc string, cpus []int) error {
	link := d.ifc.Name
	if _, err := os.Stat(filepath.Join(sys, "class/net", link, "device")); errors.Is(err, os.ErrNotExist) {
		slog.Info("The relay link has no device, so the relay threads get no CPU plan", "link", link)
		return nil
	}
	nRx, nTx := d.dev.NumRxQueues(), d.dev.NumTxQueues()
	t, err := readTopology(sys, proc, link, nRx, nTx, cpus)
	if err != nil {
		return err
	}
	p, err := makePlan(t, nRx, nTx)
	if err != nil {
		return err
	}
	saved, err := setIRQs(proc, t.irqs, p.irq)
	if err != nil {
		restoreIRQs(proc, saved)
		return err
	}
	d.restore = func() { restoreIRQs(proc, saved) }
	pending := settleIRQs(proc, t.irqs, p.irq, 2*time.Second)
	d.setPlan(p)
	if irqbalanceRuns(proc) {
		slog.Warn("irqbalance runs on the host, and it can move the queue interrupts of the relay", "link", link)
	}
	slog.Info("Set the CPU plan of the relay threads", "link", link, "cpus", len(cpus), "queue_irqs", t.irqs,
		"irq_cpus", p.irq, "rx_cpus", p.rx, "worker_cpus", p.wk, "kick_cpus", p.kick, "pending_irqs", pending)
	return nil
}

// setPlan gives each RX goroutine, worker and kicker its CPU of p, and keeps one worker for each
// CPU of p.wk.
func (d *Device) setPlan(p cpuPlan) {
	if n := len(p.wk); n < len(d.workers) {
		d.workers = d.workers[:n]
		d.p.setWorkers(n)
	}
	d.plan = p
	for i, w := range d.workers {
		w.cpu = p.wk[i]
	}
	for i, t := range d.tx {
		if i < len(p.kick) {
			t.cpu = p.kick[i]
		}
	}
}

// readTopology reads the SMT siblings of each CPU of cpus, the interrupts of the nRx queues of link
// and their CPUs.
func readTopology(sys, proc, link string, nRx, nTx int, cpus []int) (cpuTopology, error) {
	if len(cpus) == 0 {
		return cpuTopology{}, errors.New("the relay has no CPU")
	}
	t := cpuTopology{cpus: slices.Sorted(slices.Values(cpus)), siblings: map[int][]int{}, irqCPUs: map[int][]int{}}
	for _, c := range t.cpus {
		b, err := os.ReadFile(filepath.Join(sys, "devices/system/cpu", "cpu"+strconv.Itoa(c), "topology/thread_siblings_list"))
		if err != nil {
			return cpuTopology{}, err
		}
		l, err := ParseCPUList(string(b))
		if err != nil || !slices.Contains(l, c) {
			return cpuTopology{}, fmt.Errorf("bad siblings %q of CPU %d", strings.TrimSpace(string(b)), c)
		}
		t.siblings[c] = l
	}
	var err error
	if t.irqs, err = linkQueueIRQs(sys, proc, link, nRx, nTx); err != nil {
		return cpuTopology{}, err
	}
	for _, irqs := range t.irqs {
		for _, irq := range irqs {
			t.irqCPUs[irq] = irqCPUs(proc, irq)
		}
	}
	return t, nil
}

// setIRQs sets the affinity of the interrupts of each queue q to the CPU target[q]. It returns the
// old affinity of each interrupt that it changed, also when it fails.
func setIRQs(proc string, irqs map[int][]int, target []int) (map[int]string, error) {
	saved := map[int]string{}
	for q, cpu := range target {
		for _, irq := range irqs[q] {
			path := filepath.Join(proc, "irq", strconv.Itoa(irq), "smp_affinity_list")
			b, err := os.ReadFile(path)
			if err != nil {
				return saved, err
			}
			old := strings.TrimSpace(string(b))
			if old == strconv.Itoa(cpu) {
				continue
			}
			if err := os.WriteFile(path, []byte(strconv.Itoa(cpu)), 0o644); err != nil {
				return saved, fmt.Errorf("failed to move the interrupt %d of queue %d to CPU %d: %w", irq, q, cpu, err)
			}
			saved[irq] = old
			if b, err := os.ReadFile(path); err != nil || strings.TrimSpace(string(b)) != strconv.Itoa(cpu) {
				return saved, fmt.Errorf("the interrupt %d of queue %d is not on CPU %d after the move: %q", irq, q, cpu, strings.TrimSpace(string(b)))
			}
		}
	}
	return saved, nil
}

// settleIRQs waits up to limit until each interrupt of each queue q goes to target[q]. On x86 a
// move waits for the next interrupt, so the interrupts of an idle queue can stay pending: it
// returns them.
func settleIRQs(proc string, irqs map[int][]int, target []int, limit time.Duration) []int {
	end := time.Now().Add(limit)
	for {
		var pending []int
		for q, cpu := range target {
			for _, irq := range irqs[q] {
				if c := irqCPUs(proc, irq); len(c) != 1 || c[0] != cpu {
					pending = append(pending, irq)
				}
			}
		}
		if len(pending) == 0 || time.Now().After(end) {
			slices.Sort(pending)
			return pending
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// restoreIRQs puts back the affinity of each interrupt in saved.
func restoreIRQs(proc string, saved map[int]string) {
	for irq, old := range saved {
		path := filepath.Join(proc, "irq", strconv.Itoa(irq), "smp_affinity_list")
		if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
			slog.Warn("Failed to put back the affinity of an interrupt", "irq", irq, "affinity", old, "error", err)
		}
	}
	if len(saved) > 0 {
		slog.Info("Put back the affinity of the queue interrupts", "irqs", len(saved))
	}
}

// ErrCPUList is the error of ParseCPUList for a list that is not a CPU list.
var ErrCPUList = errors.New("bad CPU list")

// maxCPUs is the number of CPUs that unix.CPUSet holds, so the relay can pin a thread only to a
// CPU less than maxCPUs. unix.CPUSet is Linux only, thus device_linux.go makes sure that the two
// values are equal.
const maxCPUs = 1024

// ParseCPUList reads a CPU list as sysfs and relay.cpus give it, for example "0,16" or "0-3,8".
// It returns the CPUs, lowest first. Each CPU is less than maxCPUs.
func ParseCPUList(s string) ([]int, error) {
	var out []int
	for f := range strings.SplitSeq(strings.TrimSpace(s), ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(f), "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 || a >= maxCPUs {
			return nil, fmt.Errorf("%w %q", ErrCPUList, s)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a || b >= maxCPUs {
				return nil, fmt.Errorf("%w %q", ErrCPUList, s)
			}
		}
		for c := a; c <= b; c++ {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// irqQueueName is the name of a queue interrupt of ENA (eth0-Tx-Rx-7) and of drivers like it.
var irqQueueName = regexp.MustCompile(`(?i)-(?:tx-?rx|rx-?tx)-(\d+)$`)

// gveBlockName is the name of a notify block interrupt of gVNIC (gve-ntfy-blk3@pci:0000:00:01.0).
var gveBlockName = regexp.MustCompile(`^gve-ntfy-blk(\d+)@`)

// linkQueueIRQs returns the interrupts of each of the nRx queues of link, the RX interrupt first,
// from the MSI interrupts of its device and the handler names in procfs. ENA has one interrupt for
// each queue. gVNIC has a notify block for each TX queue (block q), for each XDP TX queue (block
// nTx+q) and for each RX queue (block blocks/2+q); a queue gets its RX, TX and XDP TX blocks.
func linkQueueIRQs(sys, proc, link string, nRx, nTx int) (map[int][]int, error) {
	entries, err := os.ReadDir(filepath.Join(sys, "class/net", link, "device/msi_irqs"))
	if err != nil {
		return nil, err
	}
	out := map[int][]int{}
	blocks := map[int]int{} // gVNIC: the interrupt of each notify block.
	for _, e := range entries {
		irq, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		acts, err := os.ReadDir(filepath.Join(proc, "irq", e.Name()))
		if err != nil {
			return nil, err
		}
		for _, a := range acts {
			if !a.IsDir() {
				continue
			}
			if m := irqQueueName.FindStringSubmatch(a.Name()); m != nil {
				q, _ := strconv.Atoi(m[1])
				out[q] = append(out[q], irq)
			} else if m := gveBlockName.FindStringSubmatch(a.Name()); m != nil {
				b, _ := strconv.Atoi(m[1])
				blocks[b] = irq
			}
		}
	}
	if len(blocks) > 0 {
		for b := range len(blocks) {
			if _, ok := blocks[b]; !ok || len(blocks)%2 != 0 {
				return nil, fmt.Errorf("gVNIC: the notify blocks are not 0 to n-1 with n even: %v", blocks)
			}
		}
		half := len(blocks) / 2
		for q := range nRx {
			rx, ok := blocks[half+q]
			if !ok || q >= half {
				return nil, fmt.Errorf("gVNIC: no RX notify block for queue %d (%d blocks)", q, len(blocks))
			}
			out[q] = []int{rx}
			for _, b := range []int{q, nTx + q} {
				if irq, ok := blocks[b]; ok && b < half {
					out[q] = append(out[q], irq)
				}
			}
		}
		return out, nil
	}
	for q := range out {
		slices.Sort(out[q])
	}
	for q := range nRx {
		if len(out[q]) == 0 {
			return nil, fmt.Errorf("queue %d of %s has no interrupt", q, link)
		}
	}
	return out, nil
}

// irqCPUs returns the CPUs that an interrupt goes to: its effective affinity, or its affinity.
func irqCPUs(proc string, irq int) []int {
	for _, f := range []string{"effective_affinity_list", "smp_affinity_list"} {
		b, err := os.ReadFile(filepath.Join(proc, "irq", strconv.Itoa(irq), f))
		if err != nil {
			continue
		}
		if l, err := ParseCPUList(string(b)); err == nil {
			return l
		}
	}
	return nil
}

// irqbalanceRuns reports whether a process named irqbalance runs on the host.
func irqbalanceRuns(proc string) bool {
	procs, _ := os.ReadDir(proc)
	for _, p := range procs {
		if b, err := os.ReadFile(filepath.Join(proc, p.Name(), "comm")); err == nil && strings.TrimSpace(string(b)) == "irqbalance" {
			return true
		}
	}
	return false
}
