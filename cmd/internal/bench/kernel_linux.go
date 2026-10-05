// SPDX-License-Identifier: AGPL-3.0-only

package bench

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// samplePeriod is the time between two stack samples of one CPU. It is not a
	// multiple of the clock tick of the kernel.
	samplePeriod = 2003 * time.Microsecond
	// stackDepth is the most frames of a kernel stack.
	stackDepth = 127
	// stackTable and countTable are the sizes of the maps of the sampler.
	stackTable = 32768
	countTable = 262144
	// bpfLicense lets the sampler read kernel stacks.
	bpfLicense = "GPL"
)

// kernel measures the kernel work of the host in the measured window.
type kernel struct {
	prefix string
	irq    *irqTimer

	mu     sync.Mutex
	stacks *stackSampler
	middle *time.Timer // Starts the stack sampler.
	ended  bool
}

// startKernel starts the IRQ timer and writes the first snapshot. After the
// time sampleAfter, it writes the middle snapshot and starts the stack sampler.
// A part that fails is not in the files.
func startKernel(prefix string, sampleAfter time.Duration) (*kernel, error) {
	k := &kernel{prefix: prefix}
	var errs []error
	var err error
	if k.irq, err = newIRQTimer(); err != nil {
		errs = append(errs, fmt.Errorf("start the IRQ timer: %w", err))
	}
	errs = append(errs, k.snapshot("1", true))
	if sampleAfter <= 0 {
		errs = append(errs, k.sample())
	} else {
		k.middle = time.AfterFunc(sampleAfter, func() {
			k.mu.Lock()
			defer k.mu.Unlock()
			if k.ended {
				return
			}
			if err := errors.Join(k.snapshot("m", false), k.sample()); err != nil {
				slog.Warn("Failed to start the kernel stack sampler", "error", err)
			}
		})
	}
	return k, errors.Join(errs...)
}

// sample starts the stack sampler.
func (k *kernel) sample() error {
	var err error
	if k.stacks, err = newStackSampler(samplePeriod); err != nil {
		return fmt.Errorf("start the stack sampler: %w", err)
	}
	return nil
}

// end stops the stack sampler, and writes the last snapshot and the stacks.
func (k *kernel) end() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ended = true
	if k.middle != nil {
		k.middle.Stop()
	}
	k.stacks.stop()
	errs := []error{k.snapshot("2", false)}
	if k.stacks != nil {
		var b bytes.Buffer
		errs = append(errs, k.stacks.write(&b), os.WriteFile(k.prefix+"-stacks.txt", b.Bytes(), 0o644))
	}
	return errors.Join(errs...)
}

func (k *kernel) close() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ended = true
	if k.middle != nil {
		k.middle.Stop()
	}
	k.irq.close()
	k.stacks.close()
}

// irqTimer measures the run time of the device IRQ handlers and of the softirq
// handlers of each CPU with BPF programs on raw tracepoints.
type irqTimer struct {
	start, acc *ebpf.Map
	closers    []io.Closer
}

// Slots of the start map of the IRQ timer.
const (
	slotSoftIRQ = 0
	slotHardIRQ = 1
)

func newIRQTimer() (*irqTimer, error) {
	t := &irqTimer{}
	var err error
	// The start time of the handler that runs on the CPU, for each slot.
	if t.start, err = ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 2}); err != nil {
		return nil, err
	}
	t.closers = append(t.closers, t.start)
	// An irqTime for each kind.
	if t.acc, err = ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 16, MaxEntries: uint32(hardIRQ + 1)}); err != nil {
		t.close()
		return nil, err
	}
	t.closers = append(t.closers, t.acc)
	progs := []struct {
		tracepoint string
		insns      asm.Instructions
	}{
		{"softirq_entry", enterProg(t.start, slotSoftIRQ)},
		{"softirq_exit", exitProg(t.start, t.acc, slotSoftIRQ, -1)},
		{"irq_handler_entry", enterProg(t.start, slotHardIRQ)},
		{"irq_handler_exit", exitProg(t.start, t.acc, slotHardIRQ, int32(hardIRQ))},
	}
	for _, p := range progs {
		prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.RawTracepoint, Instructions: p.insns, License: bpfLicense})
		if err != nil {
			t.close()
			return nil, fmt.Errorf("load the program of %s: %w", p.tracepoint, err)
		}
		t.closers = append(t.closers, prog)
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: p.tracepoint, Program: prog})
		if err != nil {
			t.close()
			return nil, fmt.Errorf("attach to %s: %w", p.tracepoint, err)
		}
		t.closers = append(t.closers, l)
	}
	return t, nil
}

// lookup returns the instructions that look up the 4-byte key at the frame
// pointer minus 4 in m. R0 gets the value, or 0.
func lookup(m *ebpf.Map) asm.Instructions {
	return asm.Instructions{
		asm.LoadMapPtr(asm.R1, m.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
	}
}

// enterProg writes the time to a slot of start when a handler starts.
func enterProg(start *ebpf.Map, slot int32) asm.Instructions {
	insns := asm.Instructions{asm.StoreImm(asm.RFP, -4, int64(slot), asm.Word)}
	insns = append(insns, lookup(start)...)
	return append(insns,
		asm.JEq.Imm(asm.R0, 0, "out"),
		asm.Mov.Reg(asm.R6, asm.R0),
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.R6, 0, asm.R0, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
		asm.Return(),
	)
}

// exitProg adds the time since the start in slot to a kind of acc when a
// handler ends. A negative kind is the softirq vector: the first argument of
// the tracepoint.
func exitProg(start, acc *ebpf.Map, slot, kind int32) asm.Instructions {
	insns := asm.Instructions{asm.Mov.Imm(asm.R7, kind)}
	if kind < 0 {
		insns = asm.Instructions{asm.LoadMem(asm.R7, asm.R1, 0, asm.DWord)}
	}
	insns = append(insns, asm.StoreImm(asm.RFP, -4, int64(slot), asm.Word))
	insns = append(insns, lookup(start)...)
	insns = append(insns,
		asm.JEq.Imm(asm.R0, 0, "out"),
		asm.LoadMem(asm.R6, asm.R0, 0, asm.DWord),
		// No start time: the handler started before the program.
		asm.JEq.Imm(asm.R6, 0, "out"),
		asm.StoreImm(asm.R0, 0, 0, asm.DWord),
		asm.FnKtimeGetNs.Call(),
		asm.Sub.Reg(asm.R0, asm.R6),
		asm.Mov.Reg(asm.R6, asm.R0),
		asm.StoreMem(asm.RFP, -4, asm.R7, asm.Word),
	)
	insns = append(insns, lookup(acc)...)
	return append(insns,
		asm.JEq.Imm(asm.R0, 0, "out"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
		asm.Add.Reg(asm.R1, asm.R6),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.R0, 8, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, 8, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
		asm.Return(),
	)
}

// read returns the times of each kind and each CPU.
func (t *irqTimer) read() ([][]irqTime, error) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	kinds := make([][]irqTime, hardIRQ+1)
	for k := range kinds {
		kinds[k] = make([]irqTime, cpus)
		if err := t.acc.Lookup(uint32(k), kinds[k]); err != nil {
			return nil, err
		}
	}
	return kinds, nil
}

func (t *irqTimer) close() {
	if t == nil {
		return
	}
	for _, c := range slices.Backward(t.closers) {
		_ = c.Close()
	}
}

// stackSampler counts the kernel stacks of each CPU with a BPF program on a
// CPU clock event.
type stackSampler struct {
	stacks, counts *ebpf.Map
	prog           *ebpf.Program
	events         []int
	period         time.Duration
	began          time.Time
	ran            time.Duration
}

func newStackSampler(period time.Duration) (*stackSampler, error) {
	s := &stackSampler{period: period}
	var err error
	if s.stacks, err = ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.StackTrace, KeySize: 4, ValueSize: 8 * stackDepth, MaxEntries: stackTable}); err != nil {
		return nil, err
	}
	// The key is the CPU in the high half and the stack id in the low half.
	if s.counts, err = ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: countTable}); err != nil {
		s.close()
		return nil, err
	}
	if s.prog, err = ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.PerfEvent, Instructions: sampleProg(s.stacks, s.counts), License: bpfLicense}); err != nil {
		s.close()
		return nil, fmt.Errorf("load the program: %w", err)
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		s.close()
		return nil, err
	}
	attr := unix.PerfEventAttr{
		Type: unix.PERF_TYPE_SOFTWARE, Config: unix.PERF_COUNT_SW_CPU_CLOCK, Size: uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Sample: uint64(period.Nanoseconds()), Bits: unix.PerfBitDisabled,
	}
	for cpu := range cpus {
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if errors.Is(err, unix.ENODEV) {
			// The CPU is not online.
			continue
		}
		if err != nil {
			s.close()
			return nil, fmt.Errorf("open the clock event of CPU %d: %w", cpu, err)
		}
		s.events = append(s.events, fd)
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, s.prog.FD()); err != nil {
			s.close()
			return nil, fmt.Errorf("attach to the clock event of CPU %d: %w", cpu, err)
		}
	}
	s.began = time.Now()
	for _, fd := range s.events {
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			s.close()
			return nil, fmt.Errorf("start a clock event: %w", err)
		}
	}
	return s, nil
}

// sampleProg adds 1 to the count of the kernel stack of the sample. A sample
// with no kernel stack has the error of the kernel as its stack id.
func sampleProg(stacks, counts *ebpf.Map) asm.Instructions {
	key := asm.Instructions{
		asm.LoadMapPtr(asm.R1, counts.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
	}
	insns := asm.Instructions{
		// R1 is the context.
		asm.LoadMapPtr(asm.R2, stacks.FD()),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnGetStackid.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.LSh.Imm(asm.R7, 32),
		asm.RSh.Imm(asm.R7, 32),
		asm.FnGetSmpProcessorId.Call(),
		asm.LSh.Imm(asm.R0, 32),
		asm.Or.Reg(asm.R0, asm.R7),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
	}
	insns = append(insns, key...)
	insns = append(insns,
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "new"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		asm.Ja.Label("out"),
		asm.StoreImm(asm.RFP, -16, 1, asm.DWord).WithSymbol("new"),
	)
	insns = append(insns, key...)
	return append(insns,
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
		asm.Return(),
	)
}

// stop ends the samples. The counts stay.
func (s *stackSampler) stop() {
	if s == nil || s.events == nil {
		return
	}
	for _, fd := range s.events {
		_ = unix.Close(fd)
	}
	s.events = nil
	s.ran = time.Since(s.began)
}

// write writes an "s" line for each stack, with its id and its frames from
// the root, and then a "c" line for each CPU and stack: the CPU, the samples
// and the stack id.
func (s *stackSampler) write(w io.Writer) error {
	var syms symbols
	if f, err := os.Open("/proc/kallsyms"); err == nil {
		syms = readSymbols(f)
		_ = f.Close()
	}
	fmt.Fprintf(w, "# period_ns %d seconds %.3f symbols %d\n", s.period.Nanoseconds(), s.ran.Seconds(), len(syms.addrs))
	counts := map[uint64]uint64{}
	var key, n uint64
	it := s.counts.Iterate()
	for it.Next(&key, &n) {
		counts[key] = n
	}
	if err := it.Err(); err != nil {
		return err
	}
	seen := map[uint32]bool{}
	var addrs [stackDepth]uint64
	for _, key := range slices.Sorted(maps.Keys(counts)) {
		id := uint32(key)
		if seen[id] {
			continue
		}
		seen[id] = true
		name := "[no stack]"
		switch {
		case id >= stackErrs:
			name = stackName(id)
		case s.stacks.Lookup(id, &addrs) == nil:
			name = syms.fold(addrs[:])
		}
		fmt.Fprintf(w, "s %d %s\n", id, name)
	}
	for _, key := range slices.Sorted(maps.Keys(counts)) {
		fmt.Fprintf(w, "c %d %d %d\n", key>>32, counts[key], uint32(key))
	}
	return nil
}

func (s *stackSampler) close() {
	if s == nil {
		return
	}
	s.stop()
	if s.prog != nil {
		_ = s.prog.Close()
	}
	if s.counts != nil {
		_ = s.counts.Close()
	}
	if s.stacks != nil {
		_ = s.stacks.Close()
	}
}

// procFiles are the files of each snapshot.
var procFiles = []string{"/proc/stat", "/proc/softirqs", "/proc/interrupts", "/proc/net/softnet_stat", "/proc/net/snmp", "/proc/net/netstat"}

// hostFiles are the files of the first snapshot: they do not change in a run.
var hostFiles = []string{
	"/proc/version", "/proc/cmdline", "/sys/devices/system/clocksource/clocksource0/current_clocksource",
	"/sys/devices/system/cpu/cpuidle/current_driver", "/sys/devices/system/cpu/cpuidle/current_governor_ro",
	"/proc/sys/net/core/busy_poll", "/proc/sys/net/core/busy_read", "/proc/sys/net/core/netdev_budget",
	"/proc/sys/net/core/netdev_budget_usecs", "/proc/sys/net/core/dev_weight", "/proc/sys/net/core/default_qdisc",
}

// configKeys are the kernel build options of the first snapshot. They tell how
// the kernel counts the CPU time of /proc/stat.
var configKeys = []string{"CONFIG_HZ", "CONFIG_NO_HZ", "CONFIG_IRQ_TIME_ACCOUNTING", "CONFIG_VIRT_CPU_ACCOUNTING", "CONFIG_TICK_CPU_ACCOUNTING", "CONFIG_PREEMPT"}

// snapshot writes the counters of the kernel and of the network devices to the
// file of name. Each part starts with a "## " line.
func (k *kernel) snapshot(name string, host bool) error {
	var b bytes.Buffer
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	fmt.Fprintf(&b, "## time\nunix_ns %d\nmonotonic_ns %d\n", time.Now().UnixNano(), ts.Nano())
	if k.irq != nil {
		b.WriteString("## irqtime\n")
		kinds, err := k.irq.read()
		if err != nil {
			fmt.Fprintf(&b, "# error: %v\n", err)
		}
		writeIRQTable(&b, kinds)
	}
	for _, path := range procFiles {
		writeFile(&b, path)
	}
	b.WriteString("## ksoftirqd\n# name, user ticks, system ticks\n")
	writeThreads(&b, "ksoftirqd/")
	writeIdle(&b)
	writeDevices(&b)
	if host {
		for _, path := range hostFiles {
			writeFile(&b, path)
		}
		writeConfig(&b)
		writeCPUInfo(&b)
	}
	return os.WriteFile(k.prefix+"-"+name+".txt", b.Bytes(), 0o644)
}

// writeFile writes a file as one part. A file that the host does not have is not a part.
func writeFile(w *bytes.Buffer, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "## %s\n%s", path, data)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		w.WriteByte('\n')
	}
}

// writeThreads writes the CPU ticks of the threads with a name that starts with prefix.
func writeThreads(w io.Writer, prefix string) {
	stats, _ := filepath.Glob("/proc/[0-9]*/stat")
	for _, path := range stats {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// The name is in brackets and can have spaces.
		open, end := bytes.IndexByte(data, '('), bytes.LastIndexByte(data, ')')
		if open < 0 || end < open || !bytes.HasPrefix(data[open+1:end], []byte(prefix)) {
			continue
		}
		// utime and stime are fields 14 and 15, and the name is field 2.
		if f := strings.Fields(string(data[end+1:])); len(f) > 12 {
			fmt.Fprintf(w, "%s %s %s\n", data[open+1:end], f[11], f[12])
		}
	}
}

// writeIdle writes the entries and the microseconds of each idle state of each CPU.
func writeIdle(w *bytes.Buffer) {
	names, _ := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*/cpuidle/state[0-9]*/name")
	if len(names) == 0 {
		return
	}
	w.WriteString("## cpuidle\n# cpu, state, name, entries, microseconds\n")
	for _, path := range names {
		dir := filepath.Dir(path)
		var vals [3]string
		for i, file := range []string{"name", "usage", "time"} {
			data, _ := os.ReadFile(filepath.Join(dir, file))
			vals[i] = strings.TrimSpace(string(data))
		}
		cpu := strings.TrimPrefix(filepath.Base(filepath.Dir(filepath.Dir(dir))), "cpu")
		fmt.Fprintf(w, "%s %s %s %s %s\n", cpu, strings.TrimPrefix(filepath.Base(dir), "state"), vals[0], vals[1], vals[2])
	}
}

// writeDevices writes the counters, the settings and the qdiscs of each
// network device that is up, without the loopback.
func writeDevices(w *bytes.Buffer) {
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}
	e, err := ethtool.NewEthtool()
	if err != nil {
		return
	}
	defer e.Close()
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		dev := ifi.Name
		if stats, err := e.Stats(dev); err == nil {
			fmt.Fprintf(w, "## nic %s\n", dev)
			for _, name := range slices.Sorted(maps.Keys(stats)) {
				fmt.Fprintf(w, "%s %d\n", name, stats[name])
			}
		}
		fmt.Fprintf(w, "## settings %s\n", dev)
		if d, err := e.DriverName(dev); err == nil {
			fmt.Fprintf(w, "driver %s\n", d)
		}
		if ch, err := e.GetChannels(dev); err == nil {
			fmt.Fprintf(w, "channels %+v\n", ch)
		}
		if c, err := e.GetCoalesce(dev); err == nil {
			fmt.Fprintf(w, "coalesce %+v\n", c)
		}
		if r, err := e.GetRing(dev); err == nil {
			fmt.Fprintf(w, "ring %+v\n", r)
		}
		if feats, err := e.Features(dev); err == nil {
			on := slices.DeleteFunc(slices.Sorted(maps.Keys(feats)), func(name string) bool { return !feats[name] })
			fmt.Fprintf(w, "features_on %s\n", strings.Join(on, " "))
		}
		sys := "/sys/class/net/" + dev + "/"
		paths := []string{sys + "gro_flush_timeout", sys + "napi_defer_hard_irqs", sys + "tx_queue_len", sys + "threaded"}
		for _, pattern := range []string{"queues/tx-*/xps_cpus", "queues/rx-*/rps_cpus"} {
			m, _ := filepath.Glob(sys + pattern)
			paths = append(paths, m...)
		}
		for _, path := range paths {
			if data, err := os.ReadFile(path); err == nil {
				fmt.Fprintf(w, "%s %s\n", strings.TrimPrefix(path, sys), strings.TrimSpace(string(data)))
			}
		}
		l, err := netlink.LinkByIndex(ifi.Index)
		if err != nil {
			continue
		}
		qdiscs, err := netlink.QdiscList(l)
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "## qdisc %s\n# kind, handle, parent, bytes, packets, drops, requeues, overlimits, qlen, backlog\n", dev)
		for _, q := range qdiscs {
			a := q.Attrs()
			var basic netlink.GnetStatsBasic
			var queue netlink.GnetStatsQueue
			if st := a.Statistics; st != nil {
				if st.Basic != nil {
					basic = *st.Basic
				}
				if st.Queue != nil {
					queue = *st.Queue
				}
			}
			fmt.Fprintf(w, "%s %x %x %d %d %d %d %d %d %d\n", q.Type(), a.Handle, a.Parent, basic.Bytes, basic.Packets,
				queue.Drops, queue.Requeues, queue.Overlimits, queue.Qlen, queue.Backlog)
		}
	}
}

// writeCPUInfo writes the /proc/cpuinfo lines of the first CPU.
func writeCPUInfo(w *bytes.Buffer) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return
	}
	first, _, _ := strings.Cut(string(data), "\n\n")
	fmt.Fprintf(w, "## cpuinfo\n%s\n", first)
}

// writeConfig writes the build options of the kernel that are in configKeys.
func writeConfig(w *bytes.Buffer) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return
	}
	data, err := os.ReadFile("/boot/config-" + unix.ByteSliceToString(uts.Release[:]))
	if err != nil {
		return
	}
	w.WriteString("## config\n")
	for line := range strings.Lines(string(data)) {
		for _, key := range configKeys {
			if strings.HasPrefix(line, key) {
				w.WriteString(line)
				break
			}
		}
	}
}
