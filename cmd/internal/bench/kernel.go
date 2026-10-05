// SPDX-License-Identifier: AGPL-3.0-only

package bench

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// softirqs are the softirq vectors of Linux, in the order of /proc/softirqs.
var softirqs = [...]string{"HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU"}

// hardIRQ is the kind of the device IRQ handlers. The softirq vectors are the kinds before it.
const hardIRQ = len(softirqs)

// irqTime is the run time and the runs of one kind of handler on one CPU.
type irqTime struct{ NS, Runs uint64 }

// writeIRQTable writes the times of the IRQ timer, one line for each CPU.
// kinds has one row for each kind, and each row has one value for each CPU.
func writeIRQTable(w io.Writer, kinds [][]irqTime) {
	fmt.Fprintf(w, "# cpu, then the nanoseconds and the runs of: HARDIRQ %s\n", strings.Join(softirqs[:], " "))
	if len(kinds) != hardIRQ+1 {
		return
	}
	for cpu := range kinds[hardIRQ] {
		fmt.Fprintf(w, "%d", cpu)
		for i := range kinds {
			// The IRQ handlers are the first column.
			var v irqTime
			if k := kinds[(hardIRQ+i)%len(kinds)]; cpu < len(k) {
				v = k[cpu]
			}
			fmt.Fprintf(w, " %d %d", v.NS, v.Runs)
		}
		fmt.Fprintln(w)
	}
}

// symbols are the text symbols of the kernel, in address order.
type symbols struct {
	addrs []uint64
	names []string
}

// readSymbols reads the text symbols of /proc/kallsyms. The kernel shows the
// address 0 for all symbols to a reader with no rights: the result is then empty.
func readSymbols(r io.Reader) symbols {
	type sym struct {
		addr uint64
		name string
	}
	var all []sym
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || !strings.ContainsAny(f[1], "tTwW") {
			continue
		}
		addr, err := strconv.ParseUint(f[0], 16, 64)
		if err != nil || addr == 0 {
			continue
		}
		all = append(all, sym{addr, f[2]})
	}
	slices.SortStableFunc(all, func(a, b sym) int {
		switch {
		case a.addr < b.addr:
			return -1
		case a.addr > b.addr:
			return 1
		}
		return 0
	})
	s := symbols{addrs: make([]uint64, len(all)), names: make([]string, len(all))}
	for i, v := range all {
		s.addrs[i], s.names[i] = v.addr, v.name
	}
	return s
}

// name returns the symbol that has addr, or the address when no symbol has it.
func (s symbols) name(addr uint64) string {
	i := sort.Search(len(s.addrs), func(i int) bool { return s.addrs[i] > addr })
	if i == 0 {
		return "0x" + strconv.FormatUint(addr, 16)
	}
	return s.names[i-1]
}

// fold returns the frames of a kernel stack with the root first. addrs has the
// leaf first and ends at the first zero.
func (s symbols) fold(addrs []uint64) string {
	n := slices.Index(addrs, 0)
	if n < 0 {
		n = len(addrs)
	}
	frames := make([]string, 0, n)
	for i := n - 1; i >= 0; i-- {
		frames = append(frames, s.name(addrs[i]))
	}
	return strings.Join(frames, ";")
}

// Stack ids of samples that have no kernel stack. The kernel gives -EFAULT for
// a sample in user code and -EEXIST when the stack table is full.
const (
	stackUser = 0xfffffff2
	stackLost = 0xffffffef
	stackErrs = 0xfffff000
)

// stackName returns the frames of a sample with no kernel stack.
func stackName(id uint32) string {
	switch id {
	case stackUser:
		return "[user]"
	case stackLost:
		return "[lost]"
	}
	return "[error " + strconv.Itoa(int(int32(id))) + "]"
}
