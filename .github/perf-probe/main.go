// SPDX-License-Identifier: AGPL-3.0-only

// Command perf-probe checks, as root, that the kernel can delay and drop packets with eBPF and fq.
// It prints a markdown table with one PASS or FAIL row for each check.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	nsA, nsB   = "perfprobe-a", "perfprobe-b"
	devA, devB = "pprobe-a", "pprobe-b"
	ipA, ipB   = "10.250.0.1", "10.250.0.2"
	delay      = 10 * time.Millisecond
	// tstampOff is the offset of __sk_buff.tstamp.
	tstampOff = 152
	// tstampMono is BPF_SKB_TSTAMP_DELIVERY_MONO.
	tstampMono = 1
	fqSpec     = "fq limit 100000 flow_limit 100000 horizon 10s horizon_drop nopacing"
)

// required are the checks that the EDT rig needs.
var required = []string{"qdisc fq", "TCX egress + bpf_skb_set_tstamp", "TCX random drop 50%"}

type row struct{ check, result, detail string }

var rows []row

func add(check string, err error, detail string) {
	res := "PASS"
	if err != nil {
		res = "FAIL"
		detail += " " + err.Error()
	}
	rows = append(rows, row{check, res, strings.TrimSpace(detail)})
}

func main() { os.Exit(probe()) }

// probe runs the checks, prints the table and returns the exit code.
func probe() int {
	defer cleanup()
	cleanup()
	if err := setup(); err != nil {
		slog.Error("Failed to set up the probe netns", "error", err)
		return 1
	}
	base, _, err := ping(20, 50*time.Millisecond)
	if err != nil {
		slog.Error("Failed to ping through the veth", "error", err)
		return 1
	}

	for _, q := range []string{fqSpec, "etf clockid CLOCK_TAI delta 300000 skip_sock_check",
		"tbf rate 1gbit burst 256k latency 30ms", "htb default 1", "netem delay 10ms", "fq_codel"} {
		kind := strings.Fields(q)[0]
		mod := modprobe("sch_" + kind)
		out, err := tc(append([]string{"qdisc", "replace", "dev", devA, "root"}, strings.Fields(q)...)...)
		add("qdisc "+kind, err, mod+" "+out)
		_, _ = tc("qdisc", "del", "dev", devA, "root")
	}
	mod := modprobe("sch_ingress")
	out, err := tc("qdisc", "add", "dev", devA, "clsact")
	add("qdisc clsact", err, mod+" "+out)
	_, _ = tc("qdisc", "del", "dev", devA, "clsact")

	store, err := load(edtStore())
	add("BPF load (tstamp store)", err, "")
	helper, err := load(edtHelper())
	add("BPF load (bpf_skb_set_tstamp)", err, "")
	drop, err := load(drop50())
	add("BPF load (random drop)", err, "")

	// EDT needs fq: it holds each packet until its delivery time.
	if _, err := tc(append([]string{"qdisc", "replace", "dev", devA, "root"}, strings.Fields(fqSpec)...)...); err != nil {
		slog.Warn("Failed to add fq; the EDT checks fail", "error", err)
	}
	if store != nil {
		edt("TCX egress + tstamp store", base, func() (func(), error) { return attachTCX(nsA, devA, store) })
		modprobe("cls_bpf")
		edt("clsact + cls_bpf + tstamp store", base, func() (func(), error) { return attachClsBPF(store) })
	}
	if helper != nil {
		edt("TCX egress + bpf_skb_set_tstamp", base, func() (func(), error) { return attachTCX(nsA, devA, helper) })
	}
	// Drop the replies on B. A drop on A is a send error, and ping sends that packet again.
	if drop != nil {
		detach, err := attachTCX(nsB, devB, drop)
		if err == nil {
			var loss float64
			_, loss, err = ping(200, 10*time.Millisecond)
			detach()
			if err == nil && (loss < 30 || loss > 70) {
				err = errors.New("want 30-70%")
			}
			add("TCX random drop 50%", err, fmt.Sprintf("ping loss %.0f%%", loss))
		} else {
			add("TCX random drop 50%", err, "")
		}
	}

	label := os.Getenv("RUNNER_LABEL")
	var uts unix.Utsname
	_ = unix.Uname(&uts)
	fmt.Printf("### Perf probe: %s, kernel %s\n\n", label, unix.ByteSliceToString(uts.Release[:]))
	fmt.Printf("Base RTT %.2f ms. The EDT checks add %v on one side.\n\n", base, delay)
	fmt.Println("| Check | Result | Detail |")
	fmt.Println("|---|---|---|")
	pass := map[string]bool{}
	for _, r := range rows {
		fmt.Printf("| %s | %s | %s |\n", r.check, r.result, strings.ReplaceAll(r.detail, "|", "/"))
		pass[r.check] = r.result == "PASS"
	}
	fmt.Println()
	var missing []string
	for _, c := range required {
		if !pass[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		fmt.Printf("**The EDT rig cannot run here.** Failed: %s.\n\n", strings.Join(missing, ", "))
		return 2
	}
	fmt.Print("**The EDT rig can run here.**\n\n")
	return 0
}

// edt attaches a delivery time program and checks that the RTT goes up by the delay.
func edt(check string, base float64, attach func() (func(), error)) {
	detach, err := attach()
	if err != nil {
		add(check, err, "")
		return
	}
	rtt, _, err := ping(20, 50*time.Millisecond)
	detach()
	want := float64(delay) / float64(time.Millisecond)
	if err == nil && (rtt-base < want-2 || rtt-base > want+3) {
		err = fmt.Errorf("want about %.2f ms", base+want)
	}
	add(check, err, fmt.Sprintf("RTT %.2f ms", rtt))
}

// edtStore writes now + delay to __sk_buff.tstamp.
func edtStore() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnKtimeGetNs.Call(),
		asm.Add.Imm(asm.R0, int32(delay)),
		asm.StoreMem(asm.R6, tstampOff, asm.R0, asm.DWord),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}
}

// edtHelper sets now + delay as a mono delivery time with bpf_skb_set_tstamp.
func edtHelper() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnKtimeGetNs.Call(),
		asm.Mov.Reg(asm.R2, asm.R0),
		asm.Add.Imm(asm.R2, int32(delay)),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R3, tstampMono),
		asm.FnSkbSetTstamp.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}
}

// drop50 drops half of the packets at random.
func drop50() asm.Instructions {
	return asm.Instructions{
		asm.FnGetPrandomU32.Call(),
		asm.And.Imm(asm.R0, 1),
		asm.JEq.Imm(asm.R0, 0, "drop"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("drop"),
		asm.Return(),
	}
}

func load(insns asm.Instructions) (*ebpf.Program, error) {
	return ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, Instructions: insns, License: "AGPL-3.0-only"})
}

func attachTCX(ns, dev string, prog *ebpf.Program) (func(), error) {
	var l link.Link
	err := inNetns(ns, func() error {
		ifc, err := net.InterfaceByName(dev)
		if err != nil {
			return err
		}
		l, err = link.AttachTCX(link.TCXOptions{Interface: ifc.Index, Program: prog, Attach: ebpf.AttachTCXEgress})
		return err
	})
	if err != nil {
		return nil, err
	}
	return func() { _ = l.Close() }, nil
}

func attachClsBPF(prog *ebpf.Program) (func(), error) {
	if out, err := tc("qdisc", "add", "dev", devA, "clsact"); err != nil {
		return nil, fmt.Errorf("%w: %s", err, out)
	}
	detach := func() { _, _ = tc("qdisc", "del", "dev", devA, "clsact") }
	err := inNetns(nsA, func() error {
		l, err := netlink.LinkByName(devA)
		if err != nil {
			return err
		}
		return netlink.FilterAdd(&netlink.BpfFilter{
			FilterAttrs:  netlink.FilterAttrs{LinkIndex: l.Attrs().Index, Parent: netlink.HANDLE_MIN_EGRESS, Handle: 1, Protocol: unix.ETH_P_ALL, Priority: 1},
			Fd:           prog.FD(),
			Name:         "perfprobe",
			DirectAction: true,
		})
	})
	if err != nil {
		detach()
		return nil, err
	}
	return detach, nil
}

// inNetns runs f on a locked OS thread in the netns name.
func inNetns(name string, f func() error) error {
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer orig.Close()
	ns, err := netns.GetFromName(name)
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer ns.Close()
	if err := netns.Set(ns); err != nil {
		runtime.UnlockOSThread()
		return err
	}
	ferr := f()
	// Keep the thread locked if it cannot go back, so that Go does not use it again.
	if err := netns.Set(orig); err != nil {
		return errors.Join(ferr, err)
	}
	runtime.UnlockOSThread()
	return ferr
}

func setup() error {
	for _, args := range [][]string{
		{"netns", "add", nsA},
		{"netns", "add", nsB},
		{"link", "add", devA, "netns", nsA, "type", "veth", "peer", "name", devB, "netns", nsB},
		{"-n", nsA, "addr", "add", ipA + "/24", "dev", devA},
		{"-n", nsB, "addr", "add", ipB + "/24", "dev", devB},
		{"-n", nsA, "link", "set", devA, "up"},
		{"-n", nsB, "link", "set", devB, "up"},
	} {
		if out, err := run("ip", args...); err != nil {
			return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

func cleanup() {
	_, _ = run("ip", "netns", "del", nsA)
	_, _ = run("ip", "netns", "del", nsB)
}

// modprobe loads a module when the host has it, and tells the result.
func modprobe(name string) string {
	if _, err := run("modprobe", name); err != nil {
		return "modprobe " + name + " failed;"
	}
	return "modprobe " + name + " ok;"
}

func tc(args ...string) (string, error) {
	return run("tc", append([]string{"-n", nsA}, args...)...)
}

var (
	rttRe  = regexp.MustCompile(`= [\d.]+/([\d.]+)/`)
	lossRe = regexp.MustCompile(`([\d.]+)% packet loss`)
)

// ping returns the average RTT in ms and the loss in percent from A to B.
func ping(count int, interval time.Duration) (rtt, loss float64, err error) {
	out, _ := run("ip", "netns", "exec", nsA, "ping", "-q", "-c", strconv.Itoa(count),
		"-i", strconv.FormatFloat(interval.Seconds(), 'f', 3, 64), "-W", "1", ipB)
	m := lossRe.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, fmt.Errorf("no ping summary: %s", out)
	}
	loss, _ = strconv.ParseFloat(m[1], 64)
	if m := rttRe.FindStringSubmatch(out); m != nil {
		rtt, _ = strconv.ParseFloat(m[1], 64)
	}
	return rtt, loss, nil
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
