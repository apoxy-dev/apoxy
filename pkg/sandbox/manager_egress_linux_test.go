//go:build linux

package sandbox

// APO-713 Stage-0 spike, tier 1 (hermetic — no workerd image): boot a REAL
// runsc/gVisor sandbox whose guest issues an ordinary outbound TCP connect() to
// a NON-LOCAL destination, and prove the in-Sentry egress forwarder
// (pkg/sandbox/sentrystack/egressfwd, armed by importing it below) STEALS that
// connect() and bridges it to the host egress endpoint (EgressHostAddr),
// carrying the real destination the shared bridge socket can't learn from its
// 5-tuple. This is the egress twin of TestInboundRoundtrip.
//
// What this proves and what it does NOT: it proves that a real guest process's
// connect() under the real Sentry (systrap syscall trapping + the production
// doInit/wireEth0 eth0 default route + loopether) lands on our forwarder and is
// bridged with the correct dst — i.e. the forwarder + EgressHostAddr wiring +
// syscall interception, end to end. It uses THIS test binary as the guest, not
// workerd, so it does NOT prove the workerd-specific claim (that a workerd
// fetch() issues an ordinary connect() with globalOutbound defaulted). That
// final tier needs a real workerd image and is the follow-up gate. The
// pure-pkg/tcpip egress_demux_test.go proves the netstack demux in isolation on
// any host; this proves the real-Sentry wiring; the workerd tier closes the
// last gap.
//
// HOW IT RUNS: like TestInboundRoundtrip it needs a privileged Linux host with
// runsc-capable gVisor and cgroup v2, and self-skips elsewhere. The guest is
// this test binary re-exec'd with egressProbeArg (so no external image is
// needed), which means it must be STATICALLY linked — build/run with
// CGO_ENABLED=0. Run with: `go test -tags acceptance` is NOT required (this is
// plain -linux, root-gated), but it must run as root on a cgroup-v2 host.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	// Blank-importing egressfwd arms sentrystack.ForwarderInstaller (its init) so
	// the Sentry boot child installs the egress forwarder. The host-side preamble
	// decoder is the side-effect-free egresswire package.
	_ "github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack/egressfwd"
	"github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack/egresswire"
)

// egressProbeArg is the argv[1] sentinel that turns this test binary into the
// in-sandbox egress client. The guest entrypoint is
// "/server <egressProbeArg> <dstAddr>". Dispatched from TestMain
// (manager_inbound_linux_test.go).
const egressProbeArg = "clrk-egress-test-probe"

// egressProbePayload is what the guest writes after connecting, so the host
// recorder can assert the stream was actually spliced through (not just that a
// SYN was seen) — the egress analog of the inbound "pong".
const egressProbePayload = "egress-probe"

// runEgressProbe is the in-guest workload: dial dst (a non-local address that
// must route out eth0 and be stolen by the egress forwarder), write the probe
// payload, then block until the host closes. Never returns.
func runEgressProbe(dst string) {
	conn, err := net.DialTimeout("tcp", dst, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "egress probe dial %s: %v\n", dst, err)
		os.Exit(1)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "%s\n", egressProbePayload); err != nil {
		fmt.Fprintf(os.Stderr, "egress probe write: %v\n", err)
		os.Exit(1)
	}
	// Block until the host recorder closes the bridged conn, so the guest
	// outlives the observation instead of racing teardown.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	_, _ = conn.Read(buf)
	os.Exit(0)
}

// egressDenyProbeArg is the argv[1] sentinel for the deny-path guest: it dials
// a destination the fake bridge deny-verdicts (expecting a FAST connection
// refusal — the forwarder RSTs the SYN pre-endpoint), then reports the observed
// dial outcome to the host over a second, allowed flow.
const egressDenyProbeArg = "clrk-egress-test-deny-probe"

// runEgressDenyProbe is the in-guest deny-path workload: dial deniedDst
// (expecting refusal), then dial reportDst and write a one-line verdict report
// the host recorder asserts on. Never returns.
func runEgressDenyProbe(deniedDst, reportDst string) {
	report := "denied-dial-succeeded" // failure sentinel: the deny didn't deny
	start := time.Now()
	conn, err := net.DialTimeout("tcp", deniedDst, 10*time.Second)
	if err == nil {
		conn.Close()
	} else {
		// The RST must arrive as a prompt refusal, not a timeout: an error
		// after ~verdict-timeout means the forwarder hung rather than refusing
		// the SYN. 5s is far above a loopback verdict RTT and far below the
		// 10s dial timeout.
		if time.Since(start) < 5*time.Second {
			report = "denied-fast"
		} else {
			report = "denied-slow"
		}
	}
	rconn, rerr := net.DialTimeout("tcp", reportDst, 10*time.Second)
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "egress deny probe report dial %s: %v\n", reportDst, rerr)
		os.Exit(1)
	}
	defer rconn.Close()
	fmt.Fprintf(rconn, "%s\n", report)
	_ = rconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	_, _ = rconn.Read(buf)
	os.Exit(0)
}

// egressRecord is what the host recorder observed for one bridged flow.
type egressRecord struct {
	src     netip.AddrPort
	dst     netip.AddrPort
	payload string
	err     error
}

// startEgressRecorder stands in for the host egress bridge: it listens on
// loopback (the address handed to the sandbox as EgressHostAddr), accepts the
// forwarder's single bridged connection, decodes the egress preamble to recover
// the real dst, reads the guest payload, and reports it. The Sentry shares the
// host net namespace under runsc+sentrystack, so it can reach this 127.0.0.1
// listener. Returns the listen address and a one-shot result channel.
func startEgressRecorder(t *testing.T) (string, <-chan egressRecord) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("egress recorder listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	out := make(chan egressRecord, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			out <- egressRecord{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		src, dst, _, err := egresswire.ReadEgressPreamble(r)
		if err != nil {
			out <- egressRecord{err: err}
			return
		}
		// v3: the forwarder holds the guest SYN until the bridge answers with a
		// verdict; allow the flow so the guest connect() completes and the
		// payload arrives.
		if err := egresswire.WriteEgressVerdict(conn, true); err != nil {
			out <- egressRecord{err: err}
			return
		}
		payload, _ := r.ReadString('\n')
		out <- egressRecord{src: src, dst: dst, payload: strings.TrimSpace(payload)}
	}()
	return ln.Addr().String(), out
}

// TestEgressRoundtrip is the tier-1 spike gate: guest connect() → in-Sentry
// egress forwarder → host recorder, asserting the recorder saw the real dst and
// the spliced payload.
func TestEgressRoundtrip(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sandbox boot requires linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("sandbox boot requires root (runsc + cgroup v2 delegation)")
	}
	cgroupPath, err := InitHostCgroup()
	if err != nil {
		t.Skipf("host cgroup v2 unavailable (%v) — needs a delegated cgroup v2 host", err)
	}

	// A non-local destination (TEST-NET-3, RFC 5737): not one of the sandbox's
	// own addresses, so reaching it requires the eth0 default route and gets
	// stolen by the catch-all egress forwarder rather than delivered locally.
	const imageRef = "test://egress-probe"
	probeDst := netip.MustParseAddrPort("203.0.113.5:80")

	recorderAddr, records := startEgressRecorder(t)

	mgr := NewManager(ManagerConfig{
		StateDir:       t.TempDir(),
		RootDir:        t.TempDir(),
		ImageStore:     NewImageStore(t.TempDir()),
		HostCgroupPath: cgroupPath,
	})
	seedResidentImage(t, mgr.ImageStore(), imageRef)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	id := SandboxID("egrtest")
	_, err = mgr.Create(ctx, Spec{
		ID:      id,
		Image:   imageRef,
		Command: []string{"/server", egressProbeArg, probeDst.String()},
		// The drive-seam: EgressHostAddr must be on the Spec so Create seals it
		// into the InitStr before the Sentry boots, and the forwarder installs
		// (InstallEgress no-ops on an empty EgressHostAddr → fail-closed).
		Egress: EgressInit{EgressHostAddr: recorderAddr},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Delete(context.Background(), id) })

	if err := mgr.Start(ctx, id); err != nil {
		t.Fatalf("Start: %v", err)
	}

	select {
	case rec := <-records:
		if rec.err != nil {
			t.Fatalf("egress forwarder did not bridge the guest connect() to the host: %v", rec.err)
		}
		if rec.dst != probeDst {
			t.Fatalf("bridged dst = %v, want %v — the forwarder lost the real destination", rec.dst, probeDst)
		}
		if rec.payload != egressProbePayload {
			t.Fatalf("bridged payload = %q, want %q — the stream was not spliced end to end", rec.payload, egressProbePayload)
		}
		t.Logf("egress roundtrip: guest connect()→forwarder→bridge observed dst=%v src=%v payload=%q", rec.dst, rec.src, rec.payload)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for the egress forwarder to bridge the guest connect(): %v", ctx.Err())
	}
}

// TestEgressDenyVerdictRefusesSYN proves the v3 fail-fast contract on a real
// Sentry: a deny verdict from the bridge refuses the guest's connect() promptly
// (RST while the SYN is half-open, before any netstack endpoint exists) rather
// than establishing and then dropping the flow. The guest reports what its
// dial observed over a second, allowed flow.
func TestEgressDenyVerdictRefusesSYN(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sandbox boot requires linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("sandbox boot requires root (runsc + cgroup v2 delegation)")
	}
	cgroupPath, err := InitHostCgroup()
	if err != nil {
		t.Skipf("host cgroup v2 unavailable (%v) — needs a delegated cgroup v2 host", err)
	}

	const imageRef = "test://egress-deny-probe"
	deniedDst := netip.MustParseAddrPort("203.0.113.6:80")
	reportDst := netip.MustParseAddrPort("203.0.113.7:80")

	// Fake bridge: deny deniedDst, allow reportDst and capture its payload.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("deny recorder listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	reports := make(chan string, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				_, dst, _, err := egresswire.ReadEgressPreamble(r)
				if err != nil {
					return
				}
				if dst == deniedDst {
					_ = egresswire.WriteEgressVerdict(conn, false)
					return
				}
				if err := egresswire.WriteEgressVerdict(conn, true); err != nil {
					return
				}
				line, _ := r.ReadString('\n')
				reports <- strings.TrimSpace(line)
			}()
		}
	}()

	mgr := NewManager(ManagerConfig{
		StateDir:       t.TempDir(),
		RootDir:        t.TempDir(),
		ImageStore:     NewImageStore(t.TempDir()),
		HostCgroupPath: cgroupPath,
	})
	seedResidentImage(t, mgr.ImageStore(), imageRef)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	id := SandboxID("egrdenytest")
	_, err = mgr.Create(ctx, Spec{
		ID:      id,
		Image:   imageRef,
		Command: []string{"/server", egressDenyProbeArg, deniedDst.String(), reportDst.String()},
		Egress:  EgressInit{EgressHostAddr: ln.Addr().String()},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Delete(context.Background(), id) })

	if err := mgr.Start(ctx, id); err != nil {
		t.Fatalf("Start: %v", err)
	}

	select {
	case report := <-reports:
		if report != "denied-fast" {
			t.Fatalf("guest observed %q for the denied dial, want %q (denied-dial-succeeded = deny not enforced; denied-slow = hung instead of RST)", report, "denied-fast")
		}
		t.Logf("deny verdict: guest connect() to %v refused promptly, reported %q via allowed flow", deniedDst, report)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for the guest's deny report: %v", ctx.Err())
	}
}
