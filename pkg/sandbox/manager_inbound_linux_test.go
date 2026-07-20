//go:build linux

package sandbox

// APO-694 end-to-end ingress roundtrip: boot a REAL runsc/gVisor sandbox whose
// guest runs a long-lived HTTP server bound inside the in-Sentry stack, then
// drive an inbound HTTP request from the host through the AF_UNIX socket and
// the in-Sentry inbound forwarder into that server. This is the first thing
// that exercises the whole inbound path against a real Sentry — Create→Start
// (incl. the InitStr InboundFDIndex hop and installInboundForwarder) →
// readiness gate → host dial → splice → guest. The pure-pkg/tcpip
// inbound_demux_test.go proves the demux mechanism in isolation; this proves
// the wiring end to end.
//
// HOW IT RUNS: this needs a privileged Linux host with runsc-capable gVisor
// (the dev Kind cluster's worker pod, or an equivalent box) and cgroup v2.
// It self-skips elsewhere. The resident server is THIS test binary re-exec'd
// with residentServeArg (so no external image or go toolchain is needed at
// run time) — which means the test binary must be STATICALLY linked to run in
// the bare guest rootfs: build/run it with CGO_ENABLED=0. The guest binds its
// listener via socket/bind/listen, which the sentrystack PluginStack must be
// allowed to service (gvisor fork branch clrk-plugin-seccomp-socket).

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// residentServeArg is the argv[1] sentinel that turns this test binary into
// the in-sandbox resident HTTP server. The guest entrypoint is
// "/server <residentServeArg> <listenAddr>".
const residentServeArg = "clrk-inbound-test-serve"

// TestMain triages how the process was invoked, in priority order:
//  1. runsc subcommand re-exec (boot/gofer/start/...) — hand off to gVisor.
//  2. resident-server re-exec inside the guest — serve HTTP and never return.
//  3. egress-probe re-exec inside the guest — dial outbound and never return
//     (manager_egress_linux_test.go).
//  4. the normal test run — install the child reaper, then run the tests.
//
// Cases 1–3 must be checked before the testing framework parses flags
// (which happens inside m.Run()), since their argv is not test flags.
func TestMain(m *testing.M) {
	DispatchRunsc()

	if len(os.Args) > 2 && os.Args[1] == residentServeArg {
		runResidentServer(os.Args[2]) // never returns
	}
	if len(os.Args) > 2 && os.Args[1] == egressProbeArg {
		runEgressProbe(os.Args[2]) // never returns
	}
	if len(os.Args) > 3 && os.Args[1] == egressDenyProbeArg {
		runEgressDenyProbe(os.Args[2], os.Args[3]) // never returns
	}

	// The test process drives runsc subprocesses and re-parents their Sentry/
	// gofer children; without reaping, teardown's `runsc wait` hangs ~2min on
	// zombie liveness probes.
	startTestChildReaper()
	os.Exit(m.Run())
}

// runResidentServer is the in-guest workload: a minimal HTTP server bound on
// addr inside the in-Sentry netstack. Stands in for resident workerd (the real
// runtime is APO-696). Never returns on success.
func runResidentServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "pong")
	})
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "resident server on %s: %v\n", addr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestInboundRoundtrip(t *testing.T) {
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

	const (
		imageRef   = "test://resident-server"
		listenAddr = "127.0.0.1:8080"
	)
	mgr := NewManager(ManagerConfig{
		StateDir:       t.TempDir(),
		RootDir:        t.TempDir(),
		ImageStore:     NewImageStore(t.TempDir()),
		HostCgroupPath: cgroupPath,
	})
	// Pre-seed the image cache with a rootfs containing this very test binary
	// as /server, so EnsureImage returns it without any registry pull.
	seedResidentImage(t, mgr.ImageStore(), imageRef)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	id := SandboxID("inbtest")
	inst, err := mgr.Create(ctx, Spec{
		ID:      id,
		Image:   imageRef,
		Command: []string{"/server", residentServeArg, listenAddr},
		// The drive-seam: must be set on the Spec so Create seals it into the
		// InitStr before the Sentry boots. (APO-694 2a.)
		InboundListenAddr: listenAddr,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Delete(context.Background(), id) })

	// Start blocks on the inbound readiness gate, so a clean return means the
	// resident server is already accepting through the forwarder.
	if err := mgr.Start(ctx, id); err != nil {
		t.Fatalf("Start (incl. inbound readiness): %v", err)
	}
	if inst.InboundSocket == "" {
		t.Fatal("InboundSocket empty after Start")
	}

	// THE roundtrip: host → {id}.in.sock → in-Sentry inbound forwarder →
	// gonet dial into the guest's 127.0.0.1:8080 listener → "pong".
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", inst.InboundSocket)
			},
		},
	}
	resp, err := client.Get("http://resident/")
	if err != nil {
		t.Fatalf("inbound GET through sandbox: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if got := string(body); got != "pong" {
		t.Fatalf("resident server returned %q, want %q", got, "pong")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Teardown unlinks the inbound socket (it's a sibling of the state dir, so
	// the state-dir RemoveAll doesn't catch it — removeInboundSock must).
	sock := inst.InboundSocket
	if err := mgr.Kill(ctx, id); err != nil {
		t.Logf("Kill (best effort): %v", err)
	}
	if err := mgr.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("inbound socket %s not unlinked after Delete (stat err=%v)", sock, err)
	}
}

// seedResidentImage assembles a minimal rootfs whose /server is this test
// binary, and injects it into the ImageStore cache so Create finds it without
// a registry pull. White-box: it pokes the unexported cache directly.
func seedResidentImage(t *testing.T, is *ImageStore, ref string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locating test binary: %v", err)
	}
	rootfs := t.TempDir()
	dst := filepath.Join(rootfs, "server")
	if err := copyExecutable(exe, dst); err != nil {
		t.Fatalf("staging resident server into rootfs: %v", err)
	}
	is.mu.Lock()
	is.images[ref] = &ImageInfo{RootFS: rootfs, Entrypoint: []string{"/server"}}
	is.mu.Unlock()
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// startTestChildReaper installs a SIGCHLD-driven reaper so re-parented Sentry/
// gofer zombies don't wedge `runsc wait`. Mirrors the consumer-side reaper
// (cmd/worker, workerd-host): it consults ShouldSkipReap so it never races the
// core's own cmd.Wait() on the direct runsc subprocesses.
func startTestChildReaper() {
	ch := make(chan os.Signal, 16)
	signal.Notify(ch, unix.SIGCHLD)
	go func() {
		for range ch {
			for {
				pid, err := peekReapablePid()
				if err != nil || pid <= 0 {
					break
				}
				if ShouldSkipReap(pid) {
					break
				}
				var status unix.WaitStatus
				reaped, err := unix.Wait4(pid, &status, unix.WNOHANG, nil)
				if err != nil || reaped <= 0 {
					break
				}
			}
		}
	}()
}

// peekReapablePid returns the PID of the next reapable child without consuming
// its zombie status. Raw waitid via Syscall6 because x/sys/unix opaque-bytes
// the si_pid field; Linux's siginfo_t lays si_pid at byte offset 16 (after
// si_signo / si_errno / si_code / _pad), stable across amd64/arm64.
func peekReapablePid() (int, error) {
	var buf [128]byte
	_, _, errno := unix.Syscall6(
		unix.SYS_WAITID,
		uintptr(unix.P_ALL),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unix.WEXITED|unix.WNOHANG|unix.WNOWAIT),
		0, 0,
	)
	if errno != 0 {
		if errno == unix.ECHILD {
			return 0, nil
		}
		return 0, errno
	}
	pid := int32(buf[16]) | int32(buf[17])<<8 | int32(buf[18])<<16 | int32(buf[19])<<24
	return int(pid), nil
}
