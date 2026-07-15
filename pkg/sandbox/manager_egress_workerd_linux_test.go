//go:build linux && acceptance

package sandbox

// APO-713 Stage-0 spike, tier 2 (real workerd): the definitive close of the
// §2.8 owed question — does a real workerd fetch() issue an ordinary connect()
// the in-Sentry netstack catches, with globalOutbound pointed at the internet
// Network service (real getaddrinfo + socket/connect, NOT a proxy)? Tier 1
// (manager_egress_linux_test.go) proved a Go guest's connect() is caught; the
// tests here prove workerd's is, AND validate the exact globalOutbound config
// form the dispatcher uses (pkg/workerd/host/dispatcher.js), in BOTH shapes:
//
//   - TestWorkerdEgressDialsThrough: globalOutbound as a capnp Worker field
//     (`globalOutbound = "internet"`) on a standalone worker.
//   - TestWorkerLoaderGlobalOutboundDialsThrough: globalOutbound as a WorkerLoader
//     JS field (`globalOutbound: env.GLOBAL_OUTBOUND`, a Network service passed
//     via a service binding) on a runtime-loaded isolate — the precise mechanism
//     dispatcher.js exercises. The isolate is loaded inline from the callback, so
//     this needs no manager control channel.
//
// Both boot a stock workerd (the acceptance image) whose fetch handler dials a
// NON-LOCAL literal IP on every inbound request. globalOutbound is an explicit
// `internet` Network service — the real-socket egress path, not an external/
// unixSocket proxy (the §2.8 foot-gun). EgressHostAddr points at a recorder (like
// tier 1); an inbound request drives the worker's fetch(); the recorder must
// observe a connect() to the real destination. The SYN is stolen by the forwarder
// before it leaves, so the target IP is never actually contacted.
//
// HOW IT RUNS: like the other real-runsc tests these need a privileged Linux host
// with runsc-capable gVisor + cgroup v2, and a stock workerd image via
// APOXY_WORKERD_ACCEPTANCE_IMAGE; they self-skip otherwise. Build/run static
// (CGO_ENABLED=0) as root on a cgroup-v2 host, with -tags acceptance.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	// Blank import arms the forwarder (sentrystack.ForwarderInstaller); the
	// preamble decoder is the side-effect-free egresswire package.
	_ "github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack/egressfwd"
	"github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack/egresswire"
)

// workerdEgressConfigTmpl is a minimal single-worker workerd config. The socket
// address is a %s placeholder (a capnp string). globalOutbound points at the
// `internet` Network service — workerd issues real socket()/connect() for the
// worker's fetch(), which the in-Sentry netstack catches. A broad allow set
// keeps workerd's own network filter from pre-empting the dial before the
// syscall (the bridge, not workerd, is the egress authority).
const workerdEgressConfigTmpl = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "main", worker = .w),
    (name = "internet", network = (allow = ["public", "private", "local", "network"])),
  ],
  sockets = [ (name = "http", address = %s, http = (), service = "main") ],
);
const w :Workerd.Worker = (
  compatibilityDate = "2025-06-01",
  modules = [ (name = "worker.js", esModule = embed "worker.js") ],
  globalOutbound = "internet",
);
`

// workerdEgressWorkerTmpl fetches a non-local literal IP (%s) on every inbound
// request. The literal avoids DNS (no resolver forwarder yet); the connect()'s
// SYN is stolen by the egress forwarder, so the address is never really dialed.
const workerdEgressWorkerTmpl = `export default {
  async fetch(req) {
    try { await fetch("http://%s/"); } catch (e) {}
    return new Response("done\n");
  }
};
`

// workerdLoaderConfigTmpl is the dispatcher-analog: one worker with a WorkerLoader
// binding plus a GLOBAL_OUTBOUND *service* binding to the `internet` Network
// service. It loads a customer isolate at runtime and hands it that binding as its
// globalOutbound — the exact shape BuildResidentConfig emits and dispatcher.js
// consumes. `experimental` enables workerLoader.
const workerdLoaderConfigTmpl = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "main", worker = .w),
    (name = "internet", network = (allow = ["public", "private", "local", "network"])),
  ],
  sockets = [ (name = "http", address = %s, http = (), service = "main") ],
);
const w :Workerd.Worker = (
  compatibilityDate = "2025-06-01",
  compatibilityFlags = ["experimental"],
  modules = [ (name = "worker.js", esModule = embed "worker.js") ],
  bindings = [
    (name = "LOADER", workerLoader = ()),
    (name = "GLOBAL_OUTBOUND", service = "internet"),
  ],
);
`

// workerdLoaderWorkerTmpl mirrors dispatcher.js's WorkerLoader path: it loads an
// isolate from an inline callback (no manager needed) and, crucially, sets that
// isolate's globalOutbound to env.GLOBAL_OUTBOUND — the Network-service Fetcher.
// The loaded isolate fetches the non-local literal %s; the connect() must reach
// the forwarder. The modules map uses the WorkerLoader runtime shape
// ({name: {js: source}}), the same shape the manager serves.
const workerdLoaderWorkerTmpl = `export default {
  async fetch(req, env) {
    const w = env.LOADER.get("probe", async () => ({
      compatibilityDate: "2025-06-01",
      mainModule: "m.js",
      modules: { "m.js": { js: "export default { async fetch() { try { await fetch('http://%s/'); } catch (e) {} return new Response('done'); } };" } },
      globalOutbound: env.GLOBAL_OUTBOUND,
    }));
    return await w.getEntrypoint().fetch(req);
  }
};
`

// startWorkerdEgressRecorder stands in for the host egress bridge: it accepts
// every bridged flow, decodes the preamble to recover the real dst, and records
// it. Multi-connection because workerd opens loopback flows of its own at boot
// (seen in the resident health run) in addition to the worker's fetch().
func startWorkerdEgressRecorder(t *testing.T) (string, func() []netip.AddrPort) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("egress recorder listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var dsts []netip.AddrPort
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, dst, err := egresswire.ReadEgressPreamble(bufio.NewReader(conn))
				if err != nil {
					return
				}
				mu.Lock()
				dsts = append(dsts, dst)
				mu.Unlock()
			}()
		}
	}()
	return ln.Addr().String(), func() []netip.AddrPort {
		mu.Lock()
		defer mu.Unlock()
		return append([]netip.AddrPort(nil), dsts...)
	}
}

// runWorkerdEgressProbe boots stock workerd with configCapnp + workerJS staged
// beside each other (so capnp `embed` resolves), points EgressHostAddr at a
// recorder, drives one inbound request, and asserts the worker's fetch() to
// probeDst was caught by the in-Sentry forwarder and bridged to the recorder with
// the real dst. It is the shared body of the two globalOutbound-form tests.
func runWorkerdEgressProbe(t *testing.T, id SandboxID, configCapnp, workerJS string, probeDst netip.AddrPort) {
	t.Helper()
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
	img := os.Getenv("APOXY_WORKERD_ACCEPTANCE_IMAGE")
	if img == "" {
		t.Skip("set APOXY_WORKERD_ACCEPTANCE_IMAGE to a stock workerd OCI image")
	}

	recorderAddr, observedDsts := startWorkerdEgressRecorder(t)

	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "worker.js"), []byte(workerJS), 0o644); err != nil {
		t.Fatalf("staging worker.js: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.capnp"), []byte(configCapnp), 0o644); err != nil {
		t.Fatalf("staging config.capnp: %v", err)
	}

	mgr := NewManager(ManagerConfig{
		StateDir:       t.TempDir(),
		RootDir:        t.TempDir(),
		ImageStore:     NewImageStore(t.TempDir()),
		HostCgroupPath: cgroupPath,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	inst, err := mgr.Create(ctx, Spec{
		ID:      id,
		Image:   img,
		Command: []string{"/usr/bin/workerd", "serve", "/etc/workerd/config.capnp", "--experimental"},
		Mounts: []Mount{
			{Source: cfgDir, Destination: "/etc/workerd", Type: "bind", Options: []string{"ro"}},
		},
		// EgressHostAddr => the recorder receives every bridged outbound flow.
		Egress: EgressInit{EgressHostAddr: recorderAddr},
		// Front the worker's *:8080 socket so we can drive an inbound request.
		InboundListenAddr: "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_ = mgr.Kill(context.Background(), id)
		_ = mgr.Delete(context.Background(), id)
	})
	if err := mgr.Start(ctx, id); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Drive an inbound request; the handler awaits fetch() before responding,
	// so the outbound connect() is issued during this call.
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", inst.InboundSocket)
			},
		},
	}
	resp, err := client.Get("http://worker/")
	if err != nil {
		t.Fatalf("inbound GET through sandbox: %v", err)
	}
	_ = resp.Body.Close()

	// The worker's fetch() connect() must have been caught by the in-Sentry
	// forwarder and bridged to the recorder with the real dst.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, d := range observedDsts() {
			if d == probeDst {
				t.Logf("workerd fetch() connect() caught by the in-Sentry forwarder: dst=%v", d)
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("workerd fetch() to %v never reached the egress forwarder; observed dsts=%v", probeDst, observedDsts())
}

// TestWorkerdEgressDialsThrough validates the capnp `globalOutbound = "internet"`
// Worker-field form on a standalone worker.
func TestWorkerdEgressDialsThrough(t *testing.T) {
	// A non-local literal (TEST-NET-3, RFC 5737): reaching it needs the eth0
	// default route, so the forwarder steals it; the literal avoids DNS.
	probeDst := netip.MustParseAddrPort("203.0.113.5:80")
	cfg := fmt.Sprintf(workerdEgressConfigTmpl, `"*:8080"`)
	worker := fmt.Sprintf(workerdEgressWorkerTmpl, probeDst.String())
	runWorkerdEgressProbe(t, "wdegress", cfg, worker, probeDst)
}

// TestWorkerLoaderGlobalOutboundDialsThrough validates the WorkerLoader JS
// `globalOutbound: env.GLOBAL_OUTBOUND` form (a Network service passed via a
// service binding) on a runtime-loaded isolate — the exact mechanism dispatcher.js
// uses. This is the airtight close on the resident egress path: not just "workerd
// can egress structurally" but "the dispatcher's specific globalOutbound wiring
// egresses structurally".
func TestWorkerLoaderGlobalOutboundDialsThrough(t *testing.T) {
	probeDst := netip.MustParseAddrPort("203.0.113.6:80")
	cfg := fmt.Sprintf(workerdLoaderConfigTmpl, `"*:8080"`)
	worker := fmt.Sprintf(workerdLoaderWorkerTmpl, probeDst.String())
	runWorkerdEgressProbe(t, "wdloader", cfg, worker, probeDst)
}
