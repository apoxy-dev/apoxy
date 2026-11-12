// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

// workerdBinEnv names a stock workerd binary. The test runs it directly (no
// sandbox) with the real resident dispatcher config, and skips when it is unset.
const workerdBinEnv = "APOXY_WORKERD_BIN"

// nullOutboundErr is part of the error workerd throws for an isolate with a
// null globalOutbound.
const nullOutboundErr = "not permitted to access the internet"

// dohAnswerIP is the A record the local DoH fake returns.
const dohAnswerIP = "192.0.2.1"

// egressProbeJS sends one kind of outbound traffic (?kind=) to the test
// upstreams and returns the result as JSON. Each probe stops after 3 s.
const egressProbeJS = `import { connect } from "cloudflare:sockets";

const enc = new TextEncoder();
const dec = new TextDecoder();

async function readOnce(readable) {
  const reader = readable.getReader();
  const { value } = await reader.read();
  reader.releaseLock();
  return value ? dec.decode(value) : "";
}

const probes = {
  async fetch(env) {
    const res = await fetch("http://" + env.HTTP_ADDR + "/?from=" + env.FROM);
    return await res.text();
  },
  async connect(env) {
    const s = connect(env.TCP_ADDR);
    const w = s.writable.getWriter();
    await w.write(enc.encode("from=" + env.FROM + "\n"));
    const line = await readOnce(s.readable);
    await s.close();
    return line;
  },
  async connectTLS(env) {
    const s = connect(env.TLS_ADDR, { secureTransport: "on" });
    await s.opened;
    await s.close();
    return "opened";
  },
  async websocket(env) {
    const ws = new WebSocket("ws://" + env.HTTP_ADDR + "/ws?from=" + env.FROM);
    return await new Promise((resolve, reject) => {
      ws.addEventListener("open", () => { ws.close(1000); resolve("open"); });
      ws.addEventListener("error", (e) => reject(new Error("websocket error: " + (e.message || e.error || "unknown"))));
    });
  },
  async nodeNet(env) {
    const net = await import("node:net");
    const [host, port] = env.TCP_ADDR.split(":");
    return await new Promise((resolve, reject) => {
      const s = net.connect({ host, port: Number(port) }, () => s.write("from=" + env.FROM + "-node\n"));
      s.on("data", (d) => { s.destroy(); resolve(String(d)); });
      s.on("error", reject);
    });
  },
  // node:dns sends its DoH query with the global fetch() and hides fetch errors.
  // Send the query to the local DoH fake with the real fetch and keep its error.
  async nodeDNS(env) {
    const dns = await import("node:dns");
    const seen = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const doh = new URL(String((input && input.url) || input));
      seen.push(doh.host);
      try {
        return await realFetch("http://" + env.HTTP_ADDR + "/dns-query?from=" + env.FROM + "&" + doh.searchParams, init);
      } catch (e) {
        seen.push(e.message);
        throw e;
      }
    };
    try {
      return JSON.stringify(await dns.promises.resolve4("example.com")) + " via " + seen.join("; ");
    } catch (e) {
      throw new Error(e.message + " via " + seen.join("; "));
    } finally {
      globalThis.fetch = realFetch;
    }
  },
};

export default {
  async fetch(req, env) {
    const kind = new URL(req.url).searchParams.get("kind");
    const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error("probe timed out")), 3000));
    try {
      const out = await Promise.race([probes[kind](env), timeout]);
      return Response.json({ ok: true, out: String(out) });
    } catch (e) {
      return Response.json({ ok: false, error: String((e && e.message) || e) });
    }
  },
};
`

// TestDispatcherEgressDisabled runs a real workerd with the resident dispatcher.
// "open" and egress-disabled "closed" send each traffic kind to the same upstreams, back to back.
func TestDispatcherEgressDisabled(t *testing.T) {
	bin := os.Getenv(workerdBinEnv)
	if bin == "" {
		t.Skipf("set %s to a workerd binary", workerdBinEnv)
	}

	up := startEgressUpstreams(t)

	open := revision("open-r1", "open", "sha256:o")
	open.Spec.Env = up.env("open")
	closed := revision("closed-r1", "closed", "sha256:c")
	closed.Spec.Env = up.env("closed")
	closed.Spec.Egress = &computev1alpha1.ServiceEgress{Disabled: true}

	manifest := esManifest()
	manifest.CompatibilityDate = "2025-06-01"
	manifest.CompatibilityFlags = []string{"nodejs_compat"}
	f := &fakeFetcher{manifest: manifest, modules: map[string][]byte{"index.js": []byte(egressProbeJS)}}
	store := NewStore(newResolverWithFetcher(newFakeClient(t, open, closed), f))
	store.setDemux(map[string]string{"open": "open-r1", "closed": "closed-r1"})

	ctl := NewControlServer(store)
	ctlAddr, err := ctl.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ctl.Serve(ctx) }()

	resident := startResidentWorkerd(t, bin, ctlAddr)

	kinds := []string{"fetch", "connect", "connectTLS", "websocket", "nodeNet", "nodeDNS"}
	for round := 0; round < 3; round++ {
		order := []string{"open", "closed"}
		if round%2 == 1 {
			order = []string{"closed", "open"}
		}
		for _, kind := range kinds {
			var prevEnd time.Time
			for _, svc := range order {
				if !prevEnd.IsZero() && time.Since(prevEnd) > 5*time.Second {
					t.Fatalf("round %d %s: second call starts %v after the first, want under 5s", round, kind, time.Since(prevEnd))
				}
				before := up.snapshot()
				res := callProbe(t, resident, svc, kind)
				after := up.snapshot()
				prevEnd = time.Now()
				t.Logf("round %d %s %s: ok=%v out=%q error=%q", round, svc, kind, res.OK, res.Out, res.Error)
				if svc == "closed" {
					assertBlocked(t, kind, res, before, after)
				} else {
					assertAllowed(t, kind, res, before, after)
				}
			}
		}
	}

	for _, m := range up.snapshot().markers {
		if strings.Contains(m, "from=closed") {
			t.Errorf("upstream saw traffic from the egress-disabled Service: %q", m)
		}
	}
}

func assertBlocked(t *testing.T, kind string, res probeResult, before, after upstreamSnapshot) {
	t.Helper()
	if res.OK || !strings.Contains(res.Error, nullOutboundErr) {
		t.Errorf("closed %s: ok=%v error=%q, want the null globalOutbound error", kind, res.OK, res.Error)
	}
	if after.accepts != before.accepts || len(after.markers) != len(before.markers) {
		t.Errorf("closed %s: upstreams changed from %+v to %+v, want no traffic", kind, before, after)
	}
}

func assertAllowed(t *testing.T, kind string, res probeResult, before, after upstreamSnapshot) {
	t.Helper()
	if strings.Contains(res.Error, nullOutboundErr) {
		t.Errorf("open %s: error=%q, want no null globalOutbound error", kind, res.Error)
	}
	switch kind {
	case "connectTLS":
		// The upstream is not a TLS server, so the handshake fails after the connection opens.
		if after.accepts.tls == before.accepts.tls {
			t.Errorf("open %s: TLS upstream accepted no connection", kind)
		}
	case "nodeDNS":
		// The probe also reports the DoH host node:dns asked for.
		if !res.OK || !strings.Contains(res.Out, dohAnswerIP) || !strings.Contains(res.Out, "cloudflare-dns.com") {
			t.Errorf("open %s: out=%q error=%q, want %s from the DoH fake", kind, res.Out, res.Error, dohAnswerIP)
		}
		if len(after.markers) == len(before.markers) {
			t.Errorf("open %s: DoH fake saw no request", kind)
		}
	default:
		if !res.OK {
			t.Errorf("open %s: error=%q, want success", kind, res.Error)
		}
		if len(after.markers) == len(before.markers) {
			t.Errorf("open %s: upstreams saw no request", kind)
		}
	}
}

type probeResult struct {
	OK    bool   `json:"ok"`
	Out   string `json:"out"`
	Error string `json:"error"`
}

func callProbe(t *testing.T, addr, service, kind string) probeResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/?kind="+kind, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("x-apoxy-service", service)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", service, kind, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: status %d body %q", service, kind, resp.StatusCode, body)
	}
	var res probeResult
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("%s %s: decode %q: %v", service, kind, body, err)
	}
	return res
}

// startResidentWorkerd runs workerd with the resident config and returns its
// HTTP address once the dispatcher health path answers.
func startResidentWorkerd(t *testing.T, bin, ctlAddr string) string {
	t.Helper()
	// Hold the port open and give the socket to workerd, so no other process can take it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	lnFile, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatalf("listener file: %v", err)
	}
	defer lnFile.Close()
	addr := ln.Addr().String()

	cfg, err := host.BuildResidentConfig(host.ResidentConfigInput{SocketAddr: addr, ManagerAddr: ctlAddr})
	if err != nil {
		t.Fatalf("BuildResidentConfig: %v", err)
	}
	path := filepath.Join(t.TempDir(), "resident.bin")
	if err := os.WriteFile(path, cfg, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var logs bytes.Buffer
	// "http" is the resident config's socket name; fd 3 is the first ExtraFiles entry.
	cmd := exec.Command(bin, "serve", "--binary", path, "--experimental", "--socket-fd", "http=3")
	cmd.ExtraFiles = []*os.File{lnFile}
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start workerd: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("workerd output:\n%s", logs.String())
		}
	})

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := client.Get("http://" + addr + "/__apoxy/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return addr
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("workerd health never answered on %s: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// egressUpstreams are the local probe targets: HTTP (fetch, WebSocket), line TCP
// (connect, node:net) and plain TCP for TLS. They count accepts and record markers.
type egressUpstreams struct {
	httpAddr, tcpAddr, tlsAddr string

	mu      sync.Mutex
	accepts acceptCounts
	markers []string
}

type acceptCounts struct{ http, tcp, tls int }

type upstreamSnapshot struct {
	accepts acceptCounts
	markers []string
}

func (u *egressUpstreams) snapshot() upstreamSnapshot {
	u.mu.Lock()
	defer u.mu.Unlock()
	return upstreamSnapshot{accepts: u.accepts, markers: append([]string(nil), u.markers...)}
}

func (u *egressUpstreams) mark(m string) {
	u.mu.Lock()
	u.markers = append(u.markers, m)
	u.mu.Unlock()
}

func (u *egressUpstreams) env(from string) []computev1alpha1.EnvVar {
	return []computev1alpha1.EnvVar{
		{Name: "FROM", Value: from},
		{Name: "HTTP_ADDR", Value: u.httpAddr},
		{Name: "TCP_ADDR", Value: u.tcpAddr},
		{Name: "TLS_ADDR", Value: u.tlsAddr},
	}
}

// countingListener counts each accepted connection in one of the counters.
type countingListener struct {
	net.Listener
	u     *egressUpstreams
	count func(*acceptCounts)
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.u.mu.Lock()
		l.count(&l.u.accepts)
		l.u.mu.Unlock()
	}
	return c, err
}

func startEgressUpstreams(t *testing.T) *egressUpstreams {
	t.Helper()
	u := &egressUpstreams{}
	listen := func(count func(*acceptCounts)) net.Listener {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		return countingListener{Listener: ln, u: u, count: count}
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mark(fmt.Sprintf("http %s from=%s", r.URL.Path, r.URL.Query().Get("from")))
		if r.URL.Path == "/dns-query" {
			w.Header().Set("Content-Type", "application/dns-json")
			_, _ = fmt.Fprintf(w, `{"Status":0,"Question":[{"name":"example.com","type":1}],"Answer":[{"name":"example.com","type":1,"TTL":60,"data":%q}]}`, dohAnswerIP)
			return
		}
		if r.URL.Path == "/ws" {
			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
			if err != nil {
				return
			}
			_ = c.Close(websocket.StatusNormalClosure, "")
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Listener = countingListener{Listener: srv.Listener, u: u, count: func(a *acceptCounts) { a.http++ }}
	srv.Start()
	t.Cleanup(srv.Close)
	u.httpAddr = srv.Listener.Addr().String()

	tcp := listen(func(a *acceptCounts) { a.tcp++ })
	u.tcpAddr = tcp.Addr().String()
	go serveConns(tcp, func(c net.Conn) {
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			return
		}
		u.mark("tcp " + strings.TrimSpace(line))
		_, _ = io.WriteString(c, "ok\n")
	})

	// The TLS probe only needs to reach a socket: read the ClientHello, then close.
	tls := listen(func(a *acceptCounts) { a.tls++ })
	u.tlsAddr = tls.Addr().String()
	go serveConns(tls, func(c net.Conn) { _, _ = c.Read(make([]byte, 1024)) })
	return u
}

func serveConns(ln net.Listener, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			handle(c)
		}()
	}
}
