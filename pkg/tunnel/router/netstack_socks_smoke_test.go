package router_test

// Integration smoke: the real production user-mode router (NewNetstackRouter —
// the router the tunnel client runs) brings up the patched socksproxy and
// proxies a request through its full lifecycle: connTrackingListener.Accept
// (keepalive + conn tracking + deadline guard), the wrappers (deadline arming
// on Read/Write), the dialer, and ProxyServer.Close (in-flight reaping) on
// router shutdown. Loopback targets exercise the host-fallback path end to end
// without requiring a live tunnel. Runs natively on darwin/linux.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	proxyclient "golang.org/x/net/proxy"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func TestNetstackRouter_SocksProxiesThroughRealRouter(t *testing.T) {
	// NewNetstackRouter registers gVisor TCP-stats collectors on the global
	// controller-runtime registry; use a fresh one so repeated runs / other
	// router-using tests in this package don't collide. Restore the original on
	// cleanup so this mutation doesn't leak into other tests in the binary
	// (otherwise a second run re-registers the same collectors and panics with
	// "duplicate metrics collector registration attempted").
	origRegistry := crmetrics.Registry
	crmetrics.Registry = prometheus.NewRegistry()
	t.Cleanup(func() { crmetrics.Registry = origRegistry })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Backend the SOCKS request will reach via the host fallback path.
	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Hello, world!")
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = backend.Serve(ln) }()
	t.Cleanup(func() { _ = backend.Close() })

	socksAddr := freeLoopbackAddr(t)
	r, err := router.NewNetstackRouter(router.WithSocksListenAddr(socksAddr))
	require.NoError(t, err)
	go func() { _ = r.Start(ctx) }()
	t.Cleanup(func() { _ = r.Close() })

	// Wait for the router's SOCKS proxy to accept connections.
	require.Eventually(t, func() bool {
		c, derr := net.DialTimeout("tcp", socksAddr, 200*time.Millisecond)
		if derr != nil {
			return false
		}
		_ = c.Close()
		return true
	}, 10*time.Second, 50*time.Millisecond, "router SOCKS proxy never came up")

	// Proxy a request through the patched SOCKS server inside the real router.
	dialer, err := proxyclient.SOCKS5("tcp", socksAddr, nil, proxyclient.Direct)
	require.NoError(t, err)
	client := &http.Client{Transport: &http.Transport{Dial: dialer.Dial}, Timeout: 5 * time.Second}

	resp, err := client.Get("http://" + ln.Addr().String())
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "Hello, world!\n", string(body))
}
