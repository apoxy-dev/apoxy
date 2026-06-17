package socksproxy_test

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/dpeckett/network"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	proxyclient "golang.org/x/net/proxy"

	"github.com/apoxy-dev/apoxy/pkg/socksproxy"
)

// freePort returns a 127.0.0.1 address whose port was free a moment ago.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

// silentTarget accepts TCP connections on 127.0.0.1 and then does nothing with
// them — never reads, writes, or closes. This models an upstream peer that has
// gone away half-open (no FIN), the production failure mode behind the leak.
func silentTarget(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()

	t.Cleanup(func() {
		_ = lis.Close()
		mu.Lock()
		for _, c := range held {
			_ = c.Close()
		}
		mu.Unlock()
	})

	return lis.Addr().String()
}

// echoTarget accepts TCP connections and echoes everything back.
func echoTarget(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	t.Cleanup(func() { _ = lis.Close() })
	return lis.Addr().String()
}

// streamingTarget accepts TCP connections and writes a byte every ~40ms until
// the peer goes away. It models a server that streams data to the client
// (download / SSE / server-push) while the client stays silent on the upload
// direction — the asymmetric-traffic case behind the one-directional reap
// regression. It never reads, so the client->target direction is idle.
func streamingTarget(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tick := time.NewTicker(40 * time.Millisecond)
				defer tick.Stop()
				for range tick.C {
					if _, err := c.Write([]byte("x")); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	t.Cleanup(func() { _ = lis.Close() })
	return lis.Addr().String()
}

// startProxy launches a ProxyServer on a free local port and returns its
// address. Both upstream and fallback are the host network; loopback targets
// (used by these tests) route through the fallback, yielding real *net.TCPConn
// endpoints on both ends.
func startProxy(t *testing.T, opts ...socksproxy.Option) string {
	t.Helper()
	addr := freePort(t)
	srv := socksproxy.NewServer(addr, network.Host(), network.Host(), opts...)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.ListenAndServe(ctx) }()
	t.Cleanup(func() {
		_ = srv.Close()
		cancel()
	})

	// Wait until the listener is accepting.
	require.Eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond, "socks proxy never started listening")

	return addr
}

// dialThroughProxy performs a SOCKS5 CONNECT to targetAddr and returns the
// established connection. The caller is responsible for closing it.
func dialThroughProxy(t *testing.T, socksAddr, targetAddr string) net.Conn {
	t.Helper()
	d, err := proxyclient.SOCKS5("tcp", socksAddr, nil, proxyclient.Direct)
	require.NoError(t, err)
	c, err := d.Dial("tcp", targetAddr)
	require.NoError(t, err)
	return c
}

func activeConns() float64 { return testutil.ToFloat64(socksproxy.SocksConnectionsActive) }

// quiescentBase returns the active-connection gauge once it has stopped moving.
// SocksConnectionsActive is a process-global shared by every test in this
// package; a prior test's connections may still be draining when the next one
// starts. Waiting for two equal consecutive reads pins a stable baseline so the
// delta assertions below are order-independent.
func quiescentBase(t *testing.T) float64 {
	t.Helper()
	var last float64
	first := true
	require.Eventually(t, func() bool {
		v := activeConns()
		if !first && v == last {
			return true
		}
		first = false
		last = v
		return false
	}, 10*time.Second, 100*time.Millisecond, "active-connection gauge never settled")
	return last
}

// TestHalfOpenConnsAreReaped is the regression test for the production leak: a
// fleet of connections whose peers fall silent must be force-closed once they
// exceed the idle timeout, returning the active-connection gauge and goroutine
// count to baseline. On the pre-fix code (no idle deadline) these connections
// pin forever — see TestWedgedConnsLeakWithoutGuards for the A/B.
func TestHalfOpenConnsAreReaped(t *testing.T) {
	const (
		n    = 20
		idle = 600 * time.Millisecond
	)

	target := silentTarget(t)
	// Keepalive off so the idle deadline is the sole (deterministic) reaper:
	// loopback peers are always alive, so TCP keepalive would never fire here.
	socksAddr := startProxy(t, socksproxy.WithIdleTimeout(idle), socksproxy.WithKeepAlive(false, 0))

	base := quiescentBase(t)
	baseGoroutines := runtime.NumGoroutine()

	// Establish all n connections concurrently. Sequential SOCKS handshakes can
	// take longer than the (deliberately short) idle window under -race load, so
	// early connections would reap before the last is dialed and the gauge would
	// never reach n. Dialing in parallel starts every idle timer within a tight
	// window. require lives on the test goroutine; the workers only record errors.
	conns := make([]net.Conn, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d, err := proxyclient.SOCKS5("tcp", socksAddr, nil, proxyclient.Direct)
			if err != nil {
				errs[i] = err
				return
			}
			conns[i], errs[i] = d.Dial("tcp", target)
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		require.NoError(t, errs[i])
	}
	t.Cleanup(func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	})

	// All n connections are established and idle.
	require.Eventually(t, func() bool { return activeConns()-base == n }, 3*time.Second, 20*time.Millisecond,
		"expected %d active connections, got %v", n, activeConns()-base)

	// After the idle timeout elapses with zero bytes flowing, every wedged
	// connection must be reaped back to baseline.
	require.Eventually(t, func() bool { return activeConns()-base == 0 }, 5*time.Second, 50*time.Millisecond,
		"idle connections were not reaped; active delta still %v", activeConns()-base)

	// Goroutines (≈2 per wedged conn) must drain back toward baseline too.
	require.Eventually(t, func() bool { return runtime.NumGoroutine() <= baseGoroutines+4 }, 5*time.Second, 50*time.Millisecond,
		"goroutines did not return to baseline: base=%d now=%d", baseGoroutines, runtime.NumGoroutine())
}

// TestWedgedConnsLeakWithoutGuards proves the scenario genuinely wedges
// go-socks5 and that the lifecycle guards are load-bearing: with idle, max
// lifetime, and keepalive all disabled (the pre-fix behavior) the connections
// are never reaped while the server runs. It then confirms ProxyServer.Close
// reaps them at shutdown regardless.
func TestWedgedConnsLeakWithoutGuards(t *testing.T) {
	const n = 15

	target := silentTarget(t)
	addr := freePort(t)
	srv := socksproxy.NewServer(addr, network.Host(), network.Host(),
		socksproxy.WithIdleTimeout(0), socksproxy.WithMaxLifetime(0), socksproxy.WithKeepAlive(false, 0))

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.ListenAndServe(ctx) }()
	t.Cleanup(cancel)

	require.Eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond)

	base := quiescentBase(t)
	conns := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		conns = append(conns, dialThroughProxy(t, addr, target))
	}
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})

	require.Eventually(t, func() bool { return activeConns()-base == n }, 3*time.Second, 20*time.Millisecond)

	// With every guard disabled, the wedged connections must NOT be reaped:
	// the gauge holds at n across a window comfortably longer than any test
	// idle timeout. (This is exactly the production leak.)
	require.Never(t, func() bool { return activeConns()-base != n }, 1500*time.Millisecond, 100*time.Millisecond,
		"connections were reaped without any guard enabled — scenario does not reproduce the leak")

	// Shutdown must reap them even though no per-conn guard is enabled.
	require.NoError(t, srv.Close())
	require.Eventually(t, func() bool { return activeConns()-base == 0 }, 5*time.Second, 50*time.Millisecond,
		"ProxyServer.Close did not reap in-flight connections; active delta still %v", activeConns()-base)
}

// TestActiveTrafficNotReaped proves the idle deadline rolls forward on real
// byte activity — an actively-used connection is never killed — and that normal
// SOCKS proxying still works end to end. Once traffic stops, the connection is
// reaped as expected.
func TestActiveTrafficNotReaped(t *testing.T) {
	const idle = 400 * time.Millisecond

	target := echoTarget(t)
	socksAddr := startProxy(t, socksproxy.WithIdleTimeout(idle), socksproxy.WithKeepAlive(false, 0))

	base := quiescentBase(t)
	c := dialThroughProxy(t, socksAddr, target)
	t.Cleanup(func() { _ = c.Close() })

	require.Eventually(t, func() bool { return activeConns()-base == 1 }, 3*time.Second, 20*time.Millisecond)

	// Exchange data for ~3x the idle window, writing more frequently than the
	// timeout. Every round-trip must succeed and the connection must stay up.
	payload := []byte("ping")
	buf := make([]byte, len(payload))
	deadline := time.Now().Add(3 * idle)
	rounds := 0
	for time.Now().Before(deadline) {
		require.NoError(t, c.SetDeadline(time.Now().Add(2*time.Second)))
		_, err := c.Write(payload)
		require.NoError(t, err)
		_, err = io.ReadFull(c, buf)
		require.NoError(t, err)
		require.Equal(t, payload, buf)
		rounds++
		require.Equal(t, float64(1), activeConns()-base, "active connection was reaped mid-transfer")
		time.Sleep(idle / 4)
	}
	require.Greater(t, rounds, 3)

	// Now go quiet: with no activity beyond the idle window, it must be reaped.
	require.Eventually(t, func() bool { return activeConns()-base == 0 }, 5*time.Second, 50*time.Millisecond,
		"idle connection was not reaped after traffic stopped; active delta %v", activeConns()-base)
}

// TestOneDirectionalStreamNotReaped is the regression test for the
// per-direction deadline bug: a connection that is actively streaming in ONE
// direction (server pushes data, client never sends) must NOT be reaped at the
// idle timeout. The fix arms the deadline in both directions on any activity,
// so the active download keeps the otherwise-silent read side alive. On the
// buggy per-direction code the downstream read deadline fired at idle and tore
// down the live stream, so this test would fail (the client's Read errors when
// both ends close).
func TestOneDirectionalStreamNotReaped(t *testing.T) {
	const idle = 400 * time.Millisecond

	target := streamingTarget(t)
	// Keepalive off so the idle deadline is the only thing that could reap it.
	socksAddr := startProxy(t, socksproxy.WithIdleTimeout(idle), socksproxy.WithKeepAlive(false, 0))

	base := quiescentBase(t)
	c := dialThroughProxy(t, socksAddr, target)
	t.Cleanup(func() { _ = c.Close() })

	require.Eventually(t, func() bool { return activeConns()-base == 1 }, 3*time.Second, 20*time.Millisecond)

	// Read the server's stream for ~3x the idle window WITHOUT ever writing.
	// Every read must succeed and the connection must stay up the whole time.
	buf := make([]byte, 1)
	deadline := time.Now().Add(3 * idle)
	reads := 0
	for time.Now().Before(deadline) {
		require.NoError(t, c.SetReadDeadline(time.Now().Add(2*time.Second)))
		n, err := c.Read(buf)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		reads++
		require.Equal(t, float64(1), activeConns()-base, "active one-directional stream was reaped mid-transfer")
	}
	require.Greater(t, reads, 3)
}
