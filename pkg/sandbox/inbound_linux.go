//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"
)

// inboundReadyTimeout bounds how long Start waits for the in-sandbox resident
// server to begin accepting before giving up. A resident workerd binds its
// listener within a few hundred ms of guest start; 5s leaves generous margin
// without letting a wedged server hang Start indefinitely.
const inboundReadyTimeout = 5 * time.Second

// openInboundListener binds a host AF_UNIX listening socket at path and returns
// a *os.File for it to donate to the runsc-start subprocess via cmd.ExtraFiles.
// The Sentry's PluginStack.PreInit surfaces that fd, runsc ships it across the
// urpc boundary, and the in-Sentry inbound forwarder accepts on it. Host-side
// callers (an Envoy upstream cluster, the backplane bridge, or an acceptance
// test) reach the in-sandbox resident server by dialing path.
//
// Ownership: the returned *os.File is the caller's to Close once it has been
// handed to the start subprocess — the Sentry holds its own dup by then, which
// keeps the socket alive and accepting. The path is intentionally NOT unlinked
// when the host's own listener fd is dropped (SetUnlinkOnClose(false)), so it
// stays connectable for the sandbox's lifetime; remove it at teardown.
func openInboundListener(path string) (*os.File, error) {
	// Clear any stale socket file left by a previous incarnation of this id.
	_ = os.Remove(path)

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen unix %q: %w", path, err)
	}
	// Keep the path after we drop our listener fd: the donated dup (held by the
	// Sentry) keeps the bound socket alive and accepting. We unlink explicitly
	// at teardown instead.
	ln.SetUnlinkOnClose(false)
	defer ln.Close()

	f, err := ln.File()
	if err != nil {
		return nil, fmt.Errorf("dup inbound listener fd for %q: %w", path, err)
	}
	return f, nil
}

// removeInboundSock unlinks the inbound socket file for a sandbox at teardown.
// No-op when the sandbox never enabled ingress (the file won't exist). The
// path is a sibling of the per-sandbox state dir, not inside it, so the
// teardown RemoveAll(stateDir/id) doesn't catch it — hence the explicit unlink.
func removeInboundSock(stateDir string, id SandboxID) {
	if err := os.Remove(InboundSockPath(stateDir, id)); err != nil && !os.IsNotExist(err) {
		slog.Warn("Failed to remove inbound socket",
			slog.String("sandbox.id", string(id)), slog.Any("error", err))
	}
}

// waitInboundReady blocks until the in-sandbox resident server behind the
// AF_UNIX socket at sockPath is accepting connections, or timeout elapses.
//
// It probes by dialing the socket and watching what the in-Sentry inbound
// forwarder does with the connection (see handleInbound): while the guest
// server isn't listening yet, the forwarder's gonet dial to the guest fails
// and it closes the probe connection without sending anything — a fast EOF.
// Once the guest is up, the splice is established and the idle connection
// stays open, so the probe's short read blocks to its deadline. "Read timed
// out, no EOF" is therefore the readiness signal; a fast EOF/reset means not
// ready yet, and we retry.
//
// This is a deliberately minimal gate — enough to keep host traffic from being
// routed before the server binds. A real health signal (an HTTP/gRPC readiness
// probe, or a guest-side ready notification) is APO-696.
func waitInboundReady(ctx context.Context, sockPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		ready, err := probeInboundOnce(ctx, sockPath)
		if ready {
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	if lastErr == nil {
		lastErr = errors.New("deadline exceeded")
	}
	return fmt.Errorf("inbound server not ready after %s: %w", timeout, lastErr)
}

// probeInboundOnce performs one readiness probe through the inbound socket.
// Returns (true, nil) when the connection is alive (guest accepted), and
// (false, err) when the forwarder closed it because the guest dial failed or
// the socket isn't connectable yet.
func probeInboundOnce(ctx context.Context, sockPath string) (bool, error) {
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := d.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// Give the forwarder a beat to dial the guest, then read one byte. A
	// resident HTTP server sends nothing unsolicited, so a healthy splice
	// blocks here (i/o timeout = ready); a failed guest dial shows as a quick
	// EOF/reset (not ready).
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	var buf [1]byte
	_, err = conn.Read(buf[:])
	if err == nil {
		return true, nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true, nil
	}
	if errors.Is(err, io.EOF) {
		return false, errors.New("forwarder closed probe (guest not listening yet)")
	}
	return false, err
}
