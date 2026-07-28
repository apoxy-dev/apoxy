// SPDX-License-Identifier: AGPL-3.0-only

// Package netns wraps the LockOSThread + setns + restore dance for running
// code — most notably dials — inside a named network namespace. It exists so
// every consumer (the tunnel VTEP router, the workerd egress bridge) shares
// one carefully audited implementation of the thread-affinity rules instead of
// re-deriving them.
//
// All functions degrade to an error on non-linux platforms (the underlying
// syscalls return vishvananda/netns.ErrNotImplemented), so callers compile
// everywhere and fail closed where namespaces don't exist.
package netns

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/vishvananda/netns"
)

// EnsureNamed returns a handle to the named network namespace, creating and
// bind-mounting it if it does not exist. The bind mount lands in the
// library's /run/netns directory — callers that share or open namespaces by
// path must use /run/netns/<name>, NOT /var/run/netns, which is only
// equivalent on images where /var/run symlinks to /run. Requires
// CAP_SYS_ADMIN to create. The caller owns the returned handle.
func EnsureNamed(name string) (netns.NsHandle, error) {
	if ns, err := netns.GetFromName(name); err == nil {
		return ns, nil
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return netns.None(), fmt.Errorf("failed to get current netns: %w", err)
	}
	defer orig.Close()
	// NewNamed switches the calling thread into the new namespace.
	ns, err := netns.NewNamed(name)
	if err != nil {
		err = fmt.Errorf("failed to create netns %q: %w", name, err)
	}
	if restoreErr := netns.Set(orig); restoreErr != nil {
		// The thread is stuck in the wrong namespace: keep it locked so the
		// runtime retires it instead of scheduling other goroutines on it.
		return netns.None(), errors.Join(err, fmt.Errorf("failed to restore netns: %w", restoreErr))
	}
	runtime.UnlockOSThread()
	return ns, err
}

// Do runs fn with the calling OS thread switched to ns. A closed (None)
// handle runs fn in place. If restoring the original namespace fails, the
// thread is left locked so the runtime retires it rather than scheduling
// other goroutines on a thread stuck in the wrong namespace.
func Do(ns netns.NsHandle, fn func() error) error {
	if !ns.IsOpen() {
		return fn()
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("failed to get current netns: %w", err)
	}
	defer orig.Close()
	if err := netns.Set(ns); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("failed to enter netns: %w", err)
	}
	fnErr := fn()
	if err := netns.Set(orig); err != nil {
		// See EnsureNamed: retire the thread rather than unlocking it.
		return errors.Join(fnErr, fmt.Errorf("failed to restore netns: %w", err))
	}
	runtime.UnlockOSThread()
	return fnErr
}

// maxConcurrentDials bounds how many DialTimeout calls may hold a locked OS
// thread at once. Each in-flight dial pins one thread for up to its timeout
// (a goroutine locked to a thread parks the thread with it), and threads
// count toward the Go runtime's fatal 10000-thread limit — without a cap, a
// burst of dials to black-holed destinations (e.g. many workers fetching a
// dead-but-still-admitted overlay endpoint) can crash the whole process.
// 512 concurrent connects in flight is far above any sane fan-out while
// keeping the worst-case thread cost bounded.
const maxConcurrentDials = 512

var dialSlots = make(chan struct{}, maxConcurrentDials)

// DialTimeout dials addr with the socket created inside the network namespace
// bind-mounted at nsPath, then returns to the original namespace. The
// namespace is opened per call — deliberately uncached, since a cached handle
// silently black-holes if the namespace is recreated, while a per-call open
// (a few µs against a ms-scale connect) self-heals.
//
// addr should be a literal IP:port: the dial runs on a locked OS thread for
// the duration of the connect handshake (bounded by timeout), and a name
// would additionally run the resolver on that thread inside the namespace.
// At most maxConcurrentDials run at once; a call that cannot acquire a slot
// within timeout fails, so total latency is bounded by 2×timeout.
func DialTimeout(nsPath, network, addr string, timeout time.Duration) (net.Conn, error) {
	select {
	case dialSlots <- struct{}{}:
	default:
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case dialSlots <- struct{}{}:
		case <-t.C:
			return nil, fmt.Errorf("timed out waiting for a netns dial slot (%d in flight)", maxConcurrentDials)
		}
	}
	defer func() { <-dialSlots }()

	ns, err := netns.GetFromPath(nsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open netns %q: %w", nsPath, err)
	}
	defer ns.Close()
	var conn net.Conn
	if err := Do(ns, func() error {
		var derr error
		conn, derr = net.DialTimeout(network, addr, timeout)
		return derr
	}); err != nil {
		// Do fails after a successful dial when the namespace restore fails;
		// the established conn must not leak with it.
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	return conn, nil
}
