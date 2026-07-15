// SPDX-License-Identifier: AGPL-3.0-only

// Package egressfwd installs the in-Sentry egress forwarder for compute-worker
// sandboxes — the APO-713 data path that makes a worker fetch() actually leave
// the box. The core sentrystack wires lo+eth0 and then, if an embedder set the
// ForwarderInstaller hook, hands the stack to us to register a catch-all TCP
// forwarder. Every outbound SYN the worker issues loops back through eth0
// (promiscuous+spoofing), matches no bound listener, and is stolen by that
// forwarder, which bridges it to the host egress endpoint at
// InitStr.EgressHostAddr. With no forwarder installed the same SYN is RST in
// the stack (fail-closed) — see the core's egress_demux_test.go.
//
// The forwarder is armed ONLY in a binary that blank-imports this package
// (init() sets sentrystack.ForwarderInstaller). Production wiring
// (cmd/workerd-manager) and the Stage-0 spike each opt in explicitly; a
// standalone core consumer leaves the hook nil and gets a no-egress sandbox.
// The pure wire framing the forwarder and the host bridge share lives in the
// side-effect-free sibling package egresswire, so a consumer that only needs to
// read/write the preamble (the host bridge) does not transitively arm the
// forwarder by importing this package.
//
// This file carries no build tag so the package always has a buildable Go
// source on every platform; the forwarder itself is linux-only
// (forwarder_linux.go, install_linux.go).
package egressfwd
