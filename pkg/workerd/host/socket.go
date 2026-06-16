// SPDX-License-Identifier: AGPL-3.0-only

// Package host drives stock workerd inside a gVisor/runsc sandbox via clrk's
// extracted pkg/sandbox.Runtime. It is the artifact a lifecycle controller
// (APO-796 ServiceManager) runs: it reconstructs a workerd config from a
// compute-API bundle and serves fetch over an HTTP socket (M1 backend mode).
package host

import "errors"

// SocketKind selects the workerd listening-socket variant Envoy talks to.
type SocketKind int

const (
	// HTTPSocket is the standard workerd `http` socket used by backend-mode
	// Services (M1). Envoy connects to it as an upstream cluster (APO-628).
	HTTPSocket SocketKind = iota
	// FilterSocket is the capnpFilter ext_proc socket used by filter-mode
	// Services. Scaffolding only in M1; full semantics are APO-629 (M2).
	FilterSocket
)

// String returns the socket kind's short name.
func (k SocketKind) String() string {
	switch k {
	case HTTPSocket:
		return "http"
	case FilterSocket:
		return "filter"
	default:
		return "unknown"
	}
}

// SocketSpec describes the listening socket workerd binds and Envoy dials.
type SocketSpec struct {
	Kind SocketKind
	// Addr is the listen address in workerd syntax: "*:8080" or
	// "127.0.0.1:8080" for TCP, or "unix:/path/to.sock" for a UDS.
	Addr string
}

// errFilterSocketUnsupported is returned when a filter-mode (capnpFilter)
// socket is requested in M1. Filter mode is deferred to APO-629 (M2); only the
// enum and this guard are present as scaffolding.
var errFilterSocketUnsupported = errors.New("workerd-host: filter (capnpFilter) socket is not supported in M1 backend mode; see APO-629")
