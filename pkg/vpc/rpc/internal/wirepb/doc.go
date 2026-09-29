// SPDX-License-Identifier: AGPL-3.0-only

// Package wirepb holds the protobuf messages of the RPC stream framing.
// Generated code is checked in; regenerate with `go generate ./pkg/vpc/rpc/...`
// (needs protoc and protoc-gen-go on PATH).
package wirepb

//go:generate protoc -I ../../../../.. --go_out=paths=source_relative:../../../../.. pkg/vpc/rpc/internal/wirepb/wire.proto
