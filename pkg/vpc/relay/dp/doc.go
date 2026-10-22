// SPDX-License-Identifier: AGPL-3.0-only

// Package dp is the data plane of the VPC relay: a Go pipeline that does what relay.p4 says. The
// control plane reaches it only through Target, with P4Runtime messages in process.
//
// relay.p4info.txtpb is the output of `p4test --arch v1model --p4runtime-files` for relay.p4, and
// CI compares it. `go generate` makes relay.gen.go from both files.
package dp

//go:generate go run ./internal/p4gen -p4info relay.p4info.txtpb -p4 relay.p4 -out relay.gen.go
