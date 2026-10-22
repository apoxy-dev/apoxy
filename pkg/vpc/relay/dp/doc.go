// SPDX-License-Identifier: AGPL-3.0-only

// Package dp is the data plane of the VPC relay: a Go pipeline that does what relay.p4 says. The
// control plane reaches it only through Target, with P4Runtime messages in process.
//
// relay.p4info.txtpb is the output of `p4test --arch v1model --p4runtime-files` for relay.p4, and
// CI compares it. `go generate` makes relay.gen.go from both files.
//
// Device is the dedicated interface of the relay (AF_XDP, Linux): a fixed demux gives its packets
// to the pipeline, to quic-go and to a netstack. FindInterface gives the interface and its
// addresses. The relay XDP program (ebpf/xdp.c; bpf2go makes xdp_bpf*.go and .o with clang) and
// the send path drop and delay packets as the impair map tells them. Only tests write that map.
package dp

//go:generate go run ./internal/p4gen -p4info relay.p4info.txtpb -p4 relay.p4 -out relay.gen.go
