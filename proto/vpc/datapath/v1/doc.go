// SPDX-License-Identifier: AGPL-3.0-only

// Package datapathv1 holds the messages and services of the VPC datapath
// control plane. They run on the pkg/vpc/rpc runtime; README.md has the wire
// format. Generated code is checked in; regenerate with
// `go generate ./proto/vpc/datapath/v1` (needs protoc and protoc-gen-go on PATH).
package datapathv1

//go:generate go build -o protoc-gen-go-vpcrpc.bin ../../../../pkg/vpc/rpc/protoc-gen-go-vpcrpc
//go:generate protoc -I ../../../.. --plugin=protoc-gen-go-vpcrpc=protoc-gen-go-vpcrpc.bin --go_out=paths=source_relative:../../../.. --go-vpcrpc_out=paths=source_relative:../../../.. proto/vpc/datapath/v1/types.proto proto/vpc/datapath/v1/relay.proto proto/vpc/datapath/v1/peer.proto proto/vpc/datapath/v1/mesh.proto
//go:generate rm protoc-gen-go-vpcrpc.bin

// ALPN protocol IDs of the control channels.
const (
	// ALPNRelay is the relay session: agent or VTEP to relay (service Relay).
	ALPNRelay = "apoxy-vpc/2"
	// ALPNPeer is the peer session: agent to agent (service Peer).
	ALPNPeer = "apoxy-peer/1"
	// ALPNMesh is the mesh session: relay to relay (service Mesh).
	ALPNMesh = "apoxy-mesh/1"
)
