// SPDX-License-Identifier: AGPL-3.0-only

// Package workerdv1 holds the workerd manager's control-plane protos: the
// EgressConfig service the backplane pushes compiled egress config through
// (APO-723/APO-726) and the DNSConfig service the manager's infra watch
// pushes the VPC name plane through. Generated code is checked in;
// regenerate with `go generate ./api/workerd/v1` (needs protoc,
// protoc-gen-go, protoc-gen-go-grpc on PATH).
package workerdv1

//go:generate protoc --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:. egress.proto vpcdns.proto
