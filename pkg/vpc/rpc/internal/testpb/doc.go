// SPDX-License-Identifier: AGPL-3.0-only

// Package testpb holds the Echo test service of the rpc package.
// Generated code is checked in; regenerate with `go generate ./pkg/vpc/rpc/...`
// (needs protoc and protoc-gen-go on PATH).
package testpb

//go:generate go build -o protoc-gen-go-vpcrpc.bin ../../protoc-gen-go-vpcrpc
//go:generate protoc -I ../../../../.. --plugin=protoc-gen-go-vpcrpc=protoc-gen-go-vpcrpc.bin --go_out=paths=source_relative:../../../../.. --go-vpcrpc_out=paths=source_relative:../../../../.. pkg/vpc/rpc/internal/testpb/echo.proto
//go:generate rm protoc-gen-go-vpcrpc.bin
