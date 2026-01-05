# CLAUDE.md - Apoxy CLI Development Guide

This document provides architecture overview and development instructions for the Apoxy CLI and platform.

## Project Overview

**Apoxy** is an API gateway and proxy management platform built in Go with Kubernetes-native architecture. It provides infrastructure for managing, routing, and controlling API proxies across cloud and on-premises deployments.

- **Module**: `github.com/apoxy-dev/apoxy`
- **Go Version**: 1.24.3

## Build Instructions

### Building the CLI

```bash
# Release build (installs to $GOPATH/bin/apoxy)
./build.sh

# Debug build
./build.sh -t debug
```

The build script:
- Extracts version from git tags
- Generates build metadata (commit hash, timestamp)
- Uses Go ldflags for version injection

### Building Docker Images

Uses Dagger for containerized builds:

```bash
# Build all images
dagger call build-all

# Build specific image
dagger call build-apiserver
dagger call build-backplane
dagger call build-tunnelproxy
```

## Test Instructions

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./pkg/tunnel/...
go test ./pkg/cmd/...

# Verbose output
go test -v ./...

# Run specific test
go test -run TestName ./...

# Linux-only tests (tunnel, netlink)
GOOS=linux go test ./pkg/net/lwtunnel/...
GOOS=linux go test ./pkg/tunnel/...
```

### Test Patterns

- **Table-driven tests** with `testify/assert` and `testify/require`
- **Fixture-based tests** using `testdata/` directories
- **Integration tests** for config loading and API operations

## Architecture

### Main Entry Points (cmd/)

| Binary | Purpose |
|--------|---------|
| `apiserver` | Kubernetes-native API server for Apoxy resources |
| `backplane` | Edge infrastructure controller managing Envoy proxies |
| `tunnelproxy` | VPN-like tunnel for device connectivity (Linux-only) |
| `kube-controller` | Kubernetes cluster integration |
| `dial-stdio` | Auxiliary stdio communication tool |

### Key Packages (pkg/)

| Package | Purpose |
|---------|---------|
| `pkg/apiserver` | API server implementation, auth, controllers |
| `pkg/gateway` | xDS server and Gateway API translation |
| `pkg/tunnel` | VPN tunnel infrastructure, routing, IPAM |
| `pkg/backplane` | Envoy proxy management, WASM extensions |
| `pkg/cmd` | CLI command implementations (Cobra) |
| `pkg/drivers` | Deployment mode drivers (Docker, Supervisor) |
| `pkg/net/lwtunnel` | Linux lightweight tunnel (Geneve) management |

### API Types (api/)

The `api/` directory contains Kubernetes-style API type definitions organized by group and version:

```
api/
├── config/v1alpha1/        # CLI configuration types
├── controllers/v1alpha1/   # Controller-specific types
├── core/
│   ├── v1alpha/            # Legacy core types
│   └── v1alpha2/           # Current core types (Proxy, TunnelAgent, Backend, Domain)
├── extensions/
│   ├── v1alpha1/           # Legacy extension types
│   └── v1alpha2/           # Current extension types (Extension, ExtensionPolicy)
├── gateway/
│   ├── v1/                 # Gateway API types (Gateway, HTTPRoute, TCPRoute, UDPRoute)
│   └── v1alpha2/           # Legacy gateway types
├── policy/v1alpha1/        # Policy types (RateLimit)
└── generated/              # Generated OpenAPI schemas
```

Each version directory contains:
- `types.go` - Main type definitions with `+k8s:deepcopy-gen=true` markers
- `groupversion_info.go` - Group/version registration
- `zz_generated.deepcopy.go` - Generated deepcopy methods
- `zz_generated.register.go` - Generated type registration

### Code Generation

After modifying API types, regenerate helpers:

```bash
./codegen/update.sh
```

This generates:
- **DeepCopy methods** - For all types marked with `+k8s:deepcopy-gen=true`
- **Register helpers** - Type registration with the API scheme
- **Client code** - Typed Kubernetes clients in `client/versioned/`
- **Listers and Informers** - For controller-runtime in `client/listers/` and `client/informers/`
- **OpenAPI schemas** - In `api/generated/zz_generated.openapi.go`

The script uses `k8s.io/code-generator` (v0.30.1) and must match the `k8s.io/apimachinery` version in `go.mod`.

## Key Subsystems

### Tunnel System (`pkg/tunnel`, `pkg/net/lwtunnel`)

The tunnel system provides VPN-like connectivity:

- **TunnelServer**: Manages QUIC connections and routing
- **Geneve**: Linux Geneve tunnel interface management with lwtunnel routing
- **IPAM**: IPv6 address allocation for tunnel endpoints
- **Router**: Netlink-based routing (kernel mode) or netstack (userspace)

Key types:
- `TunnelServer` - Main server managing connections
- `Geneve` - Geneve interface and route management
- `NetULA` - IPv6 ULA address representation

### Gateway/xDS System (`pkg/gateway`)

Translates Kubernetes Gateway API to Envoy xDS:

- **gatewayapi/**: Parses Gateway API resources
- **xds/translator/**: Converts to Envoy IR
- **xds/server/**: gRPC xDS server for Envoy
- **xds/types/**: Node metadata and type definitions

### Backplane System (`pkg/backplane`)

Manages edge proxy deployments:

- **envoy/**: Envoy binary management, hot-restart
- **wasm/**: WASM extension processor
- **kvstore/**: Distributed K/V store (Olric)
- **controllers/**: Proxy, Gateway, EdgeFunction reconcilers

## Development Workflow

### Local Development

```bash
# Start local dev environment
apoxy dev

# Regenerate API helpers after modifying types in api/
./codegen/update.sh

# Other code generation
go generate ./...
```

### Adding New Features

1. Define API types in `api/` if needed
2. Run `./codegen/update.sh` to regenerate clients and helpers
3. Implement logic in appropriate `pkg/` package
4. Add CLI commands in `pkg/cmd/` if user-facing
5. Write tests following existing patterns
6. Update this document if architectural changes

### Cross-Compilation Notes

Some packages are Linux-only due to netlink/syscall usage:
- `pkg/net/lwtunnel`
- `pkg/tunnel` (parts)
- `cmd/tunnelproxy`

Build with `GOOS=linux` for these packages on macOS.

## Key Dependencies

| Dependency | Purpose |
|------------|---------|
| `sigs.k8s.io/controller-runtime` | Kubernetes controller framework |
| `sigs.k8s.io/gateway-api` | Gateway API types |
| `envoyproxy/go-control-plane` | Envoy xDS protocol |
| `quic-go/quic-go` | QUIC protocol (Apoxy fork) |
| `vishvananda/netlink` | Linux netlink interface |
| `gvisor/gvisor` | Userspace network stack |
| `temporalio/sdk` | Workflow engine |
| `tetratelabs/wazero` | WebAssembly runtime |

## Deployment Models

| Mode | Description |
|------|-------------|
| **Cloud** | Managed by Apoxy in edge infrastructure |
| **Kubernetes** | Runs as Kubernetes pods with full integration |
| **Unmanaged** | User-deployed proxies, control plane via API |

## File Structure

```
apoxy-cli/
├── cmd/                    # Main entry points
├── pkg/                    # Core packages
├── api/                    # API type definitions
├── client/                 # Generated K8s client
├── config/                 # Configuration management
├── docs/                   # Documentation
├── ci/                     # Dagger CI pipeline
├── deploy/                 # Deployment manifests
├── build.sh                # Build script
├── install.sh              # Binary installer
├── go.mod                  # Dependencies
└── .goreleaser.yaml        # Release configuration
```
