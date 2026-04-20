# Apoxy API server

This package contains the `apiserver` startup path that replaces the old
`apiserver-runtime` sample-apiserver command wiring.

The active pieces are:

- `apiserver/`: generic-apiserver config and API group installation
- `builder/`: registration of resources, status subresources, and config hooks
- `start/`: recommended-config application and non-blocking server startup

The builder still reuses the `sigs.k8s.io/apiserver-runtime/pkg/builder/resource`
interfaces that Apoxy API types already implement, but it no longer depends on
the sample-apiserver-based builder and startup path.
