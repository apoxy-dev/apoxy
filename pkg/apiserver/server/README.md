# Apoxy API server

This package contains the `apiserver` startup path that replaces the old
`apiserver-runtime` sample-apiserver command wiring.

The active pieces are:

- `apiserver/`: generic-apiserver config and API group installation
- `builder/`: registration of resources, status subresources, and config hooks
- `start/`: recommended-config application and non-blocking server startup

Resource interfaces that Apoxy API types implement live in `api/resource/`.
