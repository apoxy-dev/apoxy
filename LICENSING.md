# Licensing

This repository is licensed under the **GNU Affero General Public License v3.0
only** (`AGPL-3.0-only`), **except** for the directories listed below, which are
licensed under the **Apache License, Version 2.0** (`Apache-2.0`).

| Path | License | SPDX |
|------|---------|------|
| Repository root (everything not listed below) | GNU AGPL v3.0 only | `AGPL-3.0-only` |
| `api/` | Apache License 2.0 | `Apache-2.0` |
| `client/` | Apache License 2.0 | `Apache-2.0` |

The full license texts are in [`LICENSE`](./LICENSE) (AGPL-3.0-only),
[`api/LICENSE`](./api/LICENSE) and [`client/LICENSE`](./client/LICENSE)
(Apache-2.0).

## Why the split

`api/` (the Apoxy API type definitions) and `client/` (the generated Kubernetes
client — clientset, informers, listers) are the SDK surface that integrators
import to build against Apoxy. They are kept permissively licensed
(`Apache-2.0`) so that consuming them does **not** impose copyleft obligations.
Both directories are self-contained: they import no other packages in this
module outside `api/` and `client/`, so the boundary is clean. Generated files
under `api/` and `client/` carry an `Apache-2.0` header stamped from
`codegen/boilerplate.go.txt`; regenerating them preserves the Apache license.

Everything else — the binaries, runtime, and supporting libraries — is
`AGPL-3.0-only`.

## History

Versions of this work were previously distributed under the Business Source
License 1.1 (BSL-1.1). That license is superseded by the terms above for all
subsequent distributions. Copyright © Apoxy, Inc.
