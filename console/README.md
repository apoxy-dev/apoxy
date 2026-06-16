# Apoxy Console

The web UI for Apoxy and CLRK: a client-only React 19 SPA over the k8s-convention
apiservers (list/get/apply/patch/delete/watch). A single WatchManager is the sole writer
to the query cache; a typed resource registry is the spine that generates the sidebar,
routes, breadcrumbs, command palette, CRUD hooks, and YAML-tray bindings.

This `console/` tree lives in `apoxy-dev/apoxy`, with packages mirroring the Go
dependency graph. It owns
`@apoxy/console-core` plus the feature packages for API groups defined in this repo, and
the openapi→TS codegen tooling shared across repos. clrk and apoxy-cloud carry their own
`console/` trees and consume `@apoxy/console-core` from here (SHA-pinned, no npm registry).

Design docs are the source of truth:
`apoxy-cloud/docs/console/` (`architecture.md` + `adr/`).

## Layout

```
console/
  packages/
    core/                 @apoxy/console-core — shell, client, registry, tokens, primitives
  apps/
    apoxy-console/        OSS embeddable console (go:embed in `apoxy console`); CI smoke consumer
  scripts/
    generate-schema.ts    openapi-typescript codegen → core/src/schema/schema.d.ts
```

## Develop

```bash
pnpm install          # from this directory
pnpm dev              # runs apps/apoxy-console on Vite 8 / Rolldown
pnpm test             # Vitest across the workspace
pnpm typecheck
pnpm codegen          # regenerate schema.d.ts from the apiserver OpenAPI
```

Toolchain: pnpm workspaces, Vite 8 (Rolldown), React 19 (no compiler at launch),
TanStack Router file routing, Tailwind v4 (tokens shipped as plain CSS), Vitest.
