# Apoxy Console

The web UI for Apoxy and CLRK: a client-only React 19 SPA over the k8s-convention
apiservers (list/get/apply/patch/delete/watch). A single WatchManager is the sole writer
to the query cache; a typed resource registry is the spine that generates the sidebar,
routes, breadcrumbs, command palette, CRUD hooks, and YAML-tray bindings.

This `console/` tree lives in `apoxy-dev/apoxy` per [ADR-0002][adr2]. It owns
`@apoxy/console-core` plus the feature packages for API groups defined in this repo, and
the openapi→TS codegen tooling shared across repos. clrk and apoxy-cloud carry their own
`console/` trees and consume `@apoxy/console-core` from here (SHA-pinned, no npm registry —
[ADR-0003][adr3]).

Design docs and ADRs are the source of truth:
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
TanStack Router file routing, Tailwind v4 (tokens shipped as plain CSS), Vitest. See
[ADR-0004][adr4].

[adr2]: ../../apoxy-cloud/docs/console/adr/0002-packages-mirror-go-dependency-graph.md
[adr3]: ../../apoxy-cloud/docs/console/adr/0003-first-party-linkage-no-npm-registry.md
[adr4]: ../../apoxy-cloud/docs/console/adr/0004-build-toolchain-pnpm-vite-rolldown.md
