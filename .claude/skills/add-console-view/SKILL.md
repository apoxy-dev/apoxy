---
name: add-console-view
description: >-
  Use when adding a view/page/kind to the Apoxy Console (the `console/` web UI) —
  e.g. surfacing a new API kind in the sidebar, list, detail, ⌘K command palette,
  or YAML editor, or adding a custom (non-resource) page. Explains the
  registry-driven `defineResource` flow so you add one entry instead of wiring a
  screen, route, sidebar item, and breadcrumb by hand.
---

# Add a view to the Apoxy Console

The console is **registry-driven**: a "view" for a resource kind is a single
`defineResource({...})` entry. Adding it auto-generates the sidebar item, the
route, breadcrumbs, the ⌘K command-palette entry, the list table, the detail
view, and (opt-in) the YAML edit tray. **You do not write a screen, a route, a
sidebar edit, or a breadcrumb** — those all derive from the registry.

> The spine: `console/packages/core/src/registry/` (`types.ts`, `registry.ts`,
> `nav.ts`). The generic renderers: `registry/resource-list-view.tsx`,
> `resource-detail-view.tsx`, `resource-view.tsx`. The app's entries:
> `console/apps/apoxy-console/src/registry.tsx`. The one splat route that
> dispatches every kind: `src/routes/_shell.$.tsx`.

## The 90% case — surface a new resource kind

### 1. (If the kind is new to the apiserver) refresh the typed schema

If the kind isn't in the generated OpenAPI types yet:

```bash
cd console
pnpm codegen          # regenerates apps/apoxy-console/src/schema/schema.d.ts
```

This is only needed if you want a typed `schema`/columns for the new GVR. Skip
it for a kind the apiserver already serves and whose types already exist.

### 2. Add one entry to the registry

Edit `console/apps/apoxy-console/src/registry.tsx` and add a `defineResource`
to the `createRegistry([...])` array:

```tsx
defineResource<Phased>({
  kind: 'Gateway',          // singular human label
  group: 'gateway.apoxy.dev',
  resource: 'gateways',     // lowercase plural (the k8s resource)
  servedVersion: 'v1',      // the ONE place the API version is named; GVR derives from it
  sidebarGroup: 'Operate',  // sidebar section (first-seen order; reuses existing groups)
  icon: <Gateway size={16} />,   // a @carbon/icons-react glyph, sized to the 16px rail
  yamlEditable: true,       // enables the SSA YAML edit tray for this kind
  columns: [nameCol, statusCol, createdCol],
}),
```

That's the whole change for a standard kind. After it, the kind shows up:
- in the sidebar under `sidebarGroup`,
- at `/<path>` (a list) and `/<path>/<name>` (a detail) — dispatched by the
  existing `_shell.$.tsx` splat, no new route file,
- in the ⌘K palette as a "Go to" command,
- in breadcrumbs,
- with an editable YAML tray when `yamlEditable: true`.

### 3. Columns

Each column is `{ id, header, cell, width?, mono? }` where `cell(obj) =>
ReactNode`. Reuse the shared columns already defined at the top of
`registry.tsx` (`nameCol`, `statusCol`, `createdCol`) or write your own:

```tsx
const replicasCol = { id: 'replicas', header: 'Replicas', mono: true,
  cell: (o: Phased) => String(o.spec?.replicas ?? '—') }
```

Status badges use the shared `phaseVariant()` + `<Badge variant=…>` so a phase
string renders as the right color (and is dark-mode-safe via tokens — never
hardcode a hex).

### 4. Optional knobs (all on `ResourceEntryInput`, see `registry/types.ts`)

| field | default | use |
|-------|---------|-----|
| `displayName` | `kind` | plural label for sidebar/list headers (`'Gateways'`) |
| `path` | `resource` | URL slug; **must be a single segment, unique** (throws otherwise) |
| `yamlEditable` | `false` | turn on the SSA YAML edit tray |
| `schema` | — | per-kind JSON Schema for richer tray validation (from generated OpenAPI) |
| `requires` | `[gvr]` | GVRs that must be served (discovery-gated); `[]` = always show |
| `detail` | generic view | a custom detail renderer `ComponentType<ResourceDetailProps<T>>` |

Discovery gating means an entry **auto-hides** when its apiserver doesn't serve
the GVR — so it's safe to register kinds that only some deployments have.

### 5. Verify

```bash
cd console
pnpm typecheck && pnpm test && pnpm build
pnpm dev      # eyeball it: sidebar entry, list, detail, ⌘K, YAML tray
```

## Custom (non-resource) views

For a page that isn't a k8s kind (a dashboard, a settings page), add a TanStack
**file route** under `console/apps/apoxy-console/src/routes/` — e.g.
`_shell.settings.tsx` renders at `/settings` inside the chrome (the `_shell`
prefix nests it under the rail+topbar layout). Model it on
`_shell.index.tsx` (the Overview page). If it needs a sidebar link, that part
isn't registry-driven — wire it where the shell builds nav, or prefer modeling
the page as a resource kind when it maps to one.

## Guardrails

- **`@apoxy/console-core` is shared** across apoxy / clrk / cloud — keep it
  app-agnostic. App-specific things (concrete kinds, icons, the project context)
  live in `apps/apoxy-console/`, not in `packages/core/`.
- **Colors come from tokens**, never hardcoded hex/rgba — the console has a
  token-driven dark theme (`tokens.css` `[data-theme="dark"]`); a literal color
  won't flip. Rail surfaces use the dedicated `--rail-*` tokens.
- `servedVersion` is the **single** place a kind's API version is named.
- Path must be a single URL segment and unique across the registry.
- Repo conventions: commit messages are `[component] short description` (single
  line); log/UI strings start Capitalized; use plain language in customer-facing
  UI, not protocol jargon.
