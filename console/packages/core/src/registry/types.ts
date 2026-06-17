// The resource registry's type vocabulary (the M3 spine). A ResourceEntry is a
// typed description of one resource kind — everything the chrome, router, and
// generic renderers need to present it. Feature packages contribute entries;
// app entrypoints compose the lists they want. Adding a kind is a registry
// entry, never a new screen/route/sidebar edit.

import type { ComponentType, ReactNode } from 'react'
import type { GVR, K8sObject } from '../lib/k8s-types'

/** One column of the generic list table, derived from the registry entry. */
export interface ResourceColumn<T extends K8sObject = K8sObject> {
  /** Stable id (also the header/cell React key). */
  id: string
  /** Column header label. */
  header: string
  /** Cell content for a row — a string/number, or any ReactNode for custom
   *  rendering (badges, mono ids, etc.). */
  cell: (obj: T) => ReactNode
  /** Optional fixed width as a CSS value (e.g. `'32%'`). */
  width?: string
  /** Render the cell in the monospace face (names, versions, ids). */
  mono?: boolean
}

/** Props handed to an entry's custom detail renderer (the `detail` escape hatch). */
export interface ResourceDetailProps<T extends K8sObject = K8sObject> {
  object: T
  entry: ResourceEntry<T>
}

/**
 * What an author writes to register a kind. The API version is named exactly
 * once — `servedVersion` — and the GVR is derived from it, so a kind's version
 * lives in a single place. `path`/`displayName`/`requires` default sensibly.
 */
export interface ResourceEntryInput<T extends K8sObject = K8sObject> {
  /** Human kind label, singular (e.g. `Proxy`). */
  kind: string
  /** API group (e.g. `core.apoxy.dev`; `''` for the core group). */
  group: string
  /** Lowercase plural resource (e.g. `proxies`). */
  resource: string
  /** The single place a kind's served API version is named (e.g. `v1alpha2`). */
  servedVersion: string
  /** Sidebar section this kind appears under (e.g. `Operate`). */
  sidebarGroup: string
  /** Plural display label for sidebar/list headers. Defaults to `kind`. */
  displayName?: string
  /** URL slug under the shell (`proxies` → `/proxies`). Defaults to `resource`. */
  path?: string
  /** Sidebar/nav icon. */
  icon?: ReactNode
  /** Columns for the generic list table. */
  columns: ResourceColumn<T>[]
  /** Whether the YAML tray can edit this kind via SSA. Defaults to `false`. */
  yamlEditable?: boolean
  /** GVRs that must be served (per discovery) for this entry to appear.
   *  Defaults to `[gvr]` — an entry hides when its own resource isn't served.
   *  An explicit empty array opts out of discovery gating (always shown). */
  requires?: GVR[]
  /** Custom detail renderer; falls back to the generic detail view. */
  detail?: ComponentType<ResourceDetailProps<T>>
}

/** A normalized registry entry: every default resolved, `gvr` computed. */
export interface ResourceEntry<T extends K8sObject = K8sObject> {
  readonly gvr: GVR
  readonly kind: string
  readonly displayName: string
  readonly path: string
  readonly sidebarGroup: string
  readonly servedVersion: string
  readonly icon?: ReactNode
  readonly columns: ResourceColumn<T>[]
  readonly yamlEditable: boolean
  readonly requires: GVR[]
  readonly detail?: ComponentType<ResourceDetailProps<T>>
}

/** A sidebar section: its label and the entries registered under it, in order. */
export interface RegistryGroup {
  readonly name: string
  readonly entries: ResourceEntry[]
}

/** The registry: the single source the chrome, routes, and renderers read from. */
export interface Registry {
  /** All entries, in registration order. */
  all(): ResourceEntry[]
  /** Entry by URL slug (`proxies`), or undefined. */
  byPath(path: string): ResourceEntry | undefined
  /** Entry by GVR address, or undefined. */
  byGvr(gvr: GVR): ResourceEntry | undefined
  /** Entries grouped by `sidebarGroup`, groups in first-seen order. */
  groups(): RegistryGroup[]
}
