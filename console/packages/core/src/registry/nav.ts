// Sidebar + breadcrumb generation from the registry (APO-774). These are pure
// functions over the registry (plus a discovery-backed `isServed` predicate),
// so adding a kind never touches sidebar or breadcrumb code — and they are
// trivially unit-testable without rendering. Route wiring is the app's single
// splat dispatcher; it reads the same registry, so it too needs no per-kind edit.

import type { ReactNode } from 'react'
import type { GVR } from '../lib/k8s-types'
import type { Registry, ResourceEntry } from './types'

/** A rendered sidebar nav item for one resource kind. */
export interface SidebarItem {
  /** URL slug to link to (`/proxies`). */
  to: string
  /** Display label (plural). */
  label: string
  /** The kind label, for tooltips/aria. */
  kind: string
  icon?: ReactNode
  gvr: GVR
}

/** A sidebar section with its (served) items. */
export interface SidebarGroupModel {
  name: string
  items: SidebarItem[]
}

export interface SidebarModel {
  groups: SidebarGroupModel[]
}

export interface BuildSidebarOptions {
  /** Whether a GVR is served by the apiserver (discovery). Defaults to served. */
  isServed?: (gvr: GVR) => boolean
}

/** True when every GVR an entry requires is served. */
function entryServed(entry: ResourceEntry, isServed: (gvr: GVR) => boolean): boolean {
  return entry.requires.every(isServed)
}

/**
 * Derive the grouped, ordered sidebar from the registry. Entries whose
 * `requires[]` are not all served are dropped; groups left empty after gating
 * are omitted. With no `isServed` (or before discovery loads) everything shows.
 */
export function buildSidebar(registry: Registry, opts: BuildSidebarOptions = {}): SidebarModel {
  const isServed = opts.isServed ?? (() => true)
  const groups: SidebarGroupModel[] = []
  for (const group of registry.groups()) {
    const items: SidebarItem[] = group.entries
      .filter((e) => entryServed(e, isServed))
      .map((e) => ({ to: `/${e.path}`, label: e.displayName, kind: e.kind, icon: e.icon, gvr: e.gvr }))
    if (items.length > 0) groups.push({ name: group.name, items })
  }
  return { groups }
}

/** A breadcrumb: a label, and a link target unless it is the current location. */
export interface Breadcrumb {
  label: string
  to?: string
}

export interface BuildBreadcrumbsOptions {
  /** A leading crumb (e.g. the project/overview root). */
  root?: Breadcrumb
}

/**
 * Breadcrumbs for the current resource view. List view: `[root?, <kind>]` with
 * the kind as the current (un-linked) crumb. Detail view: `[root?, <kind> →
 * list, <name>]` with the object name current.
 */
export function buildBreadcrumbs(
  entry: ResourceEntry | undefined,
  name?: string,
  opts: BuildBreadcrumbsOptions = {},
): Breadcrumb[] {
  const crumbs: Breadcrumb[] = []
  if (opts.root) crumbs.push(opts.root)
  if (entry) {
    crumbs.push({ label: entry.displayName, to: name ? `/${entry.path}` : undefined })
    if (name) crumbs.push({ label: name })
  }
  return crumbs
}
