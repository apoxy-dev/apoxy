// The registry machinery (APO-773). `createRegistry` normalizes authored
// entries — deriving each GVR from its `servedVersion`, defaulting `path`,
// `displayName`, and `requires` — and indexes them by slug and GVR for the
// chrome, the splat route dispatcher, and the generic renderers. A duplicate
// slug is a programming error and throws at construction, not at navigation.

import { gvrKey } from '../lib/cache-keys'
import type { GVR, K8sObject } from '../lib/k8s-types'
import type {
  Registry,
  RegistryGroup,
  ResourceEntry,
  ResourceEntryInput,
} from './types'

/** Identity helper: preserves an entry's `T` for column/detail inference. */
export function defineResource<T extends K8sObject = K8sObject>(
  input: ResourceEntryInput<T>,
): ResourceEntryInput<T> {
  return input
}

function normalize(input: ResourceEntryInput<K8sObject>): ResourceEntry {
  const gvr: GVR = { group: input.group, version: input.servedVersion, resource: input.resource }
  return {
    gvr,
    kind: input.kind,
    displayName: input.displayName ?? input.kind,
    path: input.path ?? input.resource,
    sidebarGroup: input.sidebarGroup,
    servedVersion: input.servedVersion,
    icon: input.icon,
    columns: input.columns,
    yamlEditable: input.yamlEditable ?? false,
    schema: input.schema,
    requires: input.requires ?? [gvr],
    shortcut: input.shortcut,
    detail: input.detail,
    createWizard: input.createWizard,
  }
}

/**
 * Build a registry from authored entries. Entries keep registration order;
 * `groups()` preserves the first-seen order of each `sidebarGroup`.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- entries are
// heterogeneously typed (each ResourceEntryInput<T> has a different T); the
// registry erases T at its boundary and the runtime cell(obj) calls are sound.
export function createRegistry(inputs: ResourceEntryInput<any>[]): Registry {
  const entries: ResourceEntry[] = inputs.map(normalize)

  const byPath = new Map<string, ResourceEntry>()
  const byGvr = new Map<string, ResourceEntry>()
  for (const e of entries) {
    if (e.path.includes('/')) {
      // The splat route resolves a single-segment slug; a '/' in the path would
      // make the entry unreachable (and silently shadow another's list view).
      throw new Error(`Registry path "${e.path}" (kind ${e.kind}) must be a single URL segment with no "/"`)
    }
    if (byPath.has(e.path)) {
      throw new Error(`Duplicate registry path "${e.path}" (kinds collide on the same URL slug)`)
    }
    byPath.set(e.path, e)
    byGvr.set(gvrKey(e.gvr), e)
  }

  // Group preserving first-seen group order and within-group registration order.
  const groupOrder: string[] = []
  const grouped = new Map<string, ResourceEntry[]>()
  for (const e of entries) {
    let bucket = grouped.get(e.sidebarGroup)
    if (!bucket) {
      bucket = []
      grouped.set(e.sidebarGroup, bucket)
      groupOrder.push(e.sidebarGroup)
    }
    bucket.push(e)
  }
  const groups: RegistryGroup[] = groupOrder.map((name) => ({
    name,
    entries: grouped.get(name) ?? [],
  }))

  return {
    all: () => entries,
    byPath: (path) => byPath.get(path),
    byGvr: (gvr) => byGvr.get(gvrKey(gvr)),
    groups: () => groups,
  }
}
