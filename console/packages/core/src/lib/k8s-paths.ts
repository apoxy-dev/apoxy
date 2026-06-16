// Path + query construction for the GVR client. Encodes the
// Kubernetes REST conventions — `/api/v1/...` for the core group, `/apis/g/v/...`
// otherwise, with an optional `/namespaces/<ns>/` segment — so no call site
// hand-writes a path or bakes an API version into a string.

import type { GVR } from './k8s-types'

/** Label/field selectors shared by list and watch. */
export interface Selectors {
  namespace?: string
  labelSelector?: string
  fieldSelector?: string
}

export interface ListParams extends Selectors {
  limit?: number
  /** Opaque pagination token from a previous list's `metadata.continue`. */
  continue?: string
  resourceVersion?: string
  resourceVersionMatch?: string
}

export interface WatchParams extends Selectors {
  resourceVersion?: string
  allowWatchBookmarks?: boolean
}

/** Root path for a group/version: `/api/v1` for core, `/apis/g/v` otherwise. */
function groupVersionRoot(gvr: GVR): string {
  return gvr.group === '' ? `/api/${gvr.version}` : `/apis/${gvr.group}/${gvr.version}`
}

/** Collection path, optionally namespaced. */
export function collectionPath(gvr: GVR, namespace?: string): string {
  const root = groupVersionRoot(gvr)
  return namespace ? `${root}/namespaces/${namespace}/${gvr.resource}` : `${root}/${gvr.resource}`
}

/** Single-object path. */
export function objectPath(gvr: GVR, name: string, namespace?: string): string {
  return `${collectionPath(gvr, namespace)}/${encodeURIComponent(name)}`
}

function appendQuery(path: string, params: Record<string, string | number | boolean | undefined>): string {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') q.set(k, String(v))
  }
  const s = q.toString()
  return s ? `${path}?${s}` : path
}

/** `GET` list path with selectors and pagination. */
export function listUrl(gvr: GVR, params: ListParams = {}): string {
  return appendQuery(collectionPath(gvr, params.namespace), {
    labelSelector: params.labelSelector,
    fieldSelector: params.fieldSelector,
    limit: params.limit,
    continue: params.continue,
    resourceVersion: params.resourceVersion,
    resourceVersionMatch: params.resourceVersionMatch,
  })
}

/** `GET …?watch=1` path resuming from `resourceVersion`, bookmarks on by default. */
export function watchUrl(gvr: GVR, params: WatchParams = {}): string {
  return appendQuery(collectionPath(gvr, params.namespace), {
    watch: '1',
    allowWatchBookmarks: params.allowWatchBookmarks ?? true,
    labelSelector: params.labelSelector,
    fieldSelector: params.fieldSelector,
    resourceVersion: params.resourceVersion,
  })
}
