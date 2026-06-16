// The typed cache-key factory shared by the GVR client and the WatchManager.
// Keys are scoped — they include the RequestDecorator's
// `scopeKey` — so two projects never collide on one cache entry, which is what
// makes scope teardown a key change rather than a manual cache purge.

import type { GVR } from './k8s-types'
import type { Selectors } from './k8s-paths'

/** Stable `group/version/resource` string for an entry-keying suffix. */
export function gvrKey(gvr: GVR): string {
  return `${gvr.group}/${gvr.version}/${gvr.resource}`
}

/** Selectors that distinguish two managed lists of the same GVR within a scope. */
function selectorKey(s: Selectors | undefined): [string, string, string] {
  return [s?.namespace ?? '', s?.labelSelector ?? '', s?.fieldSelector ?? '']
}

/**
 * TanStack Query key for a managed list. Shape:
 *   `['k8s', scope, group, version, resource, namespace, labelSelector, fieldSelector]`
 * The leading literals keep apoxy cache entries greppable and let a scope be
 * invalidated/removed with a prefix match.
 */
export function listKey(
  scope: string,
  gvr: GVR,
  selectors?: Selectors,
): readonly unknown[] {
  return ['k8s', scope, gvr.group, gvr.version, gvr.resource, ...selectorKey(selectors)]
}

/** Prefix matching every managed list in a scope (for scope teardown). */
export function scopePrefix(scope: string): readonly unknown[] {
  return ['k8s', scope]
}

/** Internal map key for a WatchManager entry: scope + gvr + selectors. */
export function entryKey(scope: string, gvr: GVR, selectors?: Selectors): string {
  return [scope, gvrKey(gvr), ...selectorKey(selectors)].join('|')
}
