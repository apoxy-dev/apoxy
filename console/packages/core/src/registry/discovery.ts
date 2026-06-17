// Registry gating on k8s-native mechanisms (APO-760) — no bespoke /capabilities
// endpoint. Two seams:
//   1. Served GVRs via aggregated discovery v2 (apidiscovery.k8s.io/v2) drive a
//      registry entry's `requires[]`: an entry only appears when the apiserver
//      actually serves its group/version/resource.
//   2. Per-user authorization via SelfSubjectAccessReview gates create/edit/
//      delete affordances.
// Both default OPEN when they can't be verified (still loading, fetch failed, or
// a server that doesn't speak v2): we never hide a kind we couldn't disprove,
// and the apiserver enforces authz regardless of what the UI shows.

import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { gvrKey } from '../lib/cache-keys'
import { useConsoleClient } from '../lib/hooks'
import type { RequestDecorator } from '../lib/request-decorator'
import type { GVR } from '../lib/k8s-types'

/** Accept header that asks the apiserver for aggregated discovery v2. */
const AGGREGATED_DISCOVERY_ACCEPT =
  'application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList'

const SSAR_PATH = '/apis/authorization.k8s.io/v1/selfsubjectaccessreviews'

/** The slice of an `APIGroupDiscoveryList` we read (group → versions → resources). */
export interface DiscoveryDoc {
  items?: Array<{
    metadata?: { name?: string }
    versions?: Array<{
      version?: string
      resources?: Array<{ resource?: string }>
    }>
  }>
}

/**
 * Collapse one or more aggregated-discovery docs into the set of served
 * `group/version/resource` keys (the same key shape as {@link gvrKey}).
 */
export function parseAggregatedDiscovery(docs: DiscoveryDoc[]): Set<string> {
  const served = new Set<string>()
  for (const doc of docs) {
    for (const group of doc.items ?? []) {
      const g = group.metadata?.name ?? ''
      for (const v of group.versions ?? []) {
        const version = v.version ?? ''
        for (const r of v.resources ?? []) {
          if (r.resource) served.add(`${g}/${version}/${r.resource}`)
        }
      }
    }
  }
  return served
}

export interface DiscoveryClientOptions {
  decorator: RequestDecorator
  /** Injectable for tests; defaults to the global `fetch`. */
  fetch?: typeof fetch
}

/** The served GVR set, with whether every discovery endpoint was read. */
export interface ServedGVRs {
  served: Set<string>
  /** True only when every endpoint resolved; false ⇒ inconclusive ⇒ open. */
  complete: boolean
}

/** Fetches aggregated discovery v2 from `/apis` (+ `/api`) and parses served GVRs. */
export class DiscoveryClient {
  private readonly decorator: RequestDecorator
  private readonly fetchImpl: typeof fetch

  constructor(opts: DiscoveryClientOptions) {
    this.decorator = opts.decorator
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis)
  }

  /**
   * Served `group/version/resource` keys plus a `complete` flag. Throws only if
   * neither `/apis` nor `/api` could be read. `complete` is true ONLY when every
   * endpoint resolved: a partial result (one endpoint failed) is inconclusive,
   * because it may omit exactly the group a registry entry needs — and gating
   * must never hide a kind it could not actually disprove.
   */
  async fetchServed(signal?: AbortSignal): Promise<ServedGVRs> {
    const results = await Promise.allSettled([this.getDoc('/apis', signal), this.getDoc('/api', signal)])
    const docs = results.flatMap((r) => (r.status === 'fulfilled' ? [r.value] : []))
    if (docs.length === 0) {
      const rejected = results.find((r) => r.status === 'rejected') as PromiseRejectedResult | undefined
      throw rejected?.reason ?? new Error('aggregated discovery unavailable')
    }
    return { served: parseAggregatedDiscovery(docs), complete: results.every((r) => r.status === 'fulfilled') }
  }

  private async getDoc(path: string, signal?: AbortSignal): Promise<DiscoveryDoc> {
    const headers = new Headers({ Accept: AGGREGATED_DISCOVERY_ACCEPT })
    const { url, headers: decorated } = this.decorator.decorate({ path, method: 'GET', headers })
    const res = await this.fetchImpl(url, { method: 'GET', headers: decorated, signal })
    if (!res.ok) throw new Error(`discovery ${path}: ${res.status}`)
    return (await res.json()) as DiscoveryDoc
  }
}

/** k8s authorization verbs (open string so callers aren't boxed in). */
export type Verb = 'get' | 'list' | 'watch' | 'create' | 'update' | 'patch' | 'delete' | (string & {})

export interface AccessReviewAttributes {
  verb: Verb
  gvr: GVR
  namespace?: string
  name?: string
}

/** The `SelfSubjectAccessReview` request body for a verb on a GVR. */
export function accessReviewBody(attrs: AccessReviewAttributes): Record<string, unknown> {
  return {
    apiVersion: 'authorization.k8s.io/v1',
    kind: 'SelfSubjectAccessReview',
    spec: {
      resourceAttributes: {
        group: attrs.gvr.group,
        version: attrs.gvr.version,
        resource: attrs.gvr.resource,
        verb: attrs.verb,
        ...(attrs.namespace ? { namespace: attrs.namespace } : {}),
        ...(attrs.name ? { name: attrs.name } : {}),
      },
    },
  }
}

export interface AccessReviewClientOptions {
  decorator: RequestDecorator
  fetch?: typeof fetch
}

/** Posts a SelfSubjectAccessReview and reports whether the verb is allowed. */
export class AccessReviewClient {
  private readonly decorator: RequestDecorator
  private readonly fetchImpl: typeof fetch

  constructor(opts: AccessReviewClientOptions) {
    this.decorator = opts.decorator
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis)
  }

  async canI(attrs: AccessReviewAttributes, signal?: AbortSignal): Promise<boolean> {
    const headers = new Headers({ 'Content-Type': 'application/json', Accept: 'application/json' })
    const { url, headers: decorated } = this.decorator.decorate({ path: SSAR_PATH, method: 'POST', headers })
    const res = await this.fetchImpl(url, {
      method: 'POST',
      headers: decorated,
      body: JSON.stringify(accessReviewBody(attrs)),
      signal,
    })
    if (!res.ok) throw new Error(`SelfSubjectAccessReview: ${res.status}`)
    const out = (await res.json()) as { status?: { allowed?: boolean } }
    return out.status?.allowed === true
  }
}

/**
 * The `isServed` predicate for a discovery result. Open by default: gate only
 * on a COMPLETE, non-empty result. A partial result (one endpoint failed) or an
 * empty one (server doesn't speak aggregated v2) leaves everything visible —
 * gating must never hide a kind it could not actually disprove.
 */
export function servedPredicate(data: ServedGVRs | undefined): (gvr: GVR) => boolean {
  if (!data || !data.complete || data.served.size === 0) return () => true
  const served = data.served
  return (gvr: GVR) => served.has(gvrKey(gvr))
}

/** Predicate over served GVRs (what {@link buildSidebar} gates on). */
export interface DiscoveryResult {
  isServed: (gvr: GVR) => boolean
  isLoading: boolean
  error: Error | null
}

/**
 * Fetch aggregated discovery once per scope and expose an `isServed` predicate.
 * Open by default: until discovery resolves to a non-empty set, everything is
 * treated as served so the sidebar is never blank on load or on an old server.
 */
export function useDiscovery(): DiscoveryResult {
  const client = useConsoleClient()
  const decorator = client.gvr.decorator
  const dc = useMemo(() => new DiscoveryClient({ decorator }), [decorator])
  const q = useQuery({
    queryKey: ['discovery', decorator.scopeKey],
    queryFn: ({ signal }) => dc.fetchServed(signal),
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
  })
  const isServed = useMemo(() => servedPredicate(q.data), [q.data])
  return { isServed, isLoading: q.isLoading, error: q.error }
}

export interface UseCanOptions {
  namespace?: string
  name?: string
  enabled?: boolean
}

export interface CanResult {
  allowed: boolean
  isLoading: boolean
}

/**
 * Gate an affordance on a SelfSubjectAccessReview. Optimistic: allowed until the
 * review explicitly returns `allowed: false`, so buttons don't flicker on load
 * and a failed review never falsely hides an action the server would permit.
 */
export function useCan(verb: Verb, gvr: GVR, opts: UseCanOptions = {}): CanResult {
  const client = useConsoleClient()
  const decorator = client.gvr.decorator
  const ac = useMemo(() => new AccessReviewClient({ decorator }), [decorator])
  const enabled = opts.enabled ?? true
  const q = useQuery({
    queryKey: ['ssar', decorator.scopeKey, verb, gvrKey(gvr), opts.namespace ?? '', opts.name ?? ''],
    queryFn: ({ signal }) => ac.canI({ verb, gvr, namespace: opts.namespace, name: opts.name }, signal),
    enabled,
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
  })
  return { allowed: q.data ?? true, isLoading: q.isLoading }
}
