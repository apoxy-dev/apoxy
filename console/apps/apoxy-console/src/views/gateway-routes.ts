// Pure Gateway-API relationship logic for the Gateway route browser (APO-782).
// The console never asks the apiserver "which routes attach to this gateway?" —
// that relationship is computed client-side from the single managed list of each
// route kind (ADR-0006: one cache writer, no per-gateway filtered caches). These
// helpers are the whole of that derivation, kept pure and dependency-free so the
// attachment rules are unit-tested without rendering the Miller browser.

import type { K8sObject } from '@apoxy/console-core'

export type RouteKind = 'HTTPRoute' | 'GRPCRoute' | 'TLSRoute'

export interface GatewayListener {
  name: string
  port?: number
  protocol?: string
  hostname?: string
}

interface Condition {
  type?: string
  status?: string
}

export interface GatewayObject extends K8sObject {
  spec?: { gatewayClassName?: string; listeners?: GatewayListener[] }
  status?: {
    listeners?: Array<{ name?: string; attachedRoutes?: number; conditions?: Condition[] }>
    conditions?: Condition[]
  }
}

export interface ParentRef {
  group?: string
  kind?: string
  name?: string
  namespace?: string
  sectionName?: string
  port?: number
}

export interface BackendRef {
  name?: string
  port?: number
  weight?: number
}

export interface RouteRule {
  matches?: Array<Record<string, unknown>>
  filters?: Array<{ type?: string }>
  backendRefs?: BackendRef[]
}

export interface RouteObject extends K8sObject {
  kind?: string
  spec?: { parentRefs?: ParentRef[]; hostnames?: string[]; rules?: RouteRule[] }
  status?: { parents?: Array<{ conditions?: Condition[] }> }
}

/** A stable id for a route across the three kinds (kind + namespace + name). */
export function routeId(r: RouteObject): string {
  return `${r.kind ?? 'Route'}/${r.metadata.namespace ?? ''}/${r.metadata.name ?? ''}`
}

/**
 * Whether a single `parentRef` targets `gw`: it names the gateway, is of kind
 * `Gateway` (or unset), and resolves to the gateway's namespace (a parentRef's
 * namespace defaults to the route's own). This is the one definition of "names
 * the gateway", shared by attachesToGateway and routesForListener so the two can
 * never disagree about which refs count.
 */
function refTargetsGateway(p: ParentRef, route: RouteObject, gw: GatewayObject): boolean {
  if (p.name !== gw.metadata.name) return false
  if (p.kind && p.kind !== 'Gateway') return false
  const refNs = p.namespace ?? route.metadata.namespace ?? ''
  return refNs === (gw.metadata.namespace ?? '')
}

/** Whether `route` attaches to `gw` via any of its parentRefs. */
export function attachesToGateway(route: RouteObject, gw: GatewayObject): boolean {
  return (route.spec?.parentRefs ?? []).some((p) => refTargetsGateway(p, route, gw))
}

/**
 * Routes bound to one listener: a parentRef that targets the gateway (see
 * {@link refTargetsGateway}) whose `sectionName` is that listener — or is unset,
 * which binds the route to every listener the gateway allows. The sectionName
 * test is applied to the *same* ref that targets the gateway, so a non-Gateway or
 * cross-namespace ref that merely shares the name can never bind a route here.
 */
export function routesForListener(
  routes: RouteObject[],
  gw: GatewayObject,
  listenerName: string | null,
): RouteObject[] {
  if (!listenerName) return []
  return routes.filter((r) =>
    (r.spec?.parentRefs ?? []).some(
      (p) => refTargetsGateway(p, r, gw) && (p.sectionName == null || p.sectionName === listenerName),
    ),
  )
}

/**
 * Route health from `status.parents[].conditions`, for the route row's pip — a
 * route is a top-level object with its own Accepted/ResolvedRefs status, so it
 * gets a green/red indicator independent of the listener it binds to. Any failing
 * condition is err; all-true is ok; no status yet is warn.
 */
export function routeHealth(route: RouteObject): 'ok' | 'warn' | 'err' {
  const parents = route.status?.parents ?? []
  let sawTrue = false
  for (const p of parents) {
    for (const c of p.conditions ?? []) {
      if (c.type !== 'Accepted' && c.type !== 'ResolvedRefs') continue
      if (c.status === 'False') return 'err'
      if (c.status === 'True') sawTrue = true
    }
  }
  return sawTrue ? 'ok' : 'warn'
}

/** Listener health from `status.listeners[].conditions`, for the row's pip. */
export function listenerHealth(gw: GatewayObject, name: string): 'ok' | 'warn' | 'err' {
  const ls = gw.status?.listeners?.find((l) => l.name === name)
  if (!ls) return 'warn'
  const cond = ls.conditions?.find((c) => c.type === 'Programmed' || c.type === 'Accepted' || c.type === 'Ready')
  if (cond?.status === 'True') return 'ok'
  if (cond?.status === 'False') return 'err'
  return 'warn'
}

/** A short, kind-aware summary of a rule's first match (column-3 row title). */
export function ruleMatchSummary(rule: RouteRule, kind: RouteKind): string {
  const m = rule.matches?.[0] as
    | { path?: { type?: string; value?: string }; method?: unknown; headers?: unknown[] }
    | undefined
  if (!m) return 'default'
  if (kind === 'GRPCRoute') {
    const gm = m.method as { service?: string; method?: string } | undefined
    if (gm?.service || gm?.method) return `${gm?.service ?? '*'}/${gm?.method ?? '*'}`
    return 'any method'
  }
  if (m.path?.value) return `${m.path.type ?? 'PathPrefix'} ${m.path.value}`
  if (typeof m.method === 'string') return `method ${m.method}`
  return 'match'
}
