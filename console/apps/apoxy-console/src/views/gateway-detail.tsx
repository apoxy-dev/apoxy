// Custom detail view for a Gateway (APO-782): the Routing tab is a four-column
// Miller drill-down — Listeners → Routes attached → Rules → Targets · apparent
// path — built on console-core's generic <MillerBrowser>. The gateway↔route
// relationship is derived client-side from the managed HTTPRoute/GRPCRoute/
// TLSRoute lists (see gateway-routes.ts); no per-gateway query is issued. The
// browser itself is kind-agnostic, so clrk's EgressGateway reuses it with its own
// getItems. Layout mirrors the CLRK design: tabs sit above the summary cards (the
// cards belong to the routing tab), a filter box sits above the columns, and the
// rightmost column ends in an "apparent path" trace of where a request goes.

import { useCallback, useMemo, type ReactNode } from 'react'
import {
  MillerBrowser,
  useK8sList,
  type GVR,
  type K8sList,
  type MillerColumnDef,
  type MillerItem,
  type ResourceDetailProps,
} from '@apoxy/console-core'
import {
  attachesToGateway,
  listenerHealth,
  routeHealth,
  routeId,
  routesForListener,
  ruleMatchSummary,
  type GatewayListener,
  type GatewayObject,
  type RouteKind,
  type RouteObject,
  type RouteRule,
} from './gateway-routes'

const HTTPROUTE_GVR: GVR = { group: 'gateway.apoxy.dev', version: 'v1', resource: 'httproutes' }
const GRPCROUTE_GVR: GVR = { group: 'gateway.apoxy.dev', version: 'v1', resource: 'grpcroutes' }
const TLSROUTE_GVR: GVR = { group: 'gateway.apoxy.dev', version: 'v1alpha2', resource: 'tlsroutes' }

export function GatewayDetail({ object }: ResourceDetailProps) {
  const gw = object as GatewayObject
  const http = useK8sList<RouteObject>(HTTPROUTE_GVR)
  const grpc = useK8sList<RouteObject>(GRPCROUTE_GVR)
  const tls = useK8sList<RouteObject>(TLSROUTE_GVR)

  const routes = useMemo(() => {
    const tag = (list: K8sList<RouteObject> | undefined, kind: RouteKind): RouteObject[] =>
      (list?.items ?? []).map((r) => ({ ...r, kind }))
    return [...tag(http.data, 'HTTPRoute'), ...tag(grpc.data, 'GRPCRoute'), ...tag(tls.data, 'TLSRoute')].filter((r) =>
      attachesToGateway(r, gw),
    )
  }, [http.data, grpc.data, tls.data, gw])

  // Memoized so getItems stays referentially stable across renders (the browser
  // recomputes its columns only when listeners/routes actually change).
  const listeners = useMemo(() => gw.spec?.listeners ?? [], [gw])

  const getItems = useCallback(
    (col: number, selected: (string | null)[], query: string): MillerItem[] => {
      if (col === 0) {
        return listeners.map((l) => ({
          id: l.name,
          name: l.name,
          status: listenerHealth(gw, l.name),
          sub: <ProtoBadge protocol={l.protocol} port={l.port} hostname={l.hostname} />,
        }))
      }
      if (col === 1) {
        const q = query.trim().toLowerCase()
        let rs = routesForListener(routes, gw, selected[0] ?? null)
        if (q) {
          rs = rs.filter(
            (r) =>
              (r.spec?.hostnames ?? []).some((h) => h.toLowerCase().includes(q)) ||
              (r.metadata.name ?? '').toLowerCase().includes(q) ||
              (r.kind ?? '').toLowerCase().includes(q),
          )
        }
        return rs.map((r) => ({
          id: routeId(r),
          name: r.spec?.hostnames?.join(', ') || '*',
          mono: true,
          status: routeHealth(r),
          sub: (
            <>
              <RouteKindTag kind={(r.kind as RouteKind) ?? 'HTTPRoute'} />
              <span>{r.metadata.name}</span>
              <span>· {pluralize(r.spec?.rules?.length ?? 0, 'rule')}</span>
            </>
          ),
        }))
      }
      const route = routesForListener(routes, gw, selected[0] ?? null).find((r) => routeId(r) === selected[1])
      if (col === 2) {
        return (route?.spec?.rules ?? []).map((rule, i) => ({
          id: String(i),
          name: ruleMatchSummary(rule, (route?.kind as RouteKind) ?? 'HTTPRoute'),
          sub:
            rule.filters && rule.filters.length > 0 ? (
              <>
                {rule.filters.map((f, j) => (
                  <span key={j} className={CHIP}>
                    {f.type ?? 'filter'}
                  </span>
                ))}
              </>
            ) : (
              <span className="text-[color:var(--text-disabled)]">—</span>
            ),
        }))
      }
      const rule = route?.spec?.rules?.[Number(selected[2])]
      return (rule?.backendRefs ?? []).map((b, i) => ({
        id: String(i),
        name: b.name ?? '—',
        mono: true,
        status: 'ok' as const,
        sub: b.port != null ? `:${b.port}` : undefined,
        ...(b.weight != null ? { meter: { value: b.weight, canary: b.weight <= 10 } } : {}),
      }))
    },
    [listeners, routes, gw],
  )

  const ruleCount = routes.reduce((s, r) => s + (r.spec?.rules?.length ?? 0), 0)
  // The initial LIST of all three route kinds is still in flight: distinguish
  // "still loading" from a real "nothing attached", so a cold cache never flashes
  // a definitive empty config (0 routes, "No routes attached") before data lands.
  const loading = http.isPending || grpc.isPending || tls.isPending

  const columns = useMemo<MillerColumnDef[]>(
    () => [
      { id: 'listeners', label: 'Listeners' },
      {
        id: 'routes',
        label: 'Routes attached',
        emptyMessage: loading ? 'Loading…' : 'No routes attached to this listener.',
      },
      { id: 'rules', label: 'Rules', emptyMessage: 'Pick a route' },
      {
        id: 'targets',
        label: 'Targets · apparent path',
        emptyMessage: 'Pick a rule',
        footer: (selected) => {
          const listener = listeners.find((l) => l.name === selected[0])
          const route = routesForListener(routes, gw, selected[0] ?? null).find((r) => routeId(r) === selected[1])
          const rule = route?.spec?.rules?.[Number(selected[2])]
          if (!listener || !route || !rule) return null
          return <ApparentPath listener={listener} route={route} rule={rule} />
        },
      },
    ],
    [loading, listeners, routes, gw],
  )

  return (
    <div className="flex flex-col gap-[var(--sp-4)]">
      <TabBar active="routing" tabs={[{ id: 'routing', label: 'Routing', count: loading ? undefined : routes.length }]} />
      <StatStrip
        stats={[
          { lab: 'Listeners', val: listeners.length },
          {
            lab: 'Routes attached',
            val: loading ? '…' : routes.length,
            unit: loading ? undefined : pluralize(ruleCount, 'rule'),
          },
          { lab: 'Class', val: gw.spec?.gatewayClassName ?? '—', mono: true },
          { lab: 'Status', val: <GatewayStatusText gw={gw} /> },
        ]}
      />
      <MillerBrowser
        columns={columns}
        getItems={getItems}
        template="1.1fr 1.5fr 1.5fr 1.7fr"
        searchPlaceholder="Filter routes, hostnames, kinds…"
        ariaLabel={loading ? 'Gateway routes (loading)' : 'Gateway routes'}
      />
    </div>
  )
}

// ── local presentational helpers (app-specific; the reusable piece is the
//    MillerBrowser in console-core) ───────────────────────────────────────────

const CHIP =
  'inline-flex items-center rounded-none border border-[color:var(--border-default)] bg-[var(--apx-paper)] px-[8px] py-[2px] font-mono text-[length:var(--t-micro)] text-[color:var(--text-secondary)]'

function pluralize(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`
}

// The "apparent path": a monospace trace of where a request entering this
// listener actually goes once the selected rule applies — listener address, the
// matched route/rule, each filter, and the resolved backend(s) or the upstream it
// falls through to. Mirrors the CLRK design's Targets · apparent path block.
function ApparentPath({ listener, route, rule }: { listener: GatewayListener; route: RouteObject; rule: RouteRule }) {
  const proto = (listener.protocol ?? 'HTTP').toLowerCase()
  const host = route.spec?.hostnames?.[0] ?? '*'
  const kind = (route.kind as RouteKind) ?? 'HTTPRoute'
  const backends = rule.backendRefs ?? []
  return (
    <div className="mt-[6px] border-t border-[color:var(--border-subtle)] px-[14px] py-[16px]">
      <div className="mb-[8px] text-[length:var(--t-overline)] font-medium uppercase tracking-[0.12em] text-[color:var(--text-muted)]">
        Apparent path
      </div>
      <div className="whitespace-pre font-mono text-[length:var(--t-micro)] leading-[1.7] text-[color:var(--text-secondary)]">
        <div>
          {proto}://{host}
          {listener.port != null ? `:${listener.port}` : ''}
        </div>
        <div className="text-[color:var(--apx-slate)]">
          {'  └─ '}
          <RouteKindTag kind={kind} /> {ruleMatchSummary(rule, kind)}
        </div>
        {(rule.filters ?? []).map((f, i) => (
          <div key={i} className="text-[color:var(--apx-blue-deep)]">
            {`     ↳ ${f.type ?? 'filter'}`}
          </div>
        ))}
        {backends.length > 0 ? (
          backends.map((b, i) => (
            <div key={i}>
              {`     → ${b.name ?? '—'}${b.port != null ? `:${b.port}` : ''}`}
              {b.weight != null && <span className="text-[color:var(--apx-slate)]"> ({b.weight}%)</span>}
            </div>
          ))
        ) : (
          <div>{`     → upstream ${host}`}</div>
        )}
      </div>
    </div>
  )
}

function StatStrip({ stats }: { stats: Array<{ lab: string; val: ReactNode; unit?: string; mono?: boolean }> }) {
  return (
    <div
      className="grid rounded-none border border-[color:var(--border-default)] bg-[var(--apx-white)]"
      style={{ gridTemplateColumns: `repeat(${stats.length}, minmax(0, 1fr))` }}
    >
      {stats.map((s, i) => (
        <div
          key={s.lab}
          className={i < stats.length - 1 ? 'border-r border-[color:var(--border-default)] px-[18px] py-[14px]' : 'px-[18px] py-[14px]'}
        >
          <div className="text-[length:var(--t-overline)] font-medium uppercase tracking-[0.12em] text-[color:var(--text-muted)]">
            {s.lab}
          </div>
          <div
            className={
              'mt-[4px] flex items-baseline gap-[6px] text-[28px] font-medium leading-[1.1] tracking-[-0.01em] text-[color:var(--text-primary)]' +
              (s.mono ? ' font-mono' : ' font-[family-name:var(--font-display)]')
            }
          >
            <span className="truncate">{s.val}</span>
            {s.unit && <span className="text-[length:var(--t-body-sm)] font-normal text-[color:var(--text-muted)]">· {s.unit}</span>}
          </div>
        </div>
      ))}
    </div>
  )
}

function TabBar({ active, tabs }: { active: string; tabs: Array<{ id: string; label: string; count?: number }> }) {
  return (
    <div className="flex items-center gap-[2px] border-b border-[color:var(--border-default)]">
      {tabs.map((t) => (
        <div
          key={t.id}
          className={
            'flex items-center gap-[6px] border-b-2 px-[14px] py-[10px] text-[length:var(--t-body-sm)] ' +
            (t.id === active
              ? 'border-b-[color:var(--apx-ink)] font-medium text-[color:var(--text-primary)]'
              : 'border-b-transparent text-[color:var(--text-muted)]')
          }
        >
          {t.label}
          {t.count != null && (
            <span className="font-mono text-[length:var(--t-micro)] text-[color:var(--text-muted)]">{t.count}</span>
          )}
        </div>
      ))}
    </div>
  )
}

function ProtoBadge({ protocol, port, hostname }: { protocol?: string; port?: number; hostname?: string }) {
  const isTls = protocol === 'HTTPS' || protocol === 'TLS'
  return (
    <span className="flex items-center gap-[6px]">
      <span
        className={
          'rounded-none border px-[5px] py-[1px] font-mono text-[length:var(--t-micro)] tracking-[0.06em] ' +
          (isTls
            ? 'border-[color:var(--apx-blue-deep)] bg-[var(--apx-blue-tint)] text-[color:var(--apx-blue-deep)]'
            : 'border-[color:var(--border-default)] bg-[var(--apx-paper)] text-[color:var(--text-secondary)]')
        }
      >
        {protocol ?? '—'}
      </span>
      {port != null && <span>:{port}</span>}
      {hostname && <span className="text-[color:var(--text-muted)]">{hostname}</span>}
    </span>
  )
}

function RouteKindTag({ kind }: { kind: RouteKind }) {
  const short = kind.replace('Route', '').toUpperCase()
  return (
    <span className="inline-flex items-center rounded-none border border-[color:var(--apx-ink)] px-[6px] py-[2px] font-mono text-[length:var(--t-micro)] uppercase tracking-[0.1em] text-[color:var(--apx-ink)]">
      {short}
    </span>
  )
}

function GatewayStatusText({ gw }: { gw: GatewayObject }) {
  const cond = gw.status?.conditions?.find((c) => c.type === 'Programmed' || c.type === 'Accepted')
  const ok = cond?.status === 'True'
  return (
    <span className={ok ? 'text-[color:var(--apx-leaf)]' : 'text-[color:var(--text-muted)]'}>{ok ? 'Ready' : 'Pending'}</span>
  )
}
