// The apoxy console's resource registry: the kinds this app surfaces, composed
// from console-core's generic machinery. Adding a kind is an entry here — the
// sidebar, routes, breadcrumbs, list, and detail all derive from it. (In M5
// these move into per-API-group feature packages; this is the starter set.)

import { Badge, defineResource, createRegistry, type BadgeVariant, type K8sObject } from '@apoxy/console-core'
import { BareMetalServer, Categories, Connect, FlowConnection, Gateway, GatewayApi, Globe, Locked, Roadmap } from '@carbon/icons-react'
import type { ReactNode } from 'react'
import { schemaFor } from './schema/schema-for'
import { GatewayDetail } from './views/gateway-detail'

/** Objects that carry a coarse status phase we can badge. */
interface Phased extends K8sObject {
  status?: { phase?: string }
  spec?: Record<string, unknown>
}

/**
 * Classify a free-form status phase into a badge variant. A *negated* positive
 * (`NotReady`, `Not Ready`, `not-ready`, `Unhealthy`, `NodeNotReady`) is checked
 * first and forced to danger, so a broken resource never renders green just
 * because its phase happens to contain the word `ready`/`healthy`. Order is
 * negation → danger → warning → success → neutral.
 */
export function phaseVariant(phase?: string): BadgeVariant {
  const p = (phase ?? '').toLowerCase()
  // `not<sep?>positive` with no leading boundary also catches glued compounds
  // (nodenotready); `un<positive>` catches unhealthy/unready/unavailable.
  const negated =
    /not[\s_-]?(ready|healthy|available|running|active|bound|reachable)\b/.test(p) ||
    /\bun(ready|healthy|available|reachable)\b/.test(p)
  if (negated || /\b(failed|error|errored|lost|crashloopbackoff|terminated|denied|evicted)\b/.test(p)) {
    return 'danger'
  }
  if (/\b(pending|progressing|degraded|provisioning|updating|unknown|terminating|creating)\b/.test(p)) {
    return 'warning'
  }
  if (/\b(ready|healthy|running|active|available|bound|succeeded)\b/.test(p)) {
    return 'success'
  }
  return 'neutral'
}

function phaseBadge(phase?: string): ReactNode {
  return <Badge variant={phaseVariant(phase)}>{phase ?? 'Unknown'}</Badge>
}

/** ISO date prefix (no Date parsing) for a `creationTimestamp`. */
function created(obj: K8sObject): string {
  return obj.metadata.creationTimestamp?.slice(0, 10) ?? '—'
}

// Carbon icons (sized to the 16px rail glyph) replace the design's hand-drawn set.
const proxyIcon = <Gateway size={16} />
const backendIcon = <BareMetalServer size={16} />
const domainIcon = <Globe size={16} />
const tunnelIcon = <Connect size={16} />

const nameCol = { id: 'name', header: 'Name', width: '34%', cell: (o: K8sObject) => o.metadata.name }
const statusCol = { id: 'status', header: 'Status', cell: (o: Phased) => phaseBadge(o.status?.phase) }
const createdCol = { id: 'created', header: 'Created', mono: true, cell: created }

// Gateway-API columns: these kinds carry their state in `status.conditions`, not
// a coarse `status.phase`, so they show structural columns instead of a badge.
const classCol = { id: 'class', header: 'Class', cell: (o: Phased) => (o.spec?.gatewayClassName as string) ?? '—' }
const listenersCol = {
  id: 'listeners',
  header: 'Listeners',
  mono: true,
  cell: (o: Phased) => String((o.spec?.listeners as unknown[] | undefined)?.length ?? 0),
}
const controllerCol = { id: 'controller', header: 'Controller', mono: true, cell: (o: Phased) => (o.spec?.controllerName as string) ?? '—' }
const hostnamesCol = {
  id: 'hostnames',
  header: 'Hostnames',
  mono: true,
  cell: (o: Phased) => {
    const h = o.spec?.hostnames as string[] | undefined
    return h && h.length > 0 ? h.join(', ') : '*'
  },
}

export const registry = createRegistry([
  defineResource<Phased>({
    kind: 'Proxy',
    displayName: 'Proxies',
    group: 'core.apoxy.dev',
    resource: 'proxies',
    servedVersion: 'v1alpha2',
    sidebarGroup: 'Operate',
    icon: proxyIcon,
    shortcut: 'p',
    yamlEditable: true,
    schema: schemaFor('core.apoxy.dev', 'v1alpha2', 'Proxy'),
    columns: [nameCol, statusCol, createdCol],
  }),
  defineResource<Phased>({
    kind: 'Backend',
    displayName: 'Backends',
    group: 'core.apoxy.dev',
    resource: 'backends',
    servedVersion: 'v1alpha2',
    sidebarGroup: 'Operate',
    icon: backendIcon,
    shortcut: 'b',
    yamlEditable: true,
    schema: schemaFor('core.apoxy.dev', 'v1alpha2', 'Backend'),
    columns: [nameCol, statusCol, createdCol],
  }),
  defineResource<Phased>({
    kind: 'Domain',
    displayName: 'Domains',
    group: 'core.apoxy.dev',
    resource: 'domains',
    servedVersion: 'v1alpha2',
    sidebarGroup: 'Operate',
    icon: domainIcon,
    shortcut: 'd',
    yamlEditable: true,
    // No schema is generated for kind "Domain": the served kind is DomainZone
    // (this entry's kind/resource are an M5 follow-up). The tray falls back to
    // the always-on structural checks until the kind is reconciled.
    schema: schemaFor('core.apoxy.dev', 'v1alpha2', 'Domain'),
    columns: [nameCol, statusCol, createdCol],
  }),
  defineResource<Phased>({
    kind: 'TunnelAgent',
    displayName: 'Tunnel agents',
    group: 'core.apoxy.dev',
    resource: 'tunnelagents',
    servedVersion: 'v1alpha2',
    sidebarGroup: 'Connect',
    icon: tunnelIcon,
    shortcut: 't',
    columns: [nameCol, statusCol, createdCol],
  }),
  // Gateway-API kinds (APO-782). The Gateway detail is the Miller route browser
  // (Listeners → Routes → Rules → Targets); the rest use the generic views.
  defineResource<Phased>({
    kind: 'Gateway',
    displayName: 'Gateways',
    group: 'gateway.apoxy.dev',
    resource: 'gateways',
    servedVersion: 'v1',
    sidebarGroup: 'Gateway',
    icon: <GatewayApi size={16} />,
    shortcut: 'g',
    yamlEditable: true,
    schema: schemaFor('gateway.apoxy.dev', 'v1', 'Gateway'),
    detail: GatewayDetail,
    columns: [nameCol, classCol, listenersCol, createdCol],
  }),
  defineResource<Phased>({
    kind: 'GatewayClass',
    displayName: 'Gateway classes',
    group: 'gateway.apoxy.dev',
    resource: 'gatewayclasses',
    servedVersion: 'v1',
    sidebarGroup: 'Gateway',
    icon: <Categories size={16} />,
    yamlEditable: true,
    schema: schemaFor('gateway.apoxy.dev', 'v1', 'GatewayClass'),
    columns: [nameCol, controllerCol, createdCol],
  }),
  defineResource<Phased>({
    kind: 'HTTPRoute',
    displayName: 'HTTP routes',
    group: 'gateway.apoxy.dev',
    resource: 'httproutes',
    servedVersion: 'v1',
    sidebarGroup: 'Gateway',
    icon: <Roadmap size={16} />,
    yamlEditable: true,
    schema: schemaFor('gateway.apoxy.dev', 'v1', 'HTTPRoute'),
    columns: [nameCol, hostnamesCol, createdCol],
  }),
  defineResource<Phased>({
    kind: 'GRPCRoute',
    displayName: 'gRPC routes',
    group: 'gateway.apoxy.dev',
    resource: 'grpcroutes',
    servedVersion: 'v1',
    sidebarGroup: 'Gateway',
    icon: <FlowConnection size={16} />,
    yamlEditable: true,
    schema: schemaFor('gateway.apoxy.dev', 'v1', 'GRPCRoute'),
    columns: [nameCol, hostnamesCol, createdCol],
  }),
  defineResource<Phased>({
    kind: 'TLSRoute',
    displayName: 'TLS routes',
    group: 'gateway.apoxy.dev',
    resource: 'tlsroutes',
    servedVersion: 'v1alpha2',
    sidebarGroup: 'Gateway',
    icon: <Locked size={16} />,
    yamlEditable: true,
    schema: schemaFor('gateway.apoxy.dev', 'v1alpha2', 'TLSRoute'),
    columns: [nameCol, hostnamesCol, createdCol],
  }),
])
