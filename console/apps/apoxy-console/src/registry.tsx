// The apoxy console's resource registry: the kinds this app surfaces, composed
// from console-core's generic machinery. Adding a kind is an entry here — the
// sidebar, routes, breadcrumbs, list, and detail all derive from it. (In M5
// these move into per-API-group feature packages; this is the starter set.)

import { Badge, defineResource, createRegistry, type BadgeVariant, type K8sObject } from '@apoxy/console-core'
import { BareMetalServer, Connect, Gateway, Globe } from '@carbon/icons-react'
import type { ReactNode } from 'react'
import { schemaFor } from './schema/schema-for'

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
])
