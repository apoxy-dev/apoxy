import { describe, expect, it } from 'vitest'
import { createRegistry, defineResource } from './registry'
import { buildBreadcrumbs, buildSidebar } from './nav'
import type { ResourceColumn } from './types'
import type { GVR } from '../lib/k8s-types'
import { gvrKey } from '../lib/cache-keys'

const nameCol: ResourceColumn = { id: 'name', header: 'Name', cell: (o) => o.metadata.name }

const mk = (kind: string, resource: string, group: string, requires?: GVR[]) =>
  defineResource({
    kind,
    group: 'core.apoxy.dev',
    resource,
    servedVersion: 'v1alpha2',
    sidebarGroup: group,
    requires,
    columns: [nameCol],
  })

const registry = () =>
  createRegistry([
    mk('Proxy', 'proxies', 'Operate'),
    mk('Backend', 'backends', 'Operate'),
    mk('TunnelAgent', 'tunnelagents', 'Connect'),
  ])

describe('buildSidebar', () => {
  it('groups entries and links to their slugs', () => {
    const model = buildSidebar(registry())
    expect(model.groups.map((g) => g.name)).toEqual(['Operate', 'Connect'])
    expect(model.groups[0]!.items.map((i) => i.to)).toEqual(['/proxies', '/backends'])
    expect(model.groups[0]!.items[0]!.label).toBe('Proxy')
  })

  it('shows everything when isServed is omitted', () => {
    const model = buildSidebar(registry())
    expect(model.groups.flatMap((g) => g.items)).toHaveLength(3)
  })

  it('hides entries whose required GVRs are not served', () => {
    const served = new Set([
      gvrKey({ group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }),
    ])
    const model = buildSidebar(registry(), { isServed: (gvr) => served.has(gvrKey(gvr)) })
    expect(model.groups.map((g) => g.name)).toEqual(['Operate'])
    expect(model.groups[0]!.items.map((i) => i.kind)).toEqual(['Proxy'])
  })

  it('respects an explicit requires[] (a kind gated on a different GVR)', () => {
    const reg = createRegistry([
      mk('VirtualProxy', 'virtualproxies', 'Operate', [
        { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'backends' },
      ]),
    ])
    const servedWithoutBackends = buildSidebar(reg, { isServed: () => false })
    expect(servedWithoutBackends.groups).toHaveLength(0)
    const servedWithBackends = buildSidebar(reg, { isServed: () => true })
    expect(servedWithBackends.groups[0]!.items).toHaveLength(1)
  })
})

describe('buildBreadcrumbs', () => {
  const entry = registry().byPath('proxies')

  it('makes the kind current on a list view', () => {
    const crumbs = buildBreadcrumbs(entry)
    expect(crumbs).toEqual([{ label: 'Proxy', to: undefined }])
  })

  it('links the kind and makes the name current on a detail view', () => {
    const crumbs = buildBreadcrumbs(entry, 'my-proxy')
    expect(crumbs).toEqual([{ label: 'Proxy', to: '/proxies' }, { label: 'my-proxy' }])
  })

  it('prepends a root crumb when given', () => {
    const crumbs = buildBreadcrumbs(entry, 'my-proxy', { root: { label: 'Acme', to: '/' } })
    expect(crumbs[0]).toEqual({ label: 'Acme', to: '/' })
    expect(crumbs).toHaveLength(3)
  })

  it('returns just the root for an unknown entry', () => {
    expect(buildBreadcrumbs(undefined, undefined, { root: { label: 'Home', to: '/' } })).toEqual([
      { label: 'Home', to: '/' },
    ])
  })
})
