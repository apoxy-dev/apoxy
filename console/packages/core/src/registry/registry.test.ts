import { describe, expect, it } from 'vitest'
import { createRegistry, defineResource } from './registry'
import type { ResourceColumn } from './types'
import type { K8sObject } from '../lib/k8s-types'

const nameCol: ResourceColumn = { id: 'name', header: 'Name', cell: (o) => o.metadata.name }

function proxies() {
  return defineResource({
    kind: 'Proxy',
    group: 'core.apoxy.dev',
    resource: 'proxies',
    servedVersion: 'v1alpha2',
    sidebarGroup: 'Operate',
    columns: [nameCol],
  })
}

describe('createRegistry', () => {
  it('derives the gvr from servedVersion and defaults path/displayName', () => {
    const reg = createRegistry([proxies()])
    const e = reg.byPath('proxies')
    expect(e).toBeDefined()
    expect(e!.gvr).toEqual({ group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' })
    expect(e!.path).toBe('proxies')
    expect(e!.displayName).toBe('Proxy')
    expect(e!.servedVersion).toBe('v1alpha2')
    expect(e!.yamlEditable).toBe(false)
    expect(e!.requires).toEqual([e!.gvr])
  })

  it('honors explicit path, displayName, requires, and yamlEditable', () => {
    const reg = createRegistry([
      defineResource({
        kind: 'Proxy',
        group: 'core.apoxy.dev',
        resource: 'proxies',
        servedVersion: 'v1alpha2',
        sidebarGroup: 'Operate',
        path: 'gateways',
        displayName: 'Gateways',
        yamlEditable: true,
        requires: [{ group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'backends' }],
        columns: [nameCol],
      }),
    ])
    const e = reg.byPath('gateways')!
    expect(e.displayName).toBe('Gateways')
    expect(e.yamlEditable).toBe(true)
    expect(e.requires).toEqual([{ group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'backends' }])
    expect(reg.byPath('proxies')).toBeUndefined()
  })

  it('looks an entry up by gvr', () => {
    const reg = createRegistry([proxies()])
    const e = reg.byGvr({ group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' })
    expect(e?.kind).toBe('Proxy')
    expect(reg.byGvr({ group: 'core.apoxy.dev', version: 'v1', resource: 'proxies' })).toBeUndefined()
  })

  it('groups entries preserving first-seen group order and within-group order', () => {
    const mk = (kind: string, resource: string, group: string) =>
      defineResource({ kind, group: 'core.apoxy.dev', resource, servedVersion: 'v1alpha2', sidebarGroup: group, columns: [nameCol] })
    const reg = createRegistry([
      mk('Proxy', 'proxies', 'Operate'),
      mk('Domain', 'domains', 'Operate'),
      mk('TunnelAgent', 'tunnelagents', 'Connect'),
      mk('Backend', 'backends', 'Operate'),
    ])
    const groups = reg.groups()
    expect(groups.map((g) => g.name)).toEqual(['Operate', 'Connect'])
    expect(groups[0]!.entries.map((e) => e.kind)).toEqual(['Proxy', 'Domain', 'Backend'])
    expect(groups[1]!.entries.map((e) => e.kind)).toEqual(['TunnelAgent'])
  })

  it('throws on a path containing a slash (unreachable via the splat route)', () => {
    expect(() =>
      createRegistry([
        defineResource({ kind: 'X', group: 'g', resource: 'xs', servedVersion: 'v1', sidebarGroup: 'G', path: 'a/b', columns: [nameCol] }),
      ]),
    ).toThrow(/single URL segment/)
  })

  it('throws on a duplicate slug', () => {
    const dup = (): ReturnType<typeof defineResource> =>
      defineResource({ kind: 'X', group: 'g', resource: 'proxies', servedVersion: 'v1', sidebarGroup: 'G', columns: [nameCol] })
    expect(() => createRegistry([dup(), dup()])).toThrow(/Duplicate registry path/)
  })

  it('preserves registration order in all()', () => {
    const mk = (kind: string, resource: string) =>
      defineResource({ kind, group: 'core.apoxy.dev', resource, servedVersion: 'v1alpha2', sidebarGroup: 'Operate', columns: [nameCol] })
    const reg = createRegistry([mk('Proxy', 'proxies'), mk('Backend', 'backends')])
    expect(reg.all().map((e: { kind: string }) => e.kind)).toEqual(['Proxy', 'Backend'])
  })

  it('keeps narrow typing through defineResource columns', () => {
    interface Proxy extends K8sObject {
      spec?: { hostname?: string }
    }
    const entry = defineResource<Proxy>({
      kind: 'Proxy',
      group: 'core.apoxy.dev',
      resource: 'proxies',
      servedVersion: 'v1alpha2',
      sidebarGroup: 'Operate',
      columns: [{ id: 'host', header: 'Host', cell: (o) => o.spec?.hostname ?? '—' }],
    })
    // The cell sees a Proxy, not a bare K8sObject.
    expect(entry.columns[0]!.cell({ metadata: { name: 'p' }, spec: { hostname: 'x' } })).toBe('x')
  })
})
