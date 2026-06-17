import { describe, expect, it, vi } from 'vitest'
import { createRegistry, defineResource } from '../registry/registry'
import { buildResourceCommands, filterCommands, isSubsequence, scoreCommand, type Command } from './commands'

function reg() {
  return createRegistry([
    defineResource({
      kind: 'Proxy',
      displayName: 'Proxies',
      group: 'core.apoxy.dev',
      resource: 'proxies',
      servedVersion: 'v1alpha2',
      sidebarGroup: 'Operate',
      columns: [],
    }),
    defineResource({
      kind: 'Gateway',
      displayName: 'Gateways',
      group: 'gateway.networking.k8s.io',
      resource: 'gateways',
      servedVersion: 'v1',
      sidebarGroup: 'Network',
      columns: [],
    }),
  ])
}

describe('buildResourceCommands', () => {
  it('emits one navigation command per entry', () => {
    const navigate = vi.fn()
    const cmds = buildResourceCommands(reg(), { navigate })
    expect(cmds.map((c) => c.title)).toEqual(['Proxies', 'Gateways'])
    cmds[0]!.run()
    expect(navigate).toHaveBeenCalledWith('/proxies')
    expect(cmds[1]!.subtitle).toBe('gateway.networking.k8s.io/v1')
  })

  it('hides commands for unserved GVRs', () => {
    const cmds = buildResourceCommands(reg(), {
      navigate: vi.fn(),
      isServed: (gvr) => gvr.resource === 'proxies',
    })
    expect(cmds.map((c) => c.title)).toEqual(['Proxies'])
  })
})

describe('scoreCommand', () => {
  const cmd: Command = {
    id: 'x',
    title: 'Gateways',
    subtitle: 'gateway.networking.k8s.io/v1',
    keywords: ['Gateway', 'gateways'],
    run: () => {},
  }
  it('ranks exact > prefix > substring > keyword > subtitle > fuzzy', () => {
    expect(scoreCommand(cmd, 'gateways')).toBeGreaterThan(scoreCommand(cmd, 'gate'))
    expect(scoreCommand(cmd, 'gate')).toBeGreaterThan(scoreCommand(cmd, 'ways'))
    expect(scoreCommand({ ...cmd, title: 'Zzz' }, 'gateway')).toBeGreaterThan(0) // keyword
    expect(scoreCommand({ ...cmd, title: 'Zzz', keywords: [] }, 'networking')).toBe(200) // subtitle
    expect(scoreCommand({ ...cmd, title: 'Gateways', keywords: [], subtitle: '' }, 'gtw')).toBe(100) // fuzzy
  })
  it('matches everything for a blank query', () => {
    expect(scoreCommand(cmd, '')).toBe(1)
  })
  it('ranks a tighter prefix above a longer one', () => {
    const gauge: Command = { id: 'g', title: 'Gauge', run: () => {} }
    const gateways: Command = { id: 'w', title: 'Gateways', run: () => {} }
    // Both prefix-match 'ga'; the shorter title is the closer hit.
    expect(scoreCommand(gauge, 'ga')).toBeGreaterThan(scoreCommand(gateways, 'ga'))
    // Prefix matches still outrank substring matches regardless of length.
    expect(scoreCommand(gateways, 'ga')).toBeGreaterThan(scoreCommand({ ...gateways, title: 'XGateways' }, 'ga'))
  })
})

describe('isSubsequence', () => {
  it('matches in-order characters', () => {
    expect(isSubsequence('gw', 'gateway')).toBe(true)
    expect(isSubsequence('wg', 'gateway')).toBe(false)
    expect(isSubsequence('', 'anything')).toBe(true)
  })
})

describe('filterCommands', () => {
  const commands: Command[] = [
    { id: 'a', title: 'Proxies', run: () => {} },
    { id: 'b', title: 'Gateways', keywords: ['gw'], run: () => {} },
    { id: 'c', title: 'Backends', run: () => {} },
  ]
  it('returns all for an empty query, in order', () => {
    expect(filterCommands(commands, '').map((c) => c.id)).toEqual(['a', 'b', 'c'])
  })
  it('filters and ranks by relevance', () => {
    expect(filterCommands(commands, 'gate').map((c) => c.id)).toEqual(['b'])
    expect(filterCommands(commands, 'xyz')).toEqual([])
  })
})
