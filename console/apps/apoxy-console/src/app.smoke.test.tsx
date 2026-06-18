import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Sidebar, buildSidebar } from '@apoxy/console-core'
import { registry } from './registry'

// Hermetic app smoke (CI canary): drives the app's registry through
// console-core's chrome — no router, no apiserver. If @apoxy/console-core
// resolves across the workspace, its TSX compiles, and the registry composes,
// this passes, and it asserts the registry actually drives the sidebar.
describe('apoxy console', () => {
  it('registers the starter kinds in their sidebar groups', () => {
    expect(registry.all().map((e) => e.kind)).toEqual([
      'Proxy',
      'Backend',
      'Domain',
      'TunnelAgent',
      'Gateway',
      'GatewayClass',
      'HTTPRoute',
      'GRPCRoute',
      'TLSRoute',
    ])
    expect(registry.groups().map((g) => g.name)).toEqual(['Operate', 'Connect', 'Gateway'])
  })

  it('renders a registry-driven sidebar', () => {
    render(<Sidebar model={buildSidebar(registry)} />)
    expect(screen.getByText('Operate')).toBeDefined()
    expect(screen.getByText('Connect')).toBeDefined()
    expect(screen.getByRole('link', { name: 'Proxies' }).getAttribute('href')).toBe('/proxies')
    expect(screen.getByRole('link', { name: 'Tunnel agents' }).getAttribute('href')).toBe('/tunnelagents')
  })
})
