// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { Sidebar } from './sidebar'
import { Breadcrumbs } from './breadcrumbs'
import { LinkProvider, type NavLinkProps } from './link-context'
import type { SidebarModel } from '../../registry/nav'

afterEach(cleanup)

const model: SidebarModel = {
  groups: [
    {
      name: 'Operate',
      items: [
        { to: '/proxies', label: 'Proxies', kind: 'Proxy', gvr: { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' } },
        { to: '/backends', label: 'Backends', kind: 'Backend', gvr: { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'backends' } },
      ],
    },
  ],
}

describe('Sidebar', () => {
  it('renders grouped nav items as anchor links by default', () => {
    render(<Sidebar model={model} activePath="/proxies" />)
    expect(screen.getByText('Operate')).toBeDefined()
    const active = screen.getByRole('link', { name: 'Proxies' })
    expect(active.getAttribute('href')).toBe('/proxies')
    expect(active.getAttribute('aria-current')).toBe('page')
    expect(screen.getByRole('link', { name: 'Backends' }).getAttribute('aria-current')).toBeNull()
  })

  it('routes through an injected link component', () => {
    const Custom = ({ to, children }: NavLinkProps) => (
      <a data-testid="custom" href={'#' + to}>
        {children}
      </a>
    )
    render(
      <LinkProvider component={Custom}>
        <Sidebar model={model} />
      </LinkProvider>,
    )
    expect(screen.getAllByTestId('custom')).toHaveLength(2)
    expect(screen.getByRole('link', { name: 'Proxies' }).getAttribute('href')).toBe('#/proxies')
  })

  it('renders a collapse toggle only when a handler is given', () => {
    const { rerender } = render(<Sidebar model={model} />)
    expect(screen.queryByRole('button', { name: /sidebar/i })).toBeNull()
    rerender(<Sidebar model={model} onToggleCollapsed={() => {}} />)
    expect(screen.getByRole('button', { name: 'Collapse sidebar' })).toBeDefined()
  })

  it('collapses to icon-only: labels hidden, items still named, toggle fires', () => {
    const onToggle = vi.fn()
    render(<Sidebar model={model} collapsed onToggleCollapsed={onToggle} />)
    // Group label is replaced by a divider; visible label text is gone…
    expect(screen.queryByText('Operate')).toBeNull()
    // …but the item keeps its accessible name (aria-label) for screen readers.
    expect(screen.getByRole('link', { name: 'Proxies' })).toBeDefined()
    fireEvent.click(screen.getByRole('button', { name: 'Expand sidebar' }))
    expect(onToggle).toHaveBeenCalledOnce()
  })
})

describe('Breadcrumbs', () => {
  it('links intermediate crumbs and marks the last as current', () => {
    render(<Breadcrumbs items={[{ label: 'Proxies', to: '/proxies' }, { label: 'alpha' }]} />)
    expect(screen.getByRole('link', { name: 'Proxies' }).getAttribute('href')).toBe('/proxies')
    expect(screen.getByText('alpha').getAttribute('aria-current')).toBe('page')
  })

  it('does not link a single current crumb', () => {
    render(<Breadcrumbs items={[{ label: 'Proxies', to: '/proxies' }]} />)
    // Sole crumb is the current location → rendered as text, not a link.
    expect(screen.queryByRole('link')).toBeNull()
    expect(screen.getByText('Proxies').getAttribute('aria-current')).toBe('page')
  })
})
