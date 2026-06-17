// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient } from '@tanstack/react-query'
import { WatchManager, type Scheduler } from '../lib/watch-manager'
import { ConsoleProvider } from '../lib/hooks'
import { KeyboardScopeProvider } from '../keyboard/scope-stack'
import { LinkProvider, type LinkComponent } from '../components/chrome/link-context'
import type { ConsoleClient } from '../lib/console-client'
import { InMemoryClient } from '../lib/testing/in-memory-client'
import { createRegistry, defineResource } from './registry'
import { ResourceView } from './resource-view'
import type { GVR, K8sObject } from '../lib/k8s-types'

const gvr: GVR = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }
const noDelay: Scheduler = { sleep: () => Promise.resolve() }

const Anchor: LinkComponent = ({ to, children, ...rest }) => (
  <a href={to} {...rest}>
    {children}
  </a>
)

function proxy(name: string): K8sObject {
  return { apiVersion: 'core.apoxy.dev/v1alpha2', kind: 'Proxy', metadata: { name, uid: name } } as K8sObject
}

const registry = createRegistry([
  defineResource({
    kind: 'Proxy',
    group: 'core.apoxy.dev',
    resource: 'proxies',
    servedVersion: 'v1alpha2',
    sidebarGroup: 'Operate',
    columns: [{ id: 'name', header: 'Name', cell: (o) => o.metadata.name }],
  }),
])

const managers: WatchManager[] = []
function harness(seed: K8sObject[]) {
  const navigate = vi.fn()
  const fake = new InMemoryClient()
  fake.seed(gvr, seed)
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } },
  })
  const watchManager = new WatchManager(fake.asGVRClient(), queryClient, { scheduler: noDelay })
  managers.push(watchManager)
  const client: ConsoleClient = { queryClient, gvr: fake.asGVRClient(), watchManager }
  const wrapper = ({ children }: { children: ReactNode }) => (
    <KeyboardScopeProvider isMac={false}>
      <ConsoleProvider client={client}>
        <LinkProvider component={Anchor} navigate={navigate}>
          {children}
        </LinkProvider>
      </ConsoleProvider>
    </KeyboardScopeProvider>
  )
  return { fake, navigate, wrapper }
}

afterEach(() => {
  cleanup()
  for (const m of managers.splice(0)) m.dispose()
})

describe('ResourceListView keyboard', () => {
  it('moves the row cursor with j/k and opens with Enter', async () => {
    const { navigate, wrapper: W } = harness([proxy('alpha'), proxy('beta')])
    render(<ResourceView registry={registry} splat="proxies" />, { wrapper: W })
    await screen.findByText('alpha')
    fireEvent.keyDown(document.body, { key: 'j' }) // -1 -> 0
    fireEvent.keyDown(document.body, { key: 'j' }) // 0 -> 1
    fireEvent.keyDown(document.body, { key: 'Enter' })
    expect(navigate).toHaveBeenCalledWith('/proxies/beta')
  })

  it('moves the cursor with ArrowDown when the table is focused', async () => {
    const { wrapper: W } = harness([proxy('alpha'), proxy('beta')])
    const { container } = render(<ResourceView registry={registry} splat="proxies" />, { wrapper: W })
    await screen.findByText('alpha')
    const focusable = container.querySelector('[tabindex="0"]') as HTMLElement
    focusable.focus()
    fireEvent.keyDown(focusable, { key: 'ArrowDown' })
    const selected = screen.getAllByRole('row').filter((r) => r.getAttribute('aria-selected') === 'true')
    expect(selected).toHaveLength(1)
  })

  it('defers Enter to a focused row link rather than the cursor row', async () => {
    const { navigate, wrapper: W } = harness([proxy('alpha'), proxy('beta')])
    render(<ResourceView registry={registry} splat="proxies" />, { wrapper: W })
    await screen.findByText('alpha')
    fireEvent.keyDown(document.body, { key: 'j' }) // cursor -> 0 (alpha)
    fireEvent.keyDown(document.body, { key: 'j' }) // cursor -> 1 (beta)
    const alphaLink = screen.getByRole('link', { name: 'alpha' })
    alphaLink.focus()
    fireEvent.keyDown(alphaLink, { key: 'Enter' }) // the link owns Enter
    expect(navigate).not.toHaveBeenCalled() // cursor row (beta) is NOT activated
  })
})
