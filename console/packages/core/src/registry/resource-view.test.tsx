// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient } from '@tanstack/react-query'
import { WatchManager, type Scheduler } from '../lib/watch-manager'
import { ConsoleProvider } from '../lib/hooks'
import type { ConsoleClient } from '../lib/console-client'
import { InMemoryClient } from '../lib/testing/in-memory-client'
import { createRegistry, defineResource } from './registry'
import { ResourceView } from './resource-view'
import { Badge } from '../components/ui/badge'
import type { GVR, K8sObject } from '../lib/k8s-types'

const gvr: GVR = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }
const noDelay: Scheduler = { sleep: () => Promise.resolve() }

interface Proxy extends K8sObject {
  status?: { phase?: string }
}
function proxy(name: string, phase = 'Healthy'): Proxy {
  return { metadata: { name, uid: name }, status: { phase } }
}

const registry = (detail?: ReturnType<typeof defineResource>['detail']) =>
  createRegistry([
    defineResource<Proxy>({
      kind: 'Proxy',
      group: 'core.apoxy.dev',
      resource: 'proxies',
      servedVersion: 'v1alpha2',
      sidebarGroup: 'Operate',
      columns: [
        { id: 'name', header: 'Name', cell: (o) => o.metadata.name },
        { id: 'status', header: 'Status', cell: (o) => <Badge variant="success">{o.status?.phase}</Badge> },
      ],
      detail: detail as never,
    }),
  ])

const managers: WatchManager[] = []
function harness(seed: K8sObject[] = []) {
  const fake = new InMemoryClient()
  fake.seed(gvr, seed)
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } },
  })
  const watchManager = new WatchManager(fake.asGVRClient(), queryClient, { scheduler: noDelay })
  managers.push(watchManager)
  const client: ConsoleClient = { queryClient, gvr: fake.asGVRClient(), watchManager }
  const wrapper = ({ children }: { children: ReactNode }) => (
    <ConsoleProvider client={client}>{children}</ConsoleProvider>
  )
  return { fake, client, wrapper }
}

afterEach(() => {
  cleanup()
  for (const m of managers.splice(0)) m.dispose()
})

describe('ResourceView (list)', () => {
  it('renders a table of rows from the entry columns', async () => {
    const { wrapper: W } = harness([proxy('alpha'), proxy('beta', 'Degraded')])
    render(<ResourceView registry={registry()} splat="proxies" />, { wrapper: W })

    expect(await screen.findByText('alpha')).toBeDefined()
    expect(screen.getByText('beta')).toBeDefined()
    // Column headers come from the registry entry.
    expect(screen.getByRole('columnheader', { name: 'Name' })).toBeDefined()
    expect(screen.getByRole('columnheader', { name: 'Status' })).toBeDefined()
  })

  it('links the first cell to the object detail route', async () => {
    const { wrapper: W } = harness([proxy('alpha')])
    render(<ResourceView registry={registry()} splat="proxies" />, { wrapper: W })
    const link = await screen.findByRole('link', { name: 'alpha' })
    expect(link.getAttribute('href')).toBe('/proxies/alpha')
  })

  it('shows an empty state when the collection is empty', async () => {
    const { wrapper: W } = harness([])
    render(<ResourceView registry={registry()} splat="proxies" />, { wrapper: W })
    expect(await screen.findByText(/No proxy yet\./i)).toBeDefined()
  })
})

describe('ResourceView (detail)', () => {
  it('renders the generic detail for slug/name', async () => {
    const { wrapper: W } = harness([proxy('alpha')])
    render(<ResourceView registry={registry()} splat="proxies/alpha" />, { wrapper: W })
    expect(await screen.findByRole('heading', { name: 'alpha' })).toBeDefined()
    // The generic body dumps the object; the uid appears in the JSON.
    expect(screen.getByText(/"uid": "alpha"/)).toBeDefined()
  })

  it('uses the entry detail escape hatch when present', async () => {
    const Custom = ({ object }: { object: K8sObject }) => <div>custom-{object.metadata.name}</div>
    const { wrapper: W } = harness([proxy('alpha')])
    render(<ResourceView registry={registry(Custom)} splat="proxies/alpha" />, { wrapper: W })
    expect(await screen.findByText('custom-alpha')).toBeDefined()
  })
})

describe('ResourceView (dispatch)', () => {
  it('renders a not-found message for an unknown slug', () => {
    const { wrapper: W } = harness([])
    render(<ResourceView registry={registry()} splat="widgets" />, { wrapper: W })
    expect(screen.getByText(/Unknown resource/i)).toBeDefined()
  })
})
