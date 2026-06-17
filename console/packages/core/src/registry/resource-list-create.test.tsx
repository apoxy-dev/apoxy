// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient } from '@tanstack/react-query'
import { WatchManager, type Scheduler } from '../lib/watch-manager'
import { ConsoleProvider } from '../lib/hooks'
import type { ConsoleClient } from '../lib/console-client'
import { InMemoryClient } from '../lib/testing/in-memory-client'
import { KeyboardScopeProvider } from '../keyboard/scope-stack'
import { CreateProvider } from '../yaml/create-context'
import { createRegistry, defineResource } from './registry'
import { ResourceListView } from './resource-list-view'
import type { GVR, K8sObject } from '../lib/k8s-types'

const gvr: GVR = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }
const noDelay: Scheduler = { sleep: () => Promise.resolve() }

function proxy(name: string): K8sObject {
  return { apiVersion: 'core.apoxy.dev/v1alpha2', kind: 'Proxy', metadata: { name, uid: name } } as K8sObject
}

const entry = createRegistry([
  defineResource({
    kind: 'Proxy',
    displayName: 'Proxies',
    group: 'core.apoxy.dev',
    resource: 'proxies',
    servedVersion: 'v1alpha2',
    sidebarGroup: 'Operate',
    yamlEditable: true,
    columns: [{ id: 'name', header: 'Name', cell: (o) => o.metadata.name }],
  }),
]).all()[0]!

const managers: WatchManager[] = []
let ssarAllowed = true
beforeEach(() => {
  ssarAllowed = true
  vi.stubGlobal('fetch', () =>
    Promise.resolve({ ok: true, json: async () => ({ status: { allowed: ssarAllowed } }) } as Response),
  )
})
afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
  for (const m of managers.splice(0)) m.dispose()
})

/** Mount the list view, optionally inside a CreateProvider. */
function mount(opts: { withProvider: boolean; seed?: K8sObject[] }) {
  const fake = new InMemoryClient()
  fake.seed(gvr, opts.seed ?? [])
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } },
  })
  const watchManager = new WatchManager(fake.asGVRClient(), queryClient, { scheduler: noDelay })
  managers.push(watchManager)
  const client: ConsoleClient = { queryClient, gvr: fake.asGVRClient(), watchManager }
  const body = opts.withProvider ? (
    <CreateProvider>
      <ResourceListView entry={entry} />
    </CreateProvider>
  ) : (
    <ResourceListView entry={entry} />
  )
  const wrapper = ({ children }: { children: ReactNode }) => (
    <ConsoleProvider client={client}>
      <KeyboardScopeProvider>{children}</KeyboardScopeProvider>
    </ConsoleProvider>
  )
  render(body, { wrapper })
}

describe('ResourceListView create flow', () => {
  it('opens the create tray from the "New" button when create is allowed', async () => {
    mount({ withProvider: true })
    const button = await screen.findByRole('button', { name: 'New Proxy' })
    fireEvent.click(button)
    expect(await screen.findByRole('dialog', { name: 'New Proxy' })).toBeDefined()
  })

  it('opens the create tray with the `n` shortcut', async () => {
    mount({ withProvider: true })
    await screen.findByRole('button', { name: 'New Proxy' })
    act(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'n', bubbles: true }))
    })
    expect(await screen.findByRole('dialog', { name: 'New Proxy' })).toBeDefined()
  })

  it('offers no "New" affordance when the create review denies it', async () => {
    ssarAllowed = false
    mount({ withProvider: true })
    // The list renders; the New button must not appear once the review resolves.
    await screen.findByText(/No proxies yet\./i)
    await waitFor(() => expect(screen.queryByRole('button', { name: 'New Proxy' })).toBeNull())
  })

  it('offers no "New" affordance with no CreateProvider mounted', async () => {
    mount({ withProvider: false })
    await screen.findByText(/No proxies yet\./i)
    expect(screen.queryByRole('button', { name: 'New Proxy' })).toBeNull()
  })
})

describe('ResourceListView edit-from-row (`y`)', () => {
  it('opens the YAML tray for the focused row with the `y` shortcut', async () => {
    mount({ withProvider: false, seed: [proxy('alpha'), proxy('beta')] })
    await screen.findByText('alpha')
    // Focus the first row (j: -1 -> 0), then `y` opens the tray for it. The
    // update SSAR gating `y` resolves async, so retry the press until it opens.
    act(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'j', bubbles: true }))
    })
    await waitFor(() => {
      act(() => {
        window.dispatchEvent(new KeyboardEvent('keydown', { key: 'y', bubbles: true }))
      })
      expect(screen.getByRole('dialog', { name: 'Edit Proxy' })).toBeDefined()
    })
    // The tray opened on the focused object — its name shows in the tray header.
    const dialog = screen.getByRole('dialog', { name: 'Edit Proxy' })
    expect(within(dialog).getByText('alpha')).toBeDefined()
  })

  it('does not open a tray on `y` when the update review denies it', async () => {
    ssarAllowed = false
    mount({ withProvider: false, seed: [proxy('alpha')] })
    await screen.findByText('alpha')
    act(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'j', bubbles: true })) // focus the row
    })
    // Let the (denying) SSAR settle so the gate reflects a resolved review, then
    // `y` must be a no-op — the keyboard path can't bypass the access check.
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })
    act(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'y', bubbles: true }))
    })
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})
