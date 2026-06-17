// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient } from '@tanstack/react-query'
import { WatchManager, type Scheduler } from '../lib/watch-manager'
import { ConsoleProvider } from '../lib/hooks'
import type { ConsoleClient } from '../lib/console-client'
import { InMemoryClient } from '../lib/testing/in-memory-client'
import { KeyboardScopeProvider } from '../keyboard/scope-stack'
import { createRegistry, defineResource } from './registry'
import { ResourceDetailView } from './resource-detail-view'
import type { GVR, K8sObject } from '../lib/k8s-types'

const gvr: GVR = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }
const noDelay: Scheduler = { sleep: () => Promise.resolve() }

function proxy(name: string): K8sObject {
  return { metadata: { name, uid: name }, spec: { replicas: 1 } } as K8sObject
}

function entryFor(yamlEditable: boolean) {
  // createRegistry normalizes the input (computes gvr from servedVersion); the
  // detail view needs a normalized ResourceEntry, not the raw input.
  return createRegistry([
    defineResource({
      kind: 'Proxy',
      group: 'core.apoxy.dev',
      resource: 'proxies',
      servedVersion: 'v1alpha2',
      sidebarGroup: 'Operate',
      yamlEditable,
      columns: [{ id: 'name', header: 'Name', cell: (o) => o.metadata.name }],
    }),
  ]).all()[0]!
}

const managers: WatchManager[] = []

// Stub `fetch` so the SelfSubjectAccessReview (the only fetch the detail view
// makes — list/watch go through InMemoryClient) resolves deterministically
// instead of hitting the network. `allowed` controls the Edit gate.
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

function harness(seed: K8sObject[] = [proxy('alpha')]) {
  const fake = new InMemoryClient()
  fake.seed(gvr, seed)
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } },
  })
  const watchManager = new WatchManager(fake.asGVRClient(), queryClient, { scheduler: noDelay })
  managers.push(watchManager)
  const client: ConsoleClient = { queryClient, gvr: fake.asGVRClient(), watchManager }
  const wrapper = ({ children }: { children: ReactNode }) => (
    <ConsoleProvider client={client}>
      <KeyboardScopeProvider>{children}</KeyboardScopeProvider>
    </ConsoleProvider>
  )
  return { fake, wrapper }
}

describe('ResourceDetailView edit gate', () => {
  it('opens the YAML tray from the Edit button on an editable kind', async () => {
    const { wrapper: W } = harness()
    render(<ResourceDetailView entry={entryFor(true)} name="alpha" />, { wrapper: W })

    const edit = await screen.findByRole('button', { name: 'Edit' })
    await waitFor(() => expect((edit as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(edit)
    expect(await screen.findByRole('dialog', { name: 'Edit Proxy' })).toBeDefined()
  })

  it('opens the tray with the `y` shortcut', async () => {
    const { wrapper: W } = harness()
    render(<ResourceDetailView entry={entryFor(true)} name="alpha" />, { wrapper: W })
    // Wait until the object loaded and the SSAR resolved (the `y` scope is gated
    // on both), then press the bare key on the window the dispatcher listens on.
    await screen.findByRole('button', { name: 'Edit' })
    await waitFor(() => expect((screen.getByRole('button', { name: 'Edit' }) as HTMLButtonElement).disabled).toBe(false))
    act(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'y', bubbles: true }))
    })
    expect(await screen.findByRole('dialog', { name: 'Edit Proxy' })).toBeDefined()
  })

  it('disables the Edit affordance when the access review denies it', async () => {
    ssarAllowed = false
    const { wrapper: W } = harness()
    render(<ResourceDetailView entry={entryFor(true)} name="alpha" />, { wrapper: W })
    const edit = await screen.findByRole('button', { name: 'Edit' })
    await waitFor(() => expect((edit as HTMLButtonElement).disabled).toBe(true))
    // The keyboard path is gated by the same review, so `y` must not open it.
    act(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'y', bubbles: true }))
    })
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('shows no Edit affordance for a non-editable kind', async () => {
    const { wrapper: W } = harness()
    render(<ResourceDetailView entry={entryFor(false)} name="alpha" />, { wrapper: W })
    await screen.findByRole('heading', { name: 'alpha' })
    expect(screen.queryByRole('button', { name: 'Edit' })).toBeNull()
  })

  it('keeps the tray (and the edits) when the object is deleted on the server', async () => {
    const { fake, wrapper: W } = harness()
    render(<ResourceDetailView entry={entryFor(true)} name="alpha" />, { wrapper: W })
    const edit = await screen.findByRole('button', { name: 'Edit' })
    await waitFor(() => expect((edit as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(edit)
    const editor = (await screen.findByLabelText('Proxy YAML')) as HTMLTextAreaElement
    expect(editor.value).toContain('alpha')

    // The object vanishes from the watched collection mid-edit.
    await act(async () => {
      fake.emit(gvr, 'DELETED', proxy('alpha'))
      await Promise.resolve()
    })

    // The tray stays mounted and the buffer survives — unsaved edits aren't wiped.
    expect(screen.getByRole('dialog')).toBeDefined()
    expect((screen.getByLabelText('Proxy YAML') as HTMLTextAreaElement).value).toContain('alpha')
  })
})
