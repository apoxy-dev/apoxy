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
import { LinkProvider } from '../components/chrome/link-context'
import { WizardShell } from '../yaml/wizard-shell'
import { createRegistry, defineResource } from './registry'
import { ResourceDetailView } from './resource-detail-view'
import type { WizardProps } from './types'
import type { GVR, K8sObject } from '../lib/k8s-types'

const gvr: GVR = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }
const noDelay: Scheduler = { sleep: () => Promise.resolve() }

function proxy(name: string): K8sObject {
  return { metadata: { name, uid: name }, spec: { replicas: 1 } } as K8sObject
}

// A minimal bespoke wizard on the shared shell — enough to exercise the detail
// view's Edit → wizard wiring (the Edit button is gated on a `createWizard`).
function TestWizard({ entry: e, object, open, onClose, onSaved }: WizardProps) {
  return (
    <WizardShell
      entry={e}
      object={object}
      open={open}
      onClose={onClose}
      onSaved={onSaved}
      emptyDraft={() => ({ apiVersion: 'core.apoxy.dev/v1alpha2', kind: 'Proxy', metadata: { name: '' }, spec: {} }) as K8sObject}
      steps={[{ id: 'main', label: 'Main', render: () => null }]}
    />
  )
}

function entryFor(opts: { yamlEditable?: boolean; wizard?: boolean } = {}) {
  // createRegistry normalizes the input (computes gvr from servedVersion); the
  // detail view needs a normalized ResourceEntry, not the raw input.
  return createRegistry([
    defineResource({
      kind: 'Proxy',
      group: 'core.apoxy.dev',
      resource: 'proxies',
      servedVersion: 'v1alpha2',
      sidebarGroup: 'Operate',
      yamlEditable: opts.yamlEditable ?? false,
      ...(opts.wizard ? { createWizard: TestWizard } : {}),
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
  const navigate = vi.fn()
  const Link = ({ to, children }: { to: string; children: ReactNode }) => <a href={to}>{children}</a>
  const wrapper = ({ children }: { children: ReactNode }) => (
    <ConsoleProvider client={client}>
      <LinkProvider component={Link} navigate={navigate}>
        <KeyboardScopeProvider>{children}</KeyboardScopeProvider>
      </LinkProvider>
    </ConsoleProvider>
  )
  return { fake, wrapper, navigate }
}

describe('ResourceDetailView actions', () => {
  it('opens the wizard from the Edit button when the kind has a wizard', async () => {
    const { wrapper: W } = harness()
    render(<ResourceDetailView entry={entryFor({ yamlEditable: true, wizard: true })} name="alpha" />, { wrapper: W })

    const edit = await screen.findByRole('button', { name: 'Edit' })
    await waitFor(() => expect((edit as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(edit)
    expect(await screen.findByRole('dialog', { name: 'Edit Proxy' })).toBeDefined()
  })

  it('opens the wizard with the `e` shortcut', async () => {
    const { wrapper: W } = harness()
    render(<ResourceDetailView entry={entryFor({ yamlEditable: true, wizard: true })} name="alpha" />, { wrapper: W })
    await screen.findByRole('button', { name: 'Edit' })
    await waitFor(() => expect((screen.getByRole('button', { name: 'Edit' }) as HTMLButtonElement).disabled).toBe(false))
    act(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'e', bubbles: true }))
    })
    expect(await screen.findByRole('dialog', { name: 'Edit Proxy' })).toBeDefined()
  })

  it('disables the Edit affordance when the access review denies it', async () => {
    ssarAllowed = false
    const { wrapper: W } = harness()
    render(<ResourceDetailView entry={entryFor({ yamlEditable: true, wizard: true })} name="alpha" />, { wrapper: W })
    const edit = await screen.findByRole('button', { name: 'Edit' })
    await waitFor(() => expect((edit as HTMLButtonElement).disabled).toBe(true))
    // The keyboard path is gated by the same review, so `e` must not open it.
    act(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'e', bubbles: true }))
    })
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('shows no Edit button without a wizard, but always offers the YAML menu', async () => {
    const { wrapper: W } = harness()
    render(<ResourceDetailView entry={entryFor({ yamlEditable: true })} name="alpha" />, { wrapper: W })
    await screen.findByRole('button', { name: 'YAML actions' })
    expect(screen.queryByRole('button', { name: 'Edit' })).toBeNull()
  })

  it('opens the manifest viewer with the `y` shortcut', async () => {
    const { wrapper: W } = harness()
    render(<ResourceDetailView entry={entryFor({ yamlEditable: true })} name="alpha" />, { wrapper: W })
    await screen.findByRole('button', { name: 'YAML actions' })
    act(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'y', bubbles: true }))
    })
    expect(await screen.findByRole('dialog', { name: 'Manifest for alpha' })).toBeDefined()
  })

  it('confirms and performs a delete, then navigates to the list', async () => {
    const { wrapper: W, navigate } = harness()
    render(<ResourceDetailView entry={entryFor({ yamlEditable: true })} name="alpha" />, { wrapper: W })
    const del = await screen.findByRole('button', { name: 'Delete' })
    fireEvent.click(del)
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText(/Delete Proxy/)).toBeDefined()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(navigate).toHaveBeenCalledWith('/proxies'))
  })

  it('keeps the wizard (and the edits) when the object is deleted on the server', async () => {
    const { fake, wrapper: W } = harness()
    render(<ResourceDetailView entry={entryFor({ yamlEditable: true, wizard: true })} name="alpha" />, { wrapper: W })
    const edit = await screen.findByRole('button', { name: 'Edit' })
    await waitFor(() => expect((edit as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(edit)
    const dialog = await screen.findByRole('dialog', { name: 'Edit Proxy' })
    // The buffer lives on the YAML step; switch to it to read the editor.
    fireEvent.click(within(dialog).getByRole('button', { name: /YAML/ }))
    const editor = (await within(dialog).findByLabelText('Proxy YAML')) as HTMLTextAreaElement
    expect(editor.value).toContain('alpha')

    // The object vanishes from the watched collection mid-edit.
    await act(async () => {
      fake.emit(gvr, 'DELETED', proxy('alpha'))
      await Promise.resolve()
    })

    // The wizard stays mounted and the buffer survives — unsaved edits aren't wiped.
    const stillOpen = screen.getByRole('dialog')
    expect((within(stillOpen).getByLabelText('Proxy YAML') as HTMLTextAreaElement).value).toContain('alpha')
  })
})
