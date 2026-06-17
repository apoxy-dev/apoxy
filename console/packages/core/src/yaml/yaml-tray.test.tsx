// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient } from '@tanstack/react-query'
import { WatchManager, type Scheduler } from '../lib/watch-manager'
import { ConsoleProvider } from '../lib/hooks'
import { KeyboardScopeProvider } from '../keyboard/scope-stack'
import type { ConsoleClient } from '../lib/console-client'
import { InMemoryClient } from '../lib/testing/in-memory-client'
import { K8sStatusError } from '../lib/gvr-client'
import { createRegistry, defineResource } from '../registry/registry'
import { YamlTray } from './yaml-tray'
import type { GVR, K8sObject } from '../lib/k8s-types'

const gvr: GVR = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }
const noDelay: Scheduler = { sleep: () => Promise.resolve() }

const registry = createRegistry([
  defineResource({
    kind: 'Proxy',
    group: 'core.apoxy.dev',
    resource: 'proxies',
    servedVersion: 'v1alpha2',
    sidebarGroup: 'Operate',
    yamlEditable: true,
    columns: [],
  }),
])
const entry = registry.byPath('proxies')!

function proxy(name: string, rv = '1'): K8sObject {
  return {
    apiVersion: 'core.apoxy.dev/v1alpha2',
    kind: 'Proxy',
    metadata: { name, uid: name, resourceVersion: rv },
    spec: { replicas: 1 },
  } as K8sObject
}

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
    <KeyboardScopeProvider isMac={false}>
      <ConsoleProvider client={client}>{children}</ConsoleProvider>
    </KeyboardScopeProvider>
  )
  return { fake, client, wrapper }
}

afterEach(() => {
  cleanup()
  for (const m of managers.splice(0)) m.dispose()
})

describe('YamlTray', () => {
  it('renders the object as YAML, stripped of server fields', () => {
    const { wrapper: W } = harness([proxy('alpha')])
    render(<YamlTray entry={entry} object={proxy('alpha')} open onClose={vi.fn()} />, { wrapper: W })
    const ta = screen.getByRole('textbox', { name: 'Proxy YAML' }) as HTMLTextAreaElement
    expect(ta.value).toContain('name: alpha')
    expect(ta.value).toContain('kind: Proxy')
    expect(ta.value).not.toContain('uid:')
    expect(ta.value).not.toContain('resourceVersion:')
  })

  it('saves edits via apply and closes', async () => {
    const { fake, wrapper: W } = harness([proxy('alpha')])
    const applySpy = vi.spyOn(fake, 'apply')
    const onClose = vi.fn()
    render(<YamlTray entry={entry} object={proxy('alpha')} open onClose={onClose} />, { wrapper: W })

    const ta = screen.getByRole('textbox', { name: 'Proxy YAML' }) as HTMLTextAreaElement
    fireEvent.change(ta, {
      target: { value: 'apiVersion: core.apoxy.dev/v1alpha2\nkind: Proxy\nmetadata:\n  name: alpha\nspec:\n  replicas: 5\n' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(applySpy).toHaveBeenCalled())
    expect(applySpy.mock.calls[0]![1]).toBe('alpha')
    await waitFor(() => expect(onClose).toHaveBeenCalled())
  })

  it('disables Save and shows a problem when metadata.name is missing', () => {
    const { wrapper: W } = harness([proxy('alpha')])
    render(<YamlTray entry={entry} object={proxy('alpha')} open onClose={vi.fn()} />, { wrapper: W })

    const ta = screen.getByRole('textbox', { name: 'Proxy YAML' }) as HTMLTextAreaElement
    fireEvent.change(ta, { target: { value: 'apiVersion: core.apoxy.dev/v1alpha2\nkind: Proxy\nmetadata: {}\n' } })

    expect(screen.getByText(/metadata\.name is required/)).toBeDefined()
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('surfaces a 409 conflict and overwrites with force on demand', async () => {
    const { fake, wrapper: W } = harness([proxy('alpha')])
    const applySpy = vi
      .spyOn(fake, 'apply')
      .mockRejectedValueOnce(new K8sStatusError({ reason: 'Conflict', code: 409, metadata: {} }, 409))
    render(<YamlTray entry={entry} object={proxy('alpha')} open onClose={vi.fn()} />, { wrapper: W })

    const ta = screen.getByRole('textbox', { name: 'Proxy YAML' }) as HTMLTextAreaElement
    fireEvent.change(ta, {
      target: { value: 'apiVersion: core.apoxy.dev/v1alpha2\nkind: Proxy\nmetadata:\n  name: alpha\nspec:\n  replicas: 7\n' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    const overwrite = await screen.findByRole('button', { name: 'Overwrite' })
    fireEvent.click(overwrite)

    await waitFor(() => expect(applySpy).toHaveBeenCalledTimes(2))
    // The overwrite retries with force=true.
    expect(applySpy.mock.calls[1]![3]).toMatchObject({ force: true })
  })

  it('warns when the object changed on the server while editing', async () => {
    const { fake, wrapper: W } = harness([proxy('alpha', '1')])
    render(<YamlTray entry={entry} object={proxy('alpha', '1')} open onClose={vi.fn()} />, { wrapper: W })
    // Wait for the live watch to connect before emitting, so the event isn't
    // dropped in the gap between the initial LIST and the watch loop.
    await waitFor(() => expect(fake.connections(gvr)).toBe(1))
    // A real spec change on the server (not just a resourceVersion bump).
    fake.emit(gvr, 'MODIFIED', { ...proxy('alpha', '2'), spec: { replicas: 9 } } as K8sObject)
    expect(await screen.findByText(/changed on the server/)).toBeDefined()
  })

  it('does not warn on a resourceVersion-only change (status/managed-fields churn)', async () => {
    const { fake, wrapper: W } = harness([proxy('alpha', '1')])
    render(<YamlTray entry={entry} object={proxy('alpha', '1')} open onClose={vi.fn()} />, { wrapper: W })
    await waitFor(() => expect(fake.connections(gvr)).toBe(1))
    // The editable projection (spec/metadata) is unchanged; only the rv bumps —
    // the banner must NOT appear (findByText rejects when it never shows).
    fake.emit(gvr, 'MODIFIED', proxy('alpha', '2'))
    await expect(screen.findByText(/changed on the server/, undefined, { timeout: 200 })).rejects.toThrow()
  })

  it('shows only one confirm prompt at a time (reload vs close)', async () => {
    const { fake, wrapper: W } = harness([proxy('alpha', '1')])
    render(<YamlTray entry={entry} object={proxy('alpha', '1')} open onClose={vi.fn()} />, { wrapper: W })
    await waitFor(() => expect(fake.connections(gvr)).toBe(1))
    const ta = screen.getByRole('textbox', { name: 'Proxy YAML' }) as HTMLTextAreaElement
    fireEvent.change(ta, { target: { value: ta.value + '\n# edit\n' } }) // dirty
    fake.emit(gvr, 'MODIFIED', { ...proxy('alpha', '2'), spec: { replicas: 9 } } as K8sObject) // changed on server

    // Open the reload confirm, then trigger the close confirm via the backdrop.
    fireEvent.click(await screen.findByRole('button', { name: 'Reload' }))
    expect(screen.getByText(/Discard your edits/)).toBeDefined()
    fireEvent.mouseDown(screen.getByRole('dialog').parentElement!) // backdrop -> requestClose
    // Only the close confirm is shown now; the reload confirm was dismissed.
    expect(screen.getByText(/Discard unsaved changes\?/)).toBeDefined()
    expect(screen.queryByText(/Discard your edits/)).toBeNull()
  })

  it('clears a stale conflict so a later non-conflict error is shown', async () => {
    const { fake, wrapper: W } = harness([proxy('alpha')])
    const applySpy = vi
      .spyOn(fake, 'apply')
      .mockRejectedValueOnce(new K8sStatusError({ reason: 'Conflict', code: 409, metadata: {} }, 409))
      .mockRejectedValueOnce(new K8sStatusError({ reason: 'Invalid', code: 422, message: 'bad spec', metadata: {} }, 422))
    render(<YamlTray entry={entry} object={proxy('alpha')} open onClose={vi.fn()} />, { wrapper: W })

    const ta = screen.getByRole('textbox', { name: 'Proxy YAML' }) as HTMLTextAreaElement
    fireEvent.change(ta, {
      target: { value: 'apiVersion: core.apoxy.dev/v1alpha2\nkind: Proxy\nmetadata:\n  name: alpha\nspec:\n  replicas: 2\n' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await screen.findByRole('button', { name: 'Overwrite' }) // first save -> conflict banner

    // Fix the YAML and re-save; the second apply fails for a different reason.
    fireEvent.change(ta, {
      target: { value: 'apiVersion: core.apoxy.dev/v1alpha2\nkind: Proxy\nmetadata:\n  name: alpha\nspec:\n  replicas: 3\n' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    expect(await screen.findByText('bad spec')).toBeDefined()
    // The stale conflict banner must be gone, not masking the real error.
    expect(screen.queryByRole('button', { name: 'Overwrite' })).toBeNull()
    expect(applySpy).toHaveBeenCalledTimes(2)
  })

  it('confirms before reloading the server copy over unsaved edits', async () => {
    const { fake, wrapper: W } = harness([proxy('alpha', '1')])
    render(<YamlTray entry={entry} object={proxy('alpha', '1')} open onClose={vi.fn()} />, { wrapper: W })
    await waitFor(() => expect(fake.connections(gvr)).toBe(1))

    const ta = screen.getByRole('textbox', { name: 'Proxy YAML' }) as HTMLTextAreaElement
    fireEvent.change(ta, { target: { value: ta.value + '\n# my edit\n' } }) // dirty
    fake.emit(gvr, 'MODIFIED', { ...proxy('alpha', '2'), spec: { replicas: 9 } } as K8sObject) // changed on server

    fireEvent.click(await screen.findByRole('button', { name: 'Reload' }))
    // Dirty -> confirm prompt, edits not yet discarded.
    expect(screen.getByText(/Discard your edits/)).toBeDefined()
    expect((screen.getByRole('textbox', { name: 'Proxy YAML' }) as HTMLTextAreaElement).value).toContain('# my edit')
  })

  it('confirms before discarding unsaved edits', () => {
    const onClose = vi.fn()
    const { wrapper: W } = harness([proxy('alpha')])
    render(<YamlTray entry={entry} object={proxy('alpha')} open onClose={onClose} />, { wrapper: W })

    const ta = screen.getByRole('textbox', { name: 'Proxy YAML' }) as HTMLTextAreaElement
    fireEvent.change(ta, { target: { value: ta.value + '\n# edited\n' } })
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    // First Cancel asks to confirm rather than closing.
    expect(onClose).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Discard' }))
    expect(onClose).toHaveBeenCalled()
  })

  it('keeps unsaved edits when the object disappears while editing', () => {
    const { wrapper: W } = harness([proxy('alpha')])
    const { rerender } = render(<YamlTray entry={entry} object={proxy('alpha')} open onClose={vi.fn()} />, {
      wrapper: W,
    })
    const ta = screen.getByRole('textbox', { name: 'Proxy YAML' }) as HTMLTextAreaElement
    fireEvent.change(ta, { target: { value: ta.value + '\n# keep me\n' } })
    // The object is deleted on the server: the detail view re-renders the tray
    // with object=undefined. The buffer must survive (not reset to a skeleton).
    rerender(<YamlTray entry={entry} object={undefined} open onClose={vi.fn()} />)
    expect((screen.getByRole('textbox', { name: 'Proxy YAML' }) as HTMLTextAreaElement).value).toContain('# keep me')
  })

  it('flags a per-kind schema violation in the problem list (the entry.schema path)', () => {
    // A schema shaped like the generated ones: spec is a $ref into $defs.
    const schemaEntry = createRegistry([
      defineResource({
        kind: 'Proxy',
        group: 'core.apoxy.dev',
        resource: 'proxies',
        servedVersion: 'v1alpha2',
        sidebarGroup: 'Operate',
        yamlEditable: true,
        schema: {
          type: 'object',
          properties: { spec: { $ref: 'ProxySpec' } },
          $defs: { ProxySpec: { type: 'object', properties: { replicas: { type: 'integer', minimum: 1 } } } },
        },
        columns: [],
      }),
    ]).byPath('proxies')!
    const { wrapper: W } = harness([proxy('alpha')])
    render(<YamlTray entry={schemaEntry} object={proxy('alpha')} open onClose={vi.fn()} />, { wrapper: W })
    const ta = screen.getByRole('textbox', { name: 'Proxy YAML' }) as HTMLTextAreaElement
    fireEvent.change(ta, {
      target: { value: 'apiVersion: core.apoxy.dev/v1alpha2\nkind: Proxy\nmetadata:\n  name: alpha\nspec:\n  replicas: two\n' },
    })
    // Resolved through the $ref into $defs — proves the registry schema reaches
    // the validator, not just the always-on structural checks.
    expect(screen.getByText(/\.spec\.replicas: Expected integer/)).toBeDefined()
  })
})
