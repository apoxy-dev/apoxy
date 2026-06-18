// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient } from '@tanstack/react-query'
import { WatchManager, type Scheduler } from '../lib/watch-manager'
import { ConsoleProvider } from '../lib/hooks'
import type { ConsoleClient } from '../lib/console-client'
import { InMemoryClient } from '../lib/testing/in-memory-client'
import { KeyboardScopeProvider } from '../keyboard/scope-stack'
import { createRegistry, defineResource } from '../registry/registry'
import { WizardShell, type WizardFormProps, type WizardCollection } from './wizard-shell'
import type { GVR, K8sObject } from '../lib/k8s-types'

const gvr: GVR = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }
const noDelay: Scheduler = { sleep: () => Promise.resolve() }

interface Proxy extends K8sObject {
  spec?: { replicas?: number }
}

const entry = createRegistry([
  defineResource({
    kind: 'Proxy',
    group: 'core.apoxy.dev',
    resource: 'proxies',
    servedVersion: 'v1alpha2',
    sidebarGroup: 'Operate',
    columns: [],
  }),
]).all()[0]!

function empty(): Proxy {
  return { apiVersion: 'core.apoxy.dev/v1alpha2', kind: 'Proxy', metadata: { name: '' }, spec: { replicas: 1 } }
}

// A trivial form step binding two fields onto the shared draft.
function Form({ draft, setDraft }: WizardFormProps<Proxy>) {
  return (
    <div>
      <input
        aria-label="name"
        value={draft.metadata.name ?? ''}
        onChange={(e) => setDraft({ ...draft, metadata: { ...draft.metadata, name: e.target.value } })}
      />
      <input
        aria-label="replicas"
        value={String(draft.spec?.replicas ?? '')}
        onChange={(e) => setDraft({ ...draft, spec: { ...draft.spec, replicas: Number(e.target.value) } })}
      />
    </div>
  )
}

const managers: WatchManager[] = []
afterEach(() => {
  cleanup()
  for (const m of managers.splice(0)) m.dispose()
})

function mountWizard() {
  const fake = new InMemoryClient()
  fake.seed(gvr, [])
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } },
  })
  const watchManager = new WatchManager(fake.asGVRClient(), queryClient, { scheduler: noDelay })
  managers.push(watchManager)
  const client: ConsoleClient = { queryClient, gvr: fake.asGVRClient(), watchManager }
  const onClose = vi.fn()
  const wrapper = ({ children }: { children: ReactNode }) => (
    <ConsoleProvider client={client}>
      <KeyboardScopeProvider>{children}</KeyboardScopeProvider>
    </ConsoleProvider>
  )
  render(
    <WizardShell<Proxy>
      entry={entry}
      open
      onClose={onClose}
      emptyDraft={empty}
      steps={[{ id: 'main', label: 'Main', render: (p) => <Form {...p} /> }]}
    />,
    { wrapper },
  )
  return { fake, onClose }
}

describe('WizardShell', () => {
  it('appends a built-in YAML step after the kind steps', () => {
    mountWizard()
    expect(screen.getByRole('button', { name: /Main/ })).toBeDefined()
    expect(screen.getByRole('button', { name: /YAML/ })).toBeDefined()
  })

  it('regenerates the YAML buffer when the form edits the draft', () => {
    mountWizard()
    fireEvent.change(screen.getByLabelText('name'), { target: { value: 'p1' } })
    fireEvent.click(screen.getByRole('button', { name: /YAML/ }))
    expect((screen.getByLabelText('Proxy YAML') as HTMLTextAreaElement).value).toContain('name: p1')
  })

  it('parses YAML edits back into the form (two-way sync)', () => {
    mountWizard()
    fireEvent.click(screen.getByRole('button', { name: /YAML/ }))
    fireEvent.change(screen.getByLabelText('Proxy YAML'), {
      target: { value: 'apiVersion: core.apoxy.dev/v1alpha2\nkind: Proxy\nmetadata:\n  name: zed\nspec:\n  replicas: 4\n' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Main/ }))
    expect((screen.getByLabelText('name') as HTMLInputElement).value).toBe('zed')
    expect((screen.getByLabelText('replicas') as HTMLInputElement).value).toBe('4')
  })

  it('creates via Server-Side Apply on Create, then closes', async () => {
    const { fake, onClose } = mountWizard()
    fireEvent.change(screen.getByLabelText('name'), { target: { value: 'newp' } })
    // Step to the last (YAML) step, where the Create action lives.
    fireEvent.click(screen.getByRole('button', { name: /YAML/ }))
    fireEvent.click(screen.getByRole('button', { name: /Create proxy/i }))
    await waitFor(() => expect(onClose).toHaveBeenCalled())
    const stored = await fake.list(gvr)
    expect(stored.items.map((o) => o.metadata.name)).toContain('newp')
  })

  it('keeps the Create action disabled until the draft has a name', () => {
    mountWizard()
    fireEvent.click(screen.getByRole('button', { name: /YAML/ }))
    expect((screen.getByRole('button', { name: /Create proxy/i }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: /Main/ }))
    fireEvent.change(screen.getByLabelText('name'), { target: { value: 'has-name' } })
    fireEvent.click(screen.getByRole('button', { name: /YAML/ }))
    expect((screen.getByRole('button', { name: /Create proxy/i }) as HTMLButtonElement).disabled).toBe(false)
  })
})

// A collection step: a port list, each port a full-pane editor surfaced one level
// down in the rail. Mirrors the GatewayWizard's Listeners step in miniature.
interface Ported extends K8sObject {
  spec?: { ports?: Array<{ name?: string }> }
}

const portsCollection: WizardCollection<Ported> = {
  noun: 'port',
  items: (d) => (d.spec?.ports ?? []).map((p, i) => ({ id: String(i), label: p.name || `port-${i + 1}`, summary: 'tcp' })),
  onAdd: (d) => {
    const ps = d.spec?.ports ?? []
    return { draft: { ...d, spec: { ...d.spec, ports: [...ps, { name: `port-${ps.length + 1}` }] } }, focusId: String(ps.length) }
  },
  onRemove: (d, id) => {
    const i = Number(id)
    const ps = d.spec?.ports ?? []
    return { ...d, spec: { ...d.spec, ports: ps.filter((_, j) => j !== i) } }
  },
  renderItem: ({ draft, setDraft, itemId }) => {
    const i = Number(itemId)
    const ps = draft.spec?.ports ?? []
    const p = ps[i]
    if (!p) return null
    return (
      <input
        aria-label="port-name"
        value={p.name ?? ''}
        onChange={(e) => setDraft({ ...draft, spec: { ...draft.spec, ports: ps.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)) } })}
      />
    )
  },
}

function mountCollectionWizard() {
  const fake = new InMemoryClient()
  fake.seed(gvr, [])
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } } })
  const watchManager = new WatchManager(fake.asGVRClient(), queryClient, { scheduler: noDelay })
  managers.push(watchManager)
  const client: ConsoleClient = { queryClient, gvr: fake.asGVRClient(), watchManager }
  const wrapper = ({ children }: { children: ReactNode }) => (
    <ConsoleProvider client={client}>
      <KeyboardScopeProvider>{children}</KeyboardScopeProvider>
    </ConsoleProvider>
  )
  render(
    <WizardShell<Ported>
      entry={entry}
      open
      onClose={vi.fn()}
      emptyDraft={() => ({ apiVersion: 'core.apoxy.dev/v1alpha2', kind: 'Proxy', metadata: { name: 'p' }, spec: { ports: [] } })}
      steps={[{ id: 'ports', label: 'Ports', collection: portsCollection }]}
    />,
    { wrapper },
  )
  return { fake }
}

describe('WizardShell collection step', () => {
  it('shows an empty overview with an add affordance', () => {
    mountCollectionWizard()
    expect(screen.getByText(/No ports yet/i)).toBeDefined()
    expect(screen.getAllByRole('button', { name: /Add port/i }).length).toBeGreaterThan(0)
  })

  it('drills into a freshly added item and surfaces it one level down in the rail', () => {
    mountCollectionWizard()
    fireEvent.click(screen.getAllByRole('button', { name: /Add port/i })[0]!)
    // The full-pane editor for the new item is shown…
    expect(screen.getByLabelText('port-name')).toBeDefined()
    expect(screen.getByText(/Edit · port/i)).toBeDefined()
    // …and a nested rail entry for it appears.
    expect(screen.getByRole('button', { name: /port-1/ })).toBeDefined()
  })

  it('edits the item live, returns to the overview, and reflects it in the YAML', () => {
    mountCollectionWizard()
    fireEvent.click(screen.getAllByRole('button', { name: /Add port/i })[0]!)
    fireEvent.change(screen.getByLabelText('port-name'), { target: { value: 'web' } })
    // "Done" returns to the overview — the item editor is gone…
    fireEvent.click(screen.getByRole('button', { name: 'Done' }))
    expect(screen.queryByLabelText('port-name')).toBeNull()
    // …and the shared draft regenerated the YAML buffer with the edit.
    fireEvent.click(screen.getByRole('button', { name: /YAML/ }))
    expect((screen.getByLabelText('Proxy YAML') as HTMLTextAreaElement).value).toContain('name: web')
  })

  it('removes an item from the overview', () => {
    mountCollectionWizard()
    fireEvent.click(screen.getAllByRole('button', { name: /Add port/i })[0]!)
    fireEvent.click(screen.getByRole('button', { name: 'Done' }))
    fireEvent.click(screen.getByRole('button', { name: /Remove/i }))
    expect(screen.getByText(/No ports yet/i)).toBeDefined()
  })
})
