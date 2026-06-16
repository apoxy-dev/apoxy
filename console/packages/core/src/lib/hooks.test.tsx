// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest'
import { act, cleanup, render, renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient } from '@tanstack/react-query'
import { WatchManager, type Scheduler } from './watch-manager'
import { ConsoleProvider, useK8sList, useK8sObject } from './hooks'
import type { ConsoleClient } from './console-client'
import { InMemoryClient } from './testing/in-memory-client'
import type { GVR, K8sObject } from './k8s-types'

const gvr: GVR = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }
const noDelay: Scheduler = { sleep: () => Promise.resolve() }

function proxy(name: string, labels?: Record<string, string>): K8sObject {
  return { metadata: { name, uid: name, labels } }
}

function harness(seed: K8sObject[] = []) {
  const fake = new InMemoryClient()
  fake.seed(gvr, seed)
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } },
  })
  const watchManager = new WatchManager(fake.asGVRClient(), queryClient, { scheduler: noDelay })
  const client: ConsoleClient = { queryClient, gvr: fake.asGVRClient(), watchManager }
  const wrapper = ({ children }: { children: ReactNode }) => (
    <ConsoleProvider client={client}>{children}</ConsoleProvider>
  )
  return { fake, client, queryClient, watchManager, wrapper }
}

afterEach(() => cleanup())

describe('useK8sList', () => {
  it('loads the managed list and reflects watch events', async () => {
    const { fake, wrapper } = harness([proxy('a')])
    const { result } = renderHook(() => useK8sList(gvr), { wrapper })
    await waitFor(() => expect(result.current.data?.items.map((o) => o.metadata.name)).toEqual(['a']))

    await act(async () => {
      fake.emit(gvr, 'ADDED', proxy('b'))
    })
    await waitFor(() =>
      expect(result.current.data?.items.map((o) => o.metadata.name)).toEqual(['a', 'b']),
    )
  })

  it('ref-counts one watch for two subscribers and tears down on unmount', async () => {
    const { fake, wrapper } = harness([proxy('a')])
    const h1 = renderHook(() => useK8sList(gvr), { wrapper })
    const h2 = renderHook(() => useK8sList(gvr), { wrapper })
    await waitFor(() => expect(fake.connections(gvr)).toBe(1))

    h1.unmount()
    expect(fake.connections(gvr)).toBe(1)

    h2.unmount()
    await waitFor(() => expect(fake.connections(gvr)).toBe(0))
  })
})

describe('useK8sObject', () => {
  it('derives one object by name from the managed list', async () => {
    const { wrapper } = harness([proxy('a'), proxy('b')])
    const { result } = renderHook(() => useK8sObject(gvr, 'b'), { wrapper })
    await waitFor(() => expect(result.current.data?.metadata.name).toBe('b'))
  })

  it('re-renders a row only when its own object changes', async () => {
    const { fake, client } = harness([proxy('a'), proxy('b')])
    const renders: Record<string, number> = { a: 0, b: 0 }

    function Row({ name }: { name: string }) {
      const { data } = useK8sObject(gvr, name)
      renders[name] = (renders[name] ?? 0) + 1
      return <div data-testid={name}>{data?.metadata.resourceVersion ?? ''}</div>
    }

    render(
      <ConsoleProvider client={client}>
        <Row name="a" />
        <Row name="b" />
      </ConsoleProvider>,
    )
    await waitFor(() => {
      expect(renders.a).toBeGreaterThan(0)
      expect(renders.b).toBeGreaterThan(0)
    })

    const aBefore = renders.a ?? 0
    await act(async () => {
      fake.emit(gvr, 'MODIFIED', proxy('b', { tier: 'gold' }))
    })
    // The row bound to 'b' re-renders; the row bound to 'a' does not.
    await waitFor(() => expect((renders.b ?? 0)).toBeGreaterThan(1))
    expect(renders.a).toBe(aBefore)
  })
})
