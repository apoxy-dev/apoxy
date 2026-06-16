// The WatchManager spec. These MSW-driven tests script LIST→WATCH
// sequences, 410 relist, bookmark advance, reconnect/backoff, auth-refresh
// resume, and scope teardown. They ARE the WatchManager's spec —
// keep them exhaustive and treat a behavior change here as a spec change.

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { setupServer } from 'msw/node'
import { QueryClient } from '@tanstack/react-query'
import { MockApiServer } from './testing/mock-apiserver'
import { GVRClient, K8sStatusError } from './gvr-client'
import { ProjectRequestDecorator } from './request-decorator'
import { WatchManager, type Scheduler } from './watch-manager'
import { listKey } from './cache-keys'
import type { GVR, K8sList, K8sObject } from './k8s-types'

const gvr: GVR = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }
const col = 'core.apoxy.dev/v1alpha2/proxies'

const mock = new MockApiServer()
const server = setupServer(...mock.handlers())

// Managers created during a test, disposed afterwards so no zombie run loop
// survives to reconnect against the shared mock and pollute the next test.
const managers: WatchManager[] = []
function track(mgr: WatchManager): WatchManager {
  managers.push(mgr)
  return mgr
}

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  for (const m of managers) m.dispose()
  managers.length = 0
  server.resetHandlers()
  mock.reset()
})
afterAll(() => server.close())

const noDelay: Scheduler = { sleep: () => Promise.resolve() }

function proxy(name: string, labels?: Record<string, string>): K8sObject {
  return { apiVersion: 'core.apoxy.dev/v1alpha2', kind: 'Proxy', metadata: { name, uid: name, labels } }
}

function names(list?: K8sList): string[] {
  return (list?.items ?? []).map((o) => o.metadata.name ?? '')
}

function connects() {
  return mock.watchConnects.get(col) ?? []
}

interface SetupOpts {
  projectId?: string
  token?: () => string
  scheduler?: Scheduler
}

function setup(opts: SetupOpts = {}) {
  const decorator = new ProjectRequestDecorator({
    baseUrl: mock.baseUrl,
    projectId: opts.projectId ?? 'p1',
    dynamicHeaders: () => ({ Authorization: `Bearer ${opts.token?.() ?? 't'}` }),
  })
  const client = new GVRClient({ decorator })
  const qc = new QueryClient({
    defaultOptions: { queries: { gcTime: Infinity, staleTime: Infinity, retry: false } },
  })
  const mgr = track(
    new WatchManager(client, qc, {
      scheduler: opts.scheduler ?? noDelay,
      baseBackoffMs: 10,
      maxBackoffMs: 40,
    }),
  )
  const getList = () => qc.getQueryData<K8sList>(listKey(mgr.scopeKey, gvr))
  return { decorator, client, qc, mgr, getList }
}

describe('WatchManager', () => {
  it('seeds the cache from the initial LIST and resolves ready', async () => {
    mock.seed(gvr, [proxy('a'), proxy('b')])
    const { mgr, getList } = setup()
    const sub = mgr.subscribe(gvr)
    const list = await sub.ready
    expect(names(list)).toEqual(['a', 'b'])
    expect(names(getList())).toEqual(['a', 'b'])
    sub.unsubscribe()
  })

  it('applies ADDED / MODIFIED / DELETED watch events to the cached list', async () => {
    mock.seed(gvr, [proxy('a')])
    const { mgr, getList } = setup()
    const sub = mgr.subscribe(gvr)
    await sub.ready
    await vi.waitFor(() => expect(connects().length).toBeGreaterThanOrEqual(1))

    mock.emit(gvr, 'ADDED', proxy('b'))
    await vi.waitFor(() => expect(names(getList())).toEqual(['a', 'b']))

    mock.emit(gvr, 'MODIFIED', proxy('a', { tier: 'gold' }))
    await vi.waitFor(() =>
      expect(getList()?.items.find((o) => o.metadata.name === 'a')?.metadata.labels?.tier).toBe('gold'),
    )

    mock.emit(gvr, 'DELETED', proxy('a'))
    await vi.waitFor(() => expect(names(getList())).toEqual(['b']))
    sub.unsubscribe()
  })

  it('is a single ref-counted writer: two subscribers share one LIST and one watch', async () => {
    mock.seed(gvr, [proxy('a')])
    const { mgr, getList } = setup()
    const s1 = mgr.subscribe(gvr)
    const s2 = mgr.subscribe(gvr)
    await Promise.all([s1.ready, s2.ready])
    await vi.waitFor(() => expect(connects().length).toBe(1))
    // One shared (scope, gvr) entry: one LIST, one watch connect, one cache key.
    expect(s1.key).toEqual(s2.key)
    expect(mock.listCount).toBe(1)

    s1.unsubscribe()
    // One subscriber remains: still watching, so events still apply.
    mock.emit(gvr, 'ADDED', proxy('b'))
    await vi.waitFor(() => expect(names(getList())).toEqual(['a', 'b']))

    s2.unsubscribe()
    // Last unsubscribe tears down: the cache entry is dropped and no further
    // events resurrect it.
    expect(getList()).toBeUndefined()
    mock.emit(gvr, 'ADDED', proxy('c'))
    await new Promise((r) => setTimeout(r, 20))
    expect(getList()).toBeUndefined()
  })

  it('relists from scratch on a 410 Gone watch error', async () => {
    mock.seed(gvr, [proxy('a')])
    const { mgr, getList } = setup()
    const sub = mgr.subscribe(gvr)
    await sub.ready
    await vi.waitFor(() => expect(connects().length).toBe(1))

    // The client missed mutations while watching; then the watch 410s.
    mock.setStore(gvr, [proxy('a'), proxy('c')])
    mock.emitError(gvr, { metadata: {}, code: 410, reason: 'Gone', status: 'Failure' })

    await vi.waitFor(() => expect(names(getList())).toEqual(['a', 'c']))
    // The 410 drove a relist and a fresh watch connect.
    await vi.waitFor(() => expect(connects().length).toBeGreaterThanOrEqual(2))
    sub.unsubscribe()
  })

  it('advances the resume resourceVersion on BOOKMARK and resumes from it', async () => {
    mock.seed(gvr, [proxy('a')])
    const { mgr } = setup()
    const sub = mgr.subscribe(gvr)
    await sub.ready
    await vi.waitFor(() => expect(connects().length).toBe(1))
    // First connect resumed from the initial list rv.
    expect(connects()[0]?.resourceVersion).toBe(mock.resourceVersion)

    const rv = mock.bookmark(gvr)
    await vi.waitFor(() => expect(mgr.resourceVersionFor(gvr)).toBe(rv))

    mock.closeWatches(gvr) // force a reconnect
    await vi.waitFor(() => {
      const connects = mock.watchConnects.get(col) ?? []
      expect(connects.length).toBeGreaterThanOrEqual(2)
      expect(connects[connects.length - 1]?.resourceVersion).toBe(rv)
    })
    sub.unsubscribe()
  })

  it('reconnects with exponential backoff after disconnects, resuming from rv', async () => {
    mock.seed(gvr, [proxy('a')])
    const sleeps: number[] = []
    const scheduler: Scheduler = {
      sleep: (ms) => {
        sleeps.push(ms)
        return Promise.resolve()
      },
    }
    const { mgr } = setup({ scheduler })
    const sub = mgr.subscribe(gvr)
    await sub.ready
    await vi.waitFor(() => expect((mock.watchConnects.get(col) ?? []).length).toBe(1))
    const rv1 = mock.watchConnects.get(col)?.[0]?.resourceVersion

    mock.closeWatches(gvr)
    await vi.waitFor(() => expect((mock.watchConnects.get(col) ?? []).length).toBeGreaterThanOrEqual(2))
    mock.closeWatches(gvr)
    await vi.waitFor(() => expect((mock.watchConnects.get(col) ?? []).length).toBeGreaterThanOrEqual(3))

    // The second empty reconnect backs off (10ms); reconnects resume from rv1.
    expect(sleeps).toContain(10)
    const connects = mock.watchConnects.get(col) ?? []
    expect(connects[1]?.resourceVersion).toBe(rv1)
    sub.unsubscribe()
  })

  it('resumes the watch with a fresh token on refreshAuth without dropping the list', async () => {
    let token = 'a'
    mock.seed(gvr, [proxy('x')])
    const { mgr, getList } = setup({ token: () => token })
    const sub = mgr.subscribe(gvr)
    await sub.ready
    await vi.waitFor(() => expect(mock.watchConnects.get(col)?.[0]?.authorization).toBe('Bearer a'))

    token = 'b'
    mgr.refreshAuth()
    await vi.waitFor(() => {
      const connects = mock.watchConnects.get(col) ?? []
      expect(connects.length).toBeGreaterThanOrEqual(2)
      expect(connects[connects.length - 1]?.authorization).toBe('Bearer b')
    })
    // No relist happened — the seeded list is retained.
    expect(names(getList())).toEqual(['x'])
    expect(mock.listCount).toBe(1)
    sub.unsubscribe()
  })

  it('tears down an old scope before a new one, with no cross-project leakage', async () => {
    mock.seed(gvr, [proxy('a')])
    const decoratorP1 = new ProjectRequestDecorator({ baseUrl: mock.baseUrl, projectId: 'p1' })
    const client = new GVRClient({ decorator: decoratorP1 })
    const qc = new QueryClient({
      defaultOptions: { queries: { gcTime: Infinity, staleTime: Infinity, retry: false } },
    })
    const mgr = track(new WatchManager(client, qc, { scheduler: noDelay }))
    const p1Key = listKey('http://apiserver.test|p1', gvr)
    const p2Key = listKey('http://apiserver.test|p2', gvr)

    const sub1 = mgr.subscribe(gvr)
    await sub1.ready
    await vi.waitFor(() => expect(connects().length).toBeGreaterThanOrEqual(1))
    expect(qc.getQueryData(p1Key)).toBeDefined()

    // Switch project: tear down the old scope BEFORE building the new one.
    mgr.tearDownScope('http://apiserver.test|p1')
    sub1.unsubscribe()
    client.decorator = new ProjectRequestDecorator({ baseUrl: mock.baseUrl, projectId: 'p2' })
    // Teardown synchronously drops the old scope's cache.
    expect(qc.getQueryData(p1Key)).toBeUndefined()

    const beforeP2 = connects().length
    const sub2 = mgr.subscribe(gvr)
    await sub2.ready
    await vi.waitFor(() => expect(qc.getQueryData(p2Key)).toBeDefined())
    // Wait for the p2 watch to actually connect before emitting (the mock only
    // streams events to already-connected watchers).
    await vi.waitFor(() => expect(connects().length).toBeGreaterThan(beforeP2))

    // An event after the switch lands only in the live (p2) scope.
    mock.emit(gvr, 'ADDED', proxy('b'))
    await vi.waitFor(() => expect(names(qc.getQueryData<K8sList>(p2Key))).toContain('b'))
    expect(qc.getQueryData(p1Key)).toBeUndefined()
    sub2.unsubscribe()
  })

  it('rejects ready and stops on a fatal (403) list error', async () => {
    mock.failNextList(gvr, { code: 403, reason: 'Forbidden' })
    const { mgr } = setup()
    const sub = mgr.subscribe(gvr)
    await expect(sub.ready).rejects.toBeInstanceOf(K8sStatusError)
    await new Promise((r) => setTimeout(r, 10))
    expect(mock.liveWatchers(gvr)).toBe(0)
  })

  it('retries a transient (503) list error until it succeeds', async () => {
    mock.failNextList(gvr, { code: 503, reason: 'ServiceUnavailable' })
    mock.seed(gvr, [proxy('a')])
    const { mgr } = setup()
    const sub = mgr.subscribe(gvr)
    const list = await sub.ready
    expect(names(list)).toEqual(['a'])
    expect(mock.listCount).toBeGreaterThanOrEqual(2)
    sub.unsubscribe()
  })

  it('relists when the watch connect returns HTTP 410 (not just an in-stream ERROR)', async () => {
    mock.seed(gvr, [proxy('a')])
    const { mgr, getList } = setup()
    const sub = mgr.subscribe(gvr)
    await sub.ready
    await vi.waitFor(() => expect(connects().length).toBe(1))

    mock.setStore(gvr, [proxy('a'), proxy('c')])
    mock.failNextWatch(gvr, { code: 410, reason: 'Gone' })
    mock.closeWatches(gvr) // reconnect, whose connect 410s -> relist

    await vi.waitFor(() => expect(names(getList())).toEqual(['a', 'c']))
    sub.unsubscribe()
  })

  it('advances the resume resourceVersion on DELETED', async () => {
    mock.seed(gvr, [proxy('a')])
    const { mgr } = setup()
    const sub = mgr.subscribe(gvr)
    await sub.ready
    await vi.waitFor(() => expect(connects().length).toBe(1))

    const deleted = mock.emit(gvr, 'DELETED', proxy('a'))
    await vi.waitFor(() => expect(mgr.resourceVersionFor(gvr)).toBe(deleted.metadata.resourceVersion))
    sub.unsubscribe()
  })

  it('keys distinct selectors as separate entries (separate LIST + watch)', async () => {
    mock.seed(gvr, [proxy('a')])
    const { mgr } = setup()
    const gold = mgr.subscribe(gvr, { labelSelector: 'tier=gold' })
    const silver = mgr.subscribe(gvr, { labelSelector: 'tier=silver' })
    await Promise.all([gold.ready, silver.ready])
    expect(gold.key).not.toEqual(silver.key)
    await vi.waitFor(() => expect(connects().length).toBe(2))
    expect(mock.listCount).toBe(2)
    gold.unsubscribe()
    silver.unsubscribe()
  })

  it('handles a fresh subscribe immediately after teardown (generation race)', async () => {
    mock.seed(gvr, [proxy('a')])
    const { mgr, getList } = setup()
    const sub1 = mgr.subscribe(gvr)
    await sub1.ready
    await vi.waitFor(() => expect(connects().length).toBe(1))

    // Tear down and immediately re-subscribe in the same tick (no await between).
    mgr.tearDownScope(mgr.scopeKey)
    sub1.unsubscribe()
    const before = connects().length
    const sub2 = mgr.subscribe(gvr)
    await sub2.ready
    await vi.waitFor(() => expect(connects().length).toBeGreaterThan(before))

    // The fresh entry is live; the stale loop never writes.
    mock.emit(gvr, 'ADDED', proxy('b'))
    await vi.waitFor(() => expect(names(getList())).toEqual(['a', 'b']))
    sub2.unsubscribe()
  })

  it('keeps last-known data and resumes (no permanent stop) on a post-LIST watch error', async () => {
    mock.seed(gvr, [proxy('a')])
    const sleeps: number[] = []
    const { mgr, getList } = setup({
      scheduler: {
        sleep: (ms) => {
          sleeps.push(ms)
          return Promise.resolve()
        },
      },
    })
    const sub = mgr.subscribe(gvr)
    await sub.ready
    await vi.waitFor(() => expect(connects().length).toBe(1))

    // A fatal-looking status mid-session (e.g. a transient 403 blip) must NOT
    // permanently stop the entry once the list has settled.
    mock.failNextWatch(gvr, { code: 403, reason: 'Forbidden' })
    mock.closeWatches(gvr)
    // The faulted reconnect isn't recorded (the mock records only successful
    // connects), so a second *successful* connect proves it resumed past the 403.
    await vi.waitFor(() => expect(connects().length).toBeGreaterThanOrEqual(2))
    expect(names(getList())).toEqual(['a']) // last-known retained

    // The entry is still alive: a later event still applies.
    mock.emit(gvr, 'ADDED', proxy('b'))
    await vi.waitFor(() => expect(names(getList())).toEqual(['a', 'b']))
    sub.unsubscribe()
  })

  it('rejects ready after the retry budget on a persistent non-fatal (401) initial list', async () => {
    for (let i = 0; i < 5; i++) mock.failNextList(gvr, { code: 401, reason: 'Unauthorized' })
    const { mgr } = setup({ scheduler: noDelay })
    const sub = mgr.subscribe(gvr)
    await expect(sub.ready).rejects.toBeInstanceOf(K8sStatusError)
  })

  it('whenReady() starts the entry so the queryFn never hangs without a subscribe', async () => {
    mock.seed(gvr, [proxy('a')])
    const { mgr } = setup()
    // No subscribe() — this is the queryFn path that races ahead of the effect.
    const list = await mgr.whenReady(gvr)
    expect(names(list)).toEqual(['a'])
  })

  it('paces (does not hot-loop) when the server returns a list without a resourceVersion', async () => {
    mock.seed(gvr, [proxy('a')])
    mock.suppressListRV = true
    const sleeps: number[] = []
    const { mgr } = setup({
      // A real (tiny) delay actually paces the rv-less relist loop; an immediate
      // scheduler would let it hammer the mock since there is no watch to block on.
      scheduler: {
        sleep: (ms) => {
          sleeps.push(ms)
          return new Promise((r) => setTimeout(r, Math.min(ms, 5)))
        },
      },
    })
    const sub = mgr.subscribe(gvr)
    const list = await sub.ready
    expect(names(list)).toEqual(['a']) // data is still seeded
    // The rv-less relist loop applies a growing backoff rather than spinning at 0.
    await vi.waitFor(() => expect(sleeps.some((s) => s > 0)).toBe(true))
    sub.unsubscribe()
  })

  it('backs off and resumes on a 401 watch connect (transient auth path)', async () => {
    let token = 'a'
    mock.seed(gvr, [proxy('x')])
    const sleeps: number[] = []
    const { mgr, getList } = setup({
      token: () => token,
      scheduler: {
        sleep: (ms) => {
          sleeps.push(ms)
          return Promise.resolve()
        },
      },
    })
    const sub = mgr.subscribe(gvr)
    await sub.ready
    await vi.waitFor(() => expect(connects().length).toBe(1))

    mock.failNextWatch(gvr, { code: 401, reason: 'Unauthorized' })
    token = 'b'
    mock.closeWatches(gvr)
    // The 401 reconnect isn't recorded; the next successful connect carries the
    // refreshed token.
    await vi.waitFor(() => {
      const c = connects()
      expect(c.length).toBeGreaterThanOrEqual(2)
      expect(c[c.length - 1]?.authorization).toBe('Bearer b')
    })
    expect(sleeps.length).toBeGreaterThanOrEqual(1) // backed off, did not stop
    expect(names(getList())).toEqual(['x'])
    sub.unsubscribe()
  })
})
