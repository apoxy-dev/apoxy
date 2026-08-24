import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { setupServer } from 'msw/node'
import { MockApiServer } from './testing/mock-apiserver'
import { GVRClient, K8sStatusError } from './gvr-client'
import { ProjectRequestDecorator } from './request-decorator'
import type { GVR, K8sObject, WatchEvent } from './k8s-types'
import type { WatchTransport, WatchTransportRequest } from './watch-transport'

const gvr: GVR = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }
const col = 'core.apoxy.dev/v1alpha2/proxies'

const mock = new MockApiServer()
const server = setupServer(...mock.handlers())

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  server.resetHandlers()
  mock.reset()
})
afterAll(() => server.close())

function client(token = 't'): GVRClient {
  return new GVRClient({
    decorator: new ProjectRequestDecorator({
      baseUrl: mock.baseUrl,
      projectId: 'p1',
      dynamicHeaders: () => ({ Authorization: `Bearer ${token}` }),
    }),
  })
}

function proxy(name: string): K8sObject {
  return { apiVersion: 'core.apoxy.dev/v1alpha2', kind: 'Proxy', metadata: { name, uid: name } }
}

describe('GVRClient', () => {
  it('lists a collection as a decoded K8sList (not an HTTP envelope)', async () => {
    mock.seed(gvr, [proxy('a'), proxy('b')])
    const list = await client().list(gvr)
    expect(list.items.map((o) => o.metadata.name)).toEqual(['a', 'b'])
    expect(list.metadata.resourceVersion).toBeDefined()
  })

  it('gets a single object', async () => {
    mock.seed(gvr, [proxy('a')])
    expect((await client().get(gvr, 'a')).metadata.name).toBe('a')
  })

  it('throws a typed K8sStatusError on 404', async () => {
    await expect(client().get(gvr, 'missing')).rejects.toBeInstanceOf(K8sStatusError)
    try {
      await client().get(gvr, 'missing')
      expect.unreachable()
    } catch (e) {
      const err = e as K8sStatusError
      expect(err.code).toBe(404)
      expect(err.reason).toBe('NotFound')
    }
  })

  it('creates via SSA apply (apply-patch+yaml)', async () => {
    const applied = await client().apply(gvr, 'a', proxy('a'))
    expect(applied.metadata.name).toBe('a')
    expect((await client().get(gvr, 'a')).metadata.name).toBe('a')
  })

  it('deletes an object', async () => {
    mock.seed(gvr, [proxy('a')])
    await client().delete(gvr, 'a')
    await expect(client().get(gvr, 'a')).rejects.toBeInstanceOf(K8sStatusError)
  })

  it('applies the decorator auth + project headers to requests', async () => {
    mock.seed(gvr, [])
    const ac = new AbortController()
    const stream = client('xyz').watch(gvr, {}, ac.signal)
    const pending = stream.next()
    await vi.waitFor(() => expect(mock.watchConnects.get(col)?.length).toBeGreaterThan(0))
    const rec = mock.watchConnects.get(col)?.[0]
    expect(rec?.authorization).toBe('Bearer xyz')
    expect(rec?.project).toBe('p1')
    ac.abort()
    await pending.catch(() => {})
  })

  it('routes decorated watch requests through a custom transport', async () => {
    let captured: WatchTransportRequest | undefined
    const added: WatchEvent = { type: 'ADDED', object: proxy('through-transport') }
    const transport: WatchTransport = {
      async *watch<T extends K8sObject>(request: WatchTransportRequest) {
        captured = request
        yield added as WatchEvent<T>
      },
    }
    const gvrClient = new GVRClient({
      decorator: new ProjectRequestDecorator({
        baseUrl: mock.baseUrl,
        projectId: 'p1',
        dynamicHeaders: () => ({ Authorization: 'Bearer transport-token' }),
      }),
      watchTransport: transport,
    })

    await expect(gvrClient.watch(gvr).next()).resolves.toEqual({
      done: false,
      value: added,
    })
    expect(captured?.url).toContain('/apis/core.apoxy.dev/v1alpha2/proxies?')
    expect(captured?.headers.get('Authorization')).toBe('Bearer transport-token')
    expect(captured?.headers.get('X-Apoxy-Project-Id')).toBe('p1')
  })

  it('streams watch events as decoded WatchEvents', async () => {
    mock.seed(gvr, [])
    const ac = new AbortController()
    const seen: string[] = []
    const consume = (async () => {
      for await (const ev of client().watch(gvr, {}, ac.signal)) {
        seen.push(ev.type)
        if (seen.length >= 2) return
      }
    })()
    await vi.waitFor(() => expect(mock.liveWatchers(gvr)).toBe(1))
    mock.emit(gvr, 'ADDED', proxy('a'))
    mock.emit(gvr, 'MODIFIED', proxy('a'))
    await consume
    ac.abort()
    expect(seen).toEqual(['ADDED', 'MODIFIED'])
  })

  it('throws a typed K8sStatusError when the watch connect returns 410', async () => {
    mock.failNextWatch(gvr, { code: 410, reason: 'Gone' })
    const ac = new AbortController()
    const stream = client().watch(gvr, {}, ac.signal)
    await expect(stream.next()).rejects.toBeInstanceOf(K8sStatusError)
  })

  it('reads a subresource that carries no ObjectMeta', async () => {
    mock.seedSubresource(gvr, 'a', 'metrics', { metric: 'http.requests', series: [] })
    const set = await client().subresource<{ metric: string; series: unknown[] }>(gvr, 'a', 'metrics')
    expect(set.metric).toBe('http.requests')
  })

  it('sends subresource parameters, repeating an array key', async () => {
    mock.seedSubresource(gvr, 'a', 'metrics', {})
    await client().subresource(gvr, 'a', 'metrics', {
      window: '24h',
      top: 50,
      metric: ['http.requests', 'http.latency'],
    })
    const url = new URL(mock.subresourceRequests[0]?.url ?? '')
    expect(url.pathname).toBe('/apis/core.apoxy.dev/v1alpha2/proxies/a/metrics')
    expect(url.searchParams.get('window')).toBe('24h')
    expect(url.searchParams.get('top')).toBe('50')
    expect(url.searchParams.getAll('metric')).toEqual(['http.requests', 'http.latency'])
  })

  it('applies the decorator auth + project headers to a subresource read', async () => {
    mock.seedSubresource(gvr, 'a', 'metrics', {})
    await client('sub-token').subresource(gvr, 'a', 'metrics')
    expect(mock.subresourceRequests[0]?.authorization).toBe('Bearer sub-token')
    expect(mock.subresourceRequests[0]?.project).toBe('p1')
  })

  it('exposes the response to onResponse so a caller can read Cache-Control', async () => {
    mock.seedSubresource(gvr, 'a', 'metrics', {}, { 'Cache-Control': 'max-age=60' })
    let cacheControl: string | null = null
    await client().subresource(gvr, 'a', 'metrics', {}, {
      onResponse: (res) => {
        cacheControl = res.headers.get('Cache-Control')
      },
    })
    expect(cacheControl).toBe('max-age=60')
  })

  it('throws a typed K8sStatusError for a subresource the server does not serve', async () => {
    await expect(client().subresource(gvr, 'a', 'metrics')).rejects.toBeInstanceOf(K8sStatusError)
  })

  it('aborts a subresource read through the signal', async () => {
    mock.seedSubresource(gvr, 'a', 'metrics', {})
    const ac = new AbortController()
    ac.abort()
    await expect(client().subresource(gvr, 'a', 'metrics', {}, { signal: ac.signal })).rejects.toThrow()
  })
})
