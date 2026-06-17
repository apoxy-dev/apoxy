import { describe, expect, it, vi } from 'vitest'
import {
  AccessReviewClient,
  DiscoveryClient,
  accessReviewBody,
  parseAggregatedDiscovery,
  servedPredicate,
  type DiscoveryDoc,
} from './discovery'
import type { RequestDecorator } from '../lib/request-decorator'
import { gvrKey } from '../lib/cache-keys'

const decorator: RequestDecorator = {
  scopeKey: 'test',
  decorate: ({ path, headers }) => ({ url: 'http://api.test' + path, headers }),
}

const apisDoc: DiscoveryDoc = {
  items: [
    {
      metadata: { name: 'core.apoxy.dev' },
      versions: [{ version: 'v1alpha2', resources: [{ resource: 'proxies' }, { resource: 'backends' }] }],
    },
  ],
}
const coreDoc: DiscoveryDoc = {
  items: [{ metadata: { name: '' }, versions: [{ version: 'v1', resources: [{ resource: 'pods' }] }] }],
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('parseAggregatedDiscovery', () => {
  it('collects served group/version/resource keys across docs', () => {
    const served = parseAggregatedDiscovery([apisDoc, coreDoc])
    expect(served.has(gvrKey({ group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }))).toBe(true)
    expect(served.has(gvrKey({ group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'backends' }))).toBe(true)
    expect(served.has(gvrKey({ group: '', version: 'v1', resource: 'pods' }))).toBe(true)
    expect(served.has(gvrKey({ group: 'core.apoxy.dev', version: 'v1', resource: 'proxies' }))).toBe(false)
  })

  it('tolerates missing items/versions/resources', () => {
    expect(parseAggregatedDiscovery([{}, { items: [{ versions: [{}] }] }]).size).toBe(0)
  })
})

describe('DiscoveryClient.fetchServed', () => {
  it('merges /apis and /api and reports complete', async () => {
    const fetchImpl = vi.fn(async (url: string | URL) => {
      const u = String(url)
      if (u.endsWith('/apis')) return jsonResponse(apisDoc)
      if (u.endsWith('/api')) return jsonResponse(coreDoc)
      throw new Error('unexpected ' + u)
    }) as unknown as typeof fetch
    const { served, complete } = await new DiscoveryClient({ decorator, fetch: fetchImpl }).fetchServed()
    expect(served.size).toBe(3)
    expect(complete).toBe(true)
  })

  it('requests aggregated discovery v2 via the Accept header', async () => {
    const seen: string[] = []
    const fetchImpl = vi.fn(async (_url: string | URL, init?: RequestInit) => {
      seen.push(new Headers(init?.headers).get('Accept') ?? '')
      return jsonResponse(apisDoc)
    }) as unknown as typeof fetch
    await new DiscoveryClient({ decorator, fetch: fetchImpl }).fetchServed()
    expect(seen.every((a) => a.includes('apidiscovery.k8s.io') && a.includes('v=v2'))).toBe(true)
  })

  it('tolerates one endpoint failing but marks the result incomplete', async () => {
    const fetchImpl = vi.fn(async (url: string | URL) => {
      const u = String(url)
      if (u.endsWith('/apis')) return jsonResponse(apisDoc)
      return jsonResponse({ message: 'not found' }, 404)
    }) as unknown as typeof fetch
    const { served, complete } = await new DiscoveryClient({ decorator, fetch: fetchImpl }).fetchServed()
    expect(served.size).toBe(2)
    // A partial read must NOT be trusted as authoritative (open-by-default).
    expect(complete).toBe(false)
  })

  it('throws when neither endpoint can be read', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({}, 500)) as unknown as typeof fetch
    await expect(new DiscoveryClient({ decorator, fetch: fetchImpl }).fetchServed()).rejects.toThrow()
  })
})

describe('servedPredicate (open-by-default gating)', () => {
  const proxies = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }

  it('gates strictly only on a complete, non-empty result', () => {
    const served = new Set([gvrKey(proxies)])
    const isServed = servedPredicate({ served, complete: true })
    expect(isServed(proxies)).toBe(true)
    expect(isServed({ group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'backends' })).toBe(false)
  })

  it('stays open when the result is incomplete (a partial read must not hide kinds)', () => {
    // /apis failed, /api returned only core resources: proxies absent but the
    // result is partial, so it must NOT be trusted to hide proxies.
    const served = new Set([gvrKey({ group: '', version: 'v1', resource: 'pods' })])
    const isServed = servedPredicate({ served, complete: false })
    expect(isServed(proxies)).toBe(true)
  })

  it('stays open for an empty result or no data', () => {
    expect(servedPredicate({ served: new Set(), complete: true })(proxies)).toBe(true)
    expect(servedPredicate(undefined)(proxies)).toBe(true)
  })
})

describe('accessReviewBody', () => {
  it('builds a SelfSubjectAccessReview for a verb on a GVR', () => {
    const body = accessReviewBody({
      verb: 'delete',
      gvr: { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' },
      name: 'p1',
    })
    expect(body).toMatchObject({
      apiVersion: 'authorization.k8s.io/v1',
      kind: 'SelfSubjectAccessReview',
      spec: {
        resourceAttributes: { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies', verb: 'delete', name: 'p1' },
      },
    })
    // No namespace key when none was supplied.
    expect((body.spec as { resourceAttributes: Record<string, unknown> }).resourceAttributes.namespace).toBeUndefined()
  })
})

describe('AccessReviewClient.canI', () => {
  const gvr = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }

  it('reports the server allowed decision', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ status: { allowed: true } })) as unknown as typeof fetch
    expect(await new AccessReviewClient({ decorator, fetch: fetchImpl }).canI({ verb: 'create', gvr })).toBe(true)
  })

  it('treats an absent allowed as denied', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ status: {} })) as unknown as typeof fetch
    expect(await new AccessReviewClient({ decorator, fetch: fetchImpl }).canI({ verb: 'create', gvr })).toBe(false)
  })
})
