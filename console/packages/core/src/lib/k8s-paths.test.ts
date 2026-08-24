import { describe, expect, it } from 'vitest'
import { collectionPath, listUrl, objectPath, subresourceUrl, watchUrl } from './k8s-paths'
import type { GVR } from './k8s-types'

const proxies: GVR = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }
const pods: GVR = { group: '', version: 'v1', resource: 'pods' }

describe('k8s-paths', () => {
  it('builds an /apis path for a named group', () => {
    expect(collectionPath(proxies)).toBe('/apis/core.apoxy.dev/v1alpha2/proxies')
  })

  it('builds an /api path for the core group', () => {
    expect(collectionPath(pods)).toBe('/api/v1/pods')
  })

  it('namespaces a collection when given', () => {
    expect(collectionPath(proxies, 'ns1')).toBe('/apis/core.apoxy.dev/v1alpha2/namespaces/ns1/proxies')
  })

  it('encodes the object name', () => {
    expect(objectPath(proxies, 'a b')).toBe('/apis/core.apoxy.dev/v1alpha2/proxies/a%20b')
  })

  it('lists with selectors and pagination', () => {
    const u = listUrl(proxies, { labelSelector: 'env=prod', limit: 10 })
    expect(u).toContain('labelSelector=env%3Dprod')
    expect(u).toContain('limit=10')
  })

  it('watches with watch=1, bookmarks, and resume resourceVersion', () => {
    const u = watchUrl(proxies, { resourceVersion: '42' })
    expect(u).toContain('watch=1')
    expect(u).toContain('allowWatchBookmarks=true')
    expect(u).toContain('resourceVersion=42')
  })

  it('appends the subresource to the object path, encoding the name', () => {
    expect(subresourceUrl(proxies, 'a', 'metrics')).toBe('/apis/core.apoxy.dev/v1alpha2/proxies/a/metrics')
    expect(subresourceUrl(proxies, 'a b', 'metrics')).toBe('/apis/core.apoxy.dev/v1alpha2/proxies/a%20b/metrics')
    expect(subresourceUrl(proxies, 'a', 'metrics', {}, 'ns1')).toBe(
      '/apis/core.apoxy.dev/v1alpha2/namespaces/ns1/proxies/a/metrics',
    )
  })

  it('drops empty and undefined subresource parameters', () => {
    expect(subresourceUrl(proxies, 'a', 'metrics', { window: undefined, top: '' })).toBe(
      '/apis/core.apoxy.dev/v1alpha2/proxies/a/metrics',
    )
  })

  it('appends scalar subresource parameters', () => {
    const u = subresourceUrl(proxies, 'a', 'metrics', { window: '24h', top: 50, include: 'routes' })
    expect(u).toContain('window=24h')
    expect(u).toContain('top=50')
    expect(u).toContain('include=routes')
  })

  it('repeats the key for an array parameter', () => {
    const u = subresourceUrl(proxies, 'a', 'metrics', { metric: ['http.requests', 'http.latency'] })
    expect(u).toContain('metric=http.requests')
    expect(u).toContain('metric=http.latency')
  })
})
