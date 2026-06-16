import { describe, expect, it } from 'vitest'
import { collectionPath, listUrl, objectPath, watchUrl } from './k8s-paths'
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
})
