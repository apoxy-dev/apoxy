import { describe, expect, it } from 'vitest'
import { InMemoryClient } from './in-memory-client'
import type { GVR, K8sObject } from '../k8s-types'

const gvr: GVR = { group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }

function proxy(name: string): K8sObject {
  return {
    apiVersion: 'core.apoxy.dev/v1alpha2',
    kind: 'Proxy',
    metadata: { name, uid: `uid-${name}` },
    status: { phase: 'Healthy' },
    spec: { replicas: 1 },
  } as K8sObject
}

describe('InMemoryClient.apply', () => {
  it('preserves server-owned identity and status across an update', async () => {
    const c = new InMemoryClient()
    c.seed(gvr, [proxy('a')])
    const before = (await c.list(gvr)).items[0]!

    // The tray sends a uid-stripped body; the fake must merge over the stored
    // object the way the real apiserver's SSA response does.
    const saved = (await c.apply(gvr, 'a', {
      apiVersion: 'core.apoxy.dev/v1alpha2',
      kind: 'Proxy',
      metadata: { name: 'a' },
      spec: { replicas: 5 },
    } as K8sObject)) as K8sObject & { status?: { phase?: string }; spec?: { replicas?: number } }

    expect(saved.metadata.uid).toBe('uid-a') // identity preserved
    expect(saved.status?.phase).toBe('Healthy') // status subresource untouched
    expect(saved.spec?.replicas).toBe(5) // spec updated from the body
    expect(saved.metadata.resourceVersion).not.toBe(before.metadata.resourceVersion) // server bumps rv
  })

  it('adds a brand-new object', async () => {
    const c = new InMemoryClient()
    const saved = await c.apply(gvr, 'new', {
      apiVersion: 'core.apoxy.dev/v1alpha2',
      kind: 'Proxy',
      metadata: { name: 'new' },
      spec: {},
    } as K8sObject)
    expect(saved.metadata.name).toBe('new')
    expect((await c.list(gvr)).items).toHaveLength(1)
  })
})
