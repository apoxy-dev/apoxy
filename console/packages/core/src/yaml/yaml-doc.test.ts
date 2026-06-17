import { describe, expect, it } from 'vitest'
import { forEditing, fromYaml, skeleton, toYaml } from './yaml-doc'
import type { K8sObject } from '../lib/k8s-types'

const obj: K8sObject & { status?: unknown; spec?: unknown } = {
  apiVersion: 'core.apoxy.dev/v1alpha2',
  kind: 'Proxy',
  metadata: {
    name: 'p1',
    namespace: 'default',
    uid: 'abc',
    resourceVersion: '42',
    generation: 3,
    creationTimestamp: '2026-01-01T00:00:00Z',
    managedFields: [{ manager: 'console' }],
    labels: { app: 'web' },
  },
  spec: { replicas: 2 },
  status: { phase: 'Healthy' },
}

describe('forEditing', () => {
  it('strips status and server-owned metadata, keeps spec + authored metadata', () => {
    const edit = forEditing(obj) as Record<string, unknown>
    expect(edit.status).toBeUndefined()
    const meta = edit.metadata as Record<string, unknown>
    expect(meta.uid).toBeUndefined()
    expect(meta.resourceVersion).toBeUndefined()
    expect(meta.generation).toBeUndefined()
    expect(meta.creationTimestamp).toBeUndefined()
    expect(meta.managedFields).toBeUndefined()
    // Authored fields survive.
    expect(meta.name).toBe('p1')
    expect(meta.namespace).toBe('default')
    expect(meta.labels).toEqual({ app: 'web' })
    expect(edit.spec).toEqual({ replicas: 2 })
  })
  it('does not mutate the input', () => {
    forEditing(obj)
    expect(obj.metadata.uid).toBe('abc')
    expect(obj.status).toEqual({ phase: 'Healthy' })
  })
  it('does not throw on a non-cloneable value (drops it via the JSON fallback)', () => {
    const weird = {
      apiVersion: 'v1',
      kind: 'X',
      metadata: { name: 'a' },
      spec: { fn: () => 1, n: 7 },
    } as unknown as K8sObject
    const edit = forEditing(weird) as { spec: Record<string, unknown> }
    expect(edit.spec.n).toBe(7) // plain data survives
    expect(edit.spec.fn).toBeUndefined() // the function is dropped, not a crash
  })
})

describe('toYaml / fromYaml', () => {
  it('round-trips an object', () => {
    const text = toYaml({ a: 1, b: ['x', 'y'], c: { d: true } })
    expect(fromYaml(text).value).toEqual({ a: 1, b: ['x', 'y'], c: { d: true } })
  })
  it('reports a parse error for malformed YAML', () => {
    const r = fromYaml('a: [1, 2\nb: : :')
    expect(r.error).toBeDefined()
    expect(r.value).toBeUndefined()
  })
})

describe('skeleton', () => {
  it('joins group/version for a grouped resource', () => {
    expect(skeleton({ group: 'core.apoxy.dev', version: 'v1alpha2', resource: 'proxies' }, 'Proxy')).toEqual({
      apiVersion: 'core.apoxy.dev/v1alpha2',
      kind: 'Proxy',
      metadata: { name: '' },
      spec: {},
    })
  })
  it('uses the bare version for the core group', () => {
    expect(skeleton({ group: '', version: 'v1', resource: 'pods' }, 'Pod').apiVersion).toBe('v1')
  })
})
