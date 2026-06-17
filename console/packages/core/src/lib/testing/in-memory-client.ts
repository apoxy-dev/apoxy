// A transport-free fake of the GVR client for hook tests (APO-772). It lets a
// test drive list results and push watch events synchronously in jsdom without
// MSW streaming, while exercising the real WatchManager. The MSW-backed
// mock-apiserver is the WatchManager's spec; this is the lighter harness the
// React-render tests use.

import type { GVRClient } from '../gvr-client'
import type { GVR, K8sList, K8sObject, WatchEvent } from '../k8s-types'

function colKey(gvr: GVR): string {
  return `${gvr.group}/${gvr.version}/${gvr.resource}`
}

function nameOf(obj: K8sObject): string {
  return obj.metadata.name ?? ''
}

type Listener = (ev: WatchEvent) => void

export class InMemoryClient {
  decorator = {
    scopeKey: 'mem',
    decorate: (req: { path: string; headers: Headers }) => ({ url: req.path, headers: req.headers }),
  }

  private rv = 0
  private readonly store = new Map<string, Map<string, K8sObject>>()
  private readonly listeners = new Map<string, Set<Listener>>()

  seed(gvr: GVR, objects: K8sObject[]): void {
    const m = this.ensure(colKey(gvr))
    for (const o of objects) m.set(nameOf(o), this.stamp(o))
  }

  /** Open watch streams for a collection (asserts ref-counted single-writer). */
  connections(gvr: GVR): number {
    return this.listeners.get(colKey(gvr))?.size ?? 0
  }

  async list<T extends K8sObject = K8sObject>(gvr: GVR): Promise<K8sList<T>> {
    const items = [...(this.store.get(colKey(gvr))?.values() ?? [])] as T[]
    return { metadata: { resourceVersion: String(this.rv) }, items }
  }

  async *watch<T extends K8sObject = K8sObject>(
    gvr: GVR,
    _params: unknown,
    signal?: AbortSignal,
  ): AsyncGenerator<WatchEvent<T>> {
    const col = colKey(gvr)
    const queue: WatchEvent[] = []
    let wake: (() => void) | null = null
    const listener: Listener = (ev) => {
      queue.push(ev)
      wake?.()
    }
    // Register the abort handler ONCE: it just wakes the loop, which then
    // observes `signal.aborted` at the top and returns. Re-adding it inside the
    // wait would leak a listener for every delivered event (it is normally
    // resolved by wake(), not abort, so `{ once: true }` never fires).
    const onAbort = () => wake?.()
    signal?.addEventListener('abort', onAbort)
    const set = this.listeners.get(col) ?? new Set<Listener>()
    set.add(listener)
    this.listeners.set(col, set)
    try {
      for (;;) {
        if (signal?.aborted) return
        if (queue.length === 0) {
          await new Promise<void>((resolve) => {
            wake = resolve
          })
          wake = null
        }
        while (queue.length > 0) {
          const ev = queue.shift()
          if (ev) yield ev as WatchEvent<T>
        }
      }
    } finally {
      set.delete(listener)
      signal?.removeEventListener('abort', onAbort)
    }
  }

  /** Server-Side Apply: upsert the object and broadcast the change. Tests spy on
   *  this to simulate a 409 conflict on the tray write path. */
  async apply<T extends K8sObject = K8sObject>(
    gvr: GVR,
    name: string,
    body: Partial<T> & K8sObject,
    _opts?: { namespace?: string; fieldManager?: string; force?: boolean },
  ): Promise<T> {
    const existing = this.store.get(colKey(gvr))?.get(name)
    // Like the real apiserver's SSA response: merge over the stored object so
    // server-owned identity (uid, and the status subresource) survives an update
    // instead of being replaced by the uid-stripped request body.
    const merged = {
      ...existing,
      ...body,
      metadata: { ...existing?.metadata, ...body.metadata, name },
    } as K8sObject
    return this.emit(gvr, existing ? 'MODIFIED' : 'ADDED', merged) as T
  }

  /** Delete the named object and broadcast it. */
  async delete(gvr: GVR, name: string): Promise<K8sObject> {
    const current = this.store.get(colKey(gvr))?.get(name) ?? { metadata: { name } }
    return this.emit(gvr, 'DELETED', current)
  }

  /** Apply a mutation and broadcast it to live watchers. */
  emit(gvr: GVR, type: 'ADDED' | 'MODIFIED' | 'DELETED', object: K8sObject): K8sObject {
    const m = this.ensure(colKey(gvr))
    const obj = this.stamp(object)
    if (type === 'DELETED') m.delete(nameOf(obj))
    else m.set(nameOf(obj), obj)
    const set = this.listeners.get(colKey(gvr))
    if (set) for (const l of set) l({ type, object: obj })
    return obj
  }

  asGVRClient(): GVRClient {
    return this as unknown as GVRClient
  }

  private ensure(col: string): Map<string, K8sObject> {
    let m = this.store.get(col)
    if (!m) {
      m = new Map()
      this.store.set(col, m)
    }
    return m
  }

  private stamp(obj: K8sObject): K8sObject {
    return { ...obj, metadata: { ...obj.metadata, resourceVersion: String(++this.rv) } }
  }
}
