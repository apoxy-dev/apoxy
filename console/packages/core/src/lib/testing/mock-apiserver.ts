// A scriptable mock apiserver for the WatchManager spec suite. It
// backs MSW handlers with an in-memory store and live, controllable watch
// streams, plus fault injection (410, list errors, forced disconnects) and
// per-connect recording (resume resourceVersion, auth/project headers). The
// MSW-driven tests that drive this ARE the WatchManager's spec.

import { http, HttpResponse, type RequestHandler } from 'msw'
import type { GVR, K8sList, K8sObject, Status, WatchEvent } from '../k8s-types'

/** Default origin the tests point their RequestDecorator at. */
export const MOCK_BASE_URL = 'http://apiserver.test'

interface Fault {
  code: number
  reason?: string
  message?: string
}

export interface WatchConnect {
  resourceVersion: string | null
  authorization: string | null
  project: string | null
}

interface Watcher {
  controller: ReadableStreamDefaultController<Uint8Array>
}

export class MockApiServer {
  readonly baseUrl = MOCK_BASE_URL
  /** Recorded watch connects per collection, in arrival order. */
  readonly watchConnects = new Map<string, WatchConnect[]>()
  /** Count of LIST (non-watch) requests served — asserts no double-LIST. */
  listCount = 0
  /** When true, LIST bodies omit metadata.resourceVersion (degenerate server). */
  suppressListRV = false

  private rv = 0
  private readonly store = new Map<string, Map<string, K8sObject>>()
  private readonly watchers = new Map<string, Set<Watcher>>()
  private readonly watchFaults = new Map<string, Fault[]>()
  private readonly listFaults = new Map<string, Fault[]>()
  private readonly enc = new TextEncoder()

  // --- scripting controls --------------------------------------------------

  /** Pre-populate a collection; each object is stamped with a fresh rv. */
  seed(gvr: GVR, objects: K8sObject[]): void {
    const m = this.ensure(colKey(gvr))
    for (const o of objects) {
      const obj = stampRV(o, String(++this.rv))
      m.set(nameOf(obj), obj)
    }
  }

  /** Replace a collection's contents WITHOUT notifying watchers — simulates
   *  state a client missed (e.g. while its watch was 410-expired). */
  setStore(gvr: GVR, objects: K8sObject[]): void {
    const m = this.ensure(colKey(gvr))
    m.clear()
    for (const o of objects) m.set(nameOf(o), stampRV(o, String(++this.rv)))
  }

  /** The server's current resourceVersion. */
  get resourceVersion(): string {
    return String(this.rv)
  }

  /** Apply a mutation to the store and broadcast it to live watchers. */
  emit(gvr: GVR, type: 'ADDED' | 'MODIFIED' | 'DELETED', object: K8sObject): K8sObject {
    const m = this.ensure(colKey(gvr))
    const obj = stampRV(object, String(++this.rv))
    if (type === 'DELETED') m.delete(nameOf(obj))
    else m.set(nameOf(obj), obj)
    this.push(colKey(gvr), { type, object: obj })
    return obj
  }

  /** Broadcast a BOOKMARK carrying the latest rv (no store change). */
  bookmark(gvr: GVR): string {
    const rv = String(++this.rv)
    this.push(colKey(gvr), { type: 'BOOKMARK', object: { metadata: { resourceVersion: rv } } })
    return rv
  }

  /** Push an in-stream ERROR event (e.g. a 410 Gone Status). */
  emitError(gvr: GVR, status: Status): void {
    this.push(colKey(gvr), { type: 'ERROR', object: status })
  }

  /** Make the next watch *connect* fail with this status (e.g. 410). */
  failNextWatch(gvr: GVR, fault: Fault): void {
    pushTo(this.watchFaults, colKey(gvr), fault)
  }

  /** Make the next list fail with this status. */
  failNextList(gvr: GVR, fault: Fault): void {
    pushTo(this.listFaults, colKey(gvr), fault)
  }

  /** Gracefully end live watch streams (simulate a server-side disconnect). */
  closeWatches(gvr?: GVR): void {
    const cols = gvr ? [colKey(gvr)] : [...this.watchers.keys()]
    for (const col of cols) {
      const set = this.watchers.get(col)
      if (!set) continue
      for (const w of [...set]) {
        try {
          w.controller.close()
        } catch {
          /* already closed */
        }
      }
      set.clear()
    }
  }

  /** Count of currently-open watch streams — asserts single-writer/teardown. */
  liveWatchers(gvr?: GVR): number {
    if (gvr) return this.watchers.get(colKey(gvr))?.size ?? 0
    let n = 0
    for (const s of this.watchers.values()) n += s.size
    return n
  }

  reset(): void {
    this.rv = 0
    this.listCount = 0
    this.suppressListRV = false
    this.closeWatches()
    this.store.clear()
    this.watchers.clear()
    this.watchFaults.clear()
    this.listFaults.clear()
    this.watchConnects.clear()
  }

  // --- MSW wiring ----------------------------------------------------------

  handlers(): RequestHandler[] {
    const collection = `${MOCK_BASE_URL}/apis/:group/:version/:resource`
    const object = `${MOCK_BASE_URL}/apis/:group/:version/:resource/:name`
    return [
      http.get(collection, ({ request, params }) => {
        const col = colKey(gvrOf(params))
        const url = new URL(request.url)
        if (url.searchParams.get('watch') === '1') {
          const fault = take(this.watchFaults, col)
          if (fault) return HttpResponse.json(statusBody(fault), { status: fault.code })
          recordConnect(this.watchConnects, col, {
            resourceVersion: url.searchParams.get('resourceVersion'),
            authorization: request.headers.get('authorization'),
            project: request.headers.get('x-apoxy-project-id'),
          })
          // `Transfer-Encoding: chunked` makes the client's watch fetch resolve
          // on headers (like a real apiserver) instead of blocking until the
          // first event — without it an idle watch hangs the client fetch.
          return new HttpResponse(this.openStream(col), {
            headers: { 'Content-Type': 'application/json', 'Transfer-Encoding': 'chunked' },
          })
        }
        this.listCount++
        const fault = take(this.listFaults, col)
        if (fault) return HttpResponse.json(statusBody(fault), { status: fault.code })
        return HttpResponse.json(this.listBody(col))
      }),
      http.get(object, ({ params }) => {
        const col = colKey(gvrOf(params))
        const obj = this.store.get(col)?.get(String(params.name))
        if (!obj) {
          return HttpResponse.json(statusBody({ code: 404, reason: 'NotFound' }), { status: 404 })
        }
        return HttpResponse.json(obj)
      }),
      http.patch(object, async ({ request, params }) => {
        const gvr = gvrOf(params)
        const name = String(params.name)
        const existed = this.store.get(colKey(gvr))?.has(name) ?? false
        const body = (await request.json()) as K8sObject
        const merged: K8sObject = { ...body, metadata: { ...body.metadata, name } }
        const obj = this.emit(gvr, existed ? 'MODIFIED' : 'ADDED', merged)
        return HttpResponse.json(obj)
      }),
      http.delete(object, ({ params }) => {
        const gvr = gvrOf(params)
        const name = String(params.name)
        const obj = this.store.get(colKey(gvr))?.get(name)
        if (obj) this.emit(gvr, 'DELETED', obj)
        return HttpResponse.json<Status>({
          kind: 'Status',
          apiVersion: 'v1',
          status: 'Success',
          metadata: {},
        })
      }),
    ]
  }

  // --- internals -----------------------------------------------------------

  private ensure(col: string): Map<string, K8sObject> {
    let m = this.store.get(col)
    if (!m) {
      m = new Map()
      this.store.set(col, m)
    }
    return m
  }

  private listBody(col: string): K8sList {
    const items = [...(this.store.get(col)?.values() ?? [])]
    return {
      apiVersion: 'v1',
      kind: 'List',
      metadata: this.suppressListRV ? {} : { resourceVersion: String(this.rv) },
      items,
    }
  }

  private openStream(col: string): ReadableStream<Uint8Array> {
    const set = this.watchers.get(col) ?? new Set<Watcher>()
    this.watchers.set(col, set)
    let watcher: Watcher | undefined
    return new ReadableStream<Uint8Array>({
      start: (controller) => {
        watcher = { controller }
        set.add(watcher)
      },
      cancel: () => {
        if (watcher) set.delete(watcher)
      },
    })
  }

  private push(col: string, event: WatchEvent): void {
    const set = this.watchers.get(col)
    if (!set) return
    const line = this.enc.encode(JSON.stringify(event) + '\n')
    for (const w of set) {
      try {
        w.controller.enqueue(line)
      } catch {
        /* stream already closed */
      }
    }
  }
}

function colKey(gvr: GVR): string {
  return `${gvr.group}/${gvr.version}/${gvr.resource}`
}

function gvrOf(params: Record<string, string | readonly string[] | undefined>): GVR {
  return {
    group: String(params.group),
    version: String(params.version),
    resource: String(params.resource),
  }
}

function nameOf(obj: K8sObject): string {
  return obj.metadata.name ?? ''
}

function stampRV(obj: K8sObject, rv: string): K8sObject {
  return { ...obj, metadata: { ...obj.metadata, resourceVersion: rv } }
}

function statusBody(fault: Fault): Status {
  return {
    kind: 'Status',
    apiVersion: 'v1',
    status: 'Failure',
    code: fault.code,
    reason: fault.reason,
    message: fault.message ?? `mock error ${fault.code}`,
    metadata: {},
  }
}

function take(map: Map<string, Fault[]>, col: string): Fault | undefined {
  const arr = map.get(col)
  if (!arr || arr.length === 0) return undefined
  return arr.shift()
}

function pushTo(map: Map<string, Fault[]>, col: string, fault: Fault): void {
  const arr = map.get(col) ?? []
  arr.push(fault)
  map.set(col, arr)
}

function recordConnect(map: Map<string, WatchConnect[]>, col: string, c: WatchConnect): void {
  const arr = map.get(col) ?? []
  arr.push(c)
  map.set(col, arr)
}
