// The generic GVR client: one small `fetch`-based client over the
// uniform Kubernetes verbs — list / get / apply (SSA) / delete / watch — with
// label/field selectors and typed Status error handling. It builds paths from a
// GVR and applies the RequestDecorator for scoping/headers. There are no
// per-operation methods and no API-version strings at call sites; it replaces
// `openapi-client-axios` entirely.

import type { RequestDecorator } from './request-decorator'
import type { GVR, K8sList, K8sObject, Status, WatchEvent } from './k8s-types'
import {
  type ListParams,
  type WatchParams,
  listUrl,
  objectPath,
  watchUrl,
} from './k8s-paths'

const CONTENT_TYPE_JSON = 'application/json'
/** Server-Side Apply media type (JSON is valid YAML, so we send JSON). */
const CONTENT_TYPE_APPLY = 'application/apply-patch+yaml'

/** Error thrown for any non-2xx response, carrying the decoded apiserver Status. */
export class K8sStatusError extends Error {
  readonly status: Status
  readonly httpStatus: number

  constructor(status: Status, httpStatus: number) {
    super(status.message ?? status.reason ?? `Kubernetes API error ${httpStatus}`)
    this.name = 'K8sStatusError'
    this.status = status
    this.httpStatus = httpStatus
  }

  /** The apiserver's suggested code, falling back to the HTTP status. */
  get code(): number {
    return this.status.code ?? this.httpStatus
  }

  /** Machine-readable reason (e.g. `Gone`, `NotFound`, `Conflict`). */
  get reason(): string | undefined {
    return this.status.reason
  }

  /** True for `410 Gone` / `Expired` — the WatchManager relists on this. */
  get isGone(): boolean {
    return this.code === 410
  }
}

export interface ApplyOptions {
  namespace?: string
  /** SSA field manager; defaults to `console`. */
  fieldManager?: string
  /**
   * Force-take ownership of fields owned by another manager. Defaults to
   * `false` so a field-ownership conflict surfaces as a `409` the YAML tray can
   * show, instead of silently stealing ownership on every save.
   */
  force?: boolean
}

export interface MutateOptions {
  namespace?: string
}

export interface GVRClientOptions {
  decorator: RequestDecorator
  /** Injectable for tests; defaults to the global `fetch`. */
  fetch?: typeof fetch
}

export class GVRClient {
  /** Public so the WatchManager can read `decorator.scopeKey` and callers can
   *  swap the decorator on a project switch. */
  decorator: RequestDecorator
  private readonly fetchImpl: typeof fetch

  constructor(opts: GVRClientOptions) {
    this.decorator = opts.decorator
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis)
  }

  /** LIST a collection; returns the decoded `K8sList` (not an HTTP envelope). */
  async list<T extends K8sObject = K8sObject>(gvr: GVR, params: ListParams = {}): Promise<K8sList<T>> {
    const res = await this.send('GET', listUrl(gvr, params), { accept: CONTENT_TYPE_JSON })
    return this.readJson<K8sList<T>>(res)
  }

  /** GET a single object by name. */
  async get<T extends K8sObject = K8sObject>(
    gvr: GVR,
    name: string,
    opts: MutateOptions = {},
  ): Promise<T> {
    const res = await this.send('GET', objectPath(gvr, name, opts.namespace), {
      accept: CONTENT_TYPE_JSON,
    })
    return this.readJson<T>(res)
  }

  /** Create-or-update via Server-Side Apply (`application/apply-patch+yaml`). */
  async apply<T extends K8sObject = K8sObject>(
    gvr: GVR,
    name: string,
    body: Partial<T> & K8sObject,
    opts: ApplyOptions = {},
  ): Promise<T> {
    const q = new URLSearchParams({ fieldManager: opts.fieldManager ?? 'console' })
    if (opts.force) q.set('force', 'true')
    const path = `${objectPath(gvr, name, opts.namespace)}?${q.toString()}`
    const res = await this.send('PATCH', path, {
      accept: CONTENT_TYPE_JSON,
      contentType: CONTENT_TYPE_APPLY,
      body: JSON.stringify(body),
    })
    return this.readJson<T>(res)
  }

  /** DELETE an object; returns the server's `Status` or the deleted object. */
  async delete<T extends K8sObject = K8sObject>(
    gvr: GVR,
    name: string,
    opts: MutateOptions = {},
  ): Promise<Status | T> {
    const res = await this.send('DELETE', objectPath(gvr, name, opts.namespace), {
      accept: CONTENT_TYPE_JSON,
    })
    return this.readJson<Status | T>(res)
  }

  /**
   * WATCH a collection from `params.resourceVersion`, yielding decoded
   * {@link WatchEvent}s until the stream ends or `signal` aborts. Bookmarks are
   * requested by default so the resume `resourceVersion` keeps advancing on
   * otherwise-idle collections. Non-2xx responses (e.g. `410 Gone`) throw a
   * {@link K8sStatusError} before the first event.
   */
  async *watch<T extends K8sObject = K8sObject>(
    gvr: GVR,
    params: WatchParams = {},
    signal?: AbortSignal,
  ): AsyncGenerator<WatchEvent<T>> {
    const res = await this.send('GET', watchUrl(gvr, params), {
      accept: CONTENT_TYPE_JSON,
      signal,
    })
    if (!res.body) return
    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let buf = ''

    // The abort signal must interrupt a blocked read() even if the transport
    // ignores it, and the finally must cancel() the body so the server stream is
    // torn down on every exit (abort, relist, reconnect) — releaseLock alone
    // leaves it open and leaks a watcher.
    let onAbort: (() => void) | undefined
    const aborted = signal
      ? new Promise<'aborted'>((resolve) => {
          onAbort = () => resolve('aborted')
          if (signal.aborted) resolve('aborted')
          else signal.addEventListener('abort', onAbort, { once: true })
        })
      : undefined

    try {
      for (;;) {
        const result = aborted ? await Promise.race([reader.read(), aborted]) : await reader.read()
        if (result === 'aborted') return
        const { done, value } = result
        if (done) break
        buf += decoder.decode(value, { stream: true })
        // Newline-delimited JSON: a chunk may split a line, so only parse up to
        // the last newline and keep the remainder buffered.
        let nl: number
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl).trim()
          buf = buf.slice(nl + 1)
          if (line) yield JSON.parse(line) as WatchEvent<T>
        }
      }
      // Flush a final event that wasn't newline-terminated before the stream ended.
      const tail = buf.trim()
      if (tail) yield JSON.parse(tail) as WatchEvent<T>
    } finally {
      if (signal && onAbort) signal.removeEventListener('abort', onAbort)
      // Best-effort cancel of the body so the server tears the stream down; not
      // awaited, since a cancel on an abandoned stream can hang and we must not
      // pin the generator open past this point.
      void reader.cancel().catch(() => {})
    }
  }

  // --- internals -----------------------------------------------------------

  private async send(
    method: string,
    path: string,
    init: { accept?: string; contentType?: string; body?: BodyInit; signal?: AbortSignal },
  ): Promise<Response> {
    const headers = new Headers()
    if (init.accept) headers.set('Accept', init.accept)
    if (init.contentType) headers.set('Content-Type', init.contentType)
    const { url, headers: decorated } = this.decorator.decorate({ path, method, headers })
    const res = await this.fetchImpl(url, {
      method,
      headers: decorated,
      body: init.body,
      signal: init.signal,
    })
    if (!res.ok) throw await this.toStatusError(res)
    return res
  }

  private async readJson<T>(res: Response): Promise<T> {
    return (await res.json()) as T
  }

  private async toStatusError(res: Response): Promise<K8sStatusError> {
    let status: Status
    try {
      status = (await res.json()) as Status
    } catch {
      status = { metadata: {}, code: res.status, message: res.statusText, status: 'Failure' }
    }
    return new K8sStatusError(status, res.status)
  }
}
