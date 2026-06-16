// The WatchManager: the single, ref-counted owner of list+watch for
// each `(scope, gvr)` and the ONLY writer of resource data into the TanStack
// Query cache. "Fetch" and "watch" are one feature here — a watched list *is*
// the cache — which removes the dashboard's three racing cache writers.
//
// Lifecycle it owns centrally (APO-770):
//   - 410 Gone         → relist from scratch
//   - BOOKMARK         → advance the stored resourceVersion
//   - disconnect       → bounded exponential backoff, then resume from rv
//   - auth refresh     → cycle the watch so the next connect carries a fresh
//                        token, without dropping the seeded list
//   - scope change     → tear down old-scope watches before building new ones,
//                        which fixes the project-switch leak structurally (no
//                        `window.location.reload()`).

import type { QueryClient } from '@tanstack/react-query'
import { GVRClient, K8sStatusError } from './gvr-client'
import type { Selectors } from './k8s-paths'
import type { GVR, K8sList, K8sObject } from './k8s-types'
import { entryKey, listKey, scopePrefix } from './cache-keys'

/** Abortable sleep, injectable so tests run without real timers. */
export interface Scheduler {
  sleep(ms: number, signal?: AbortSignal): Promise<void>
}

const defaultScheduler: Scheduler = {
  sleep(ms, signal) {
    if (ms <= 0 || signal?.aborted) return Promise.resolve()
    return new Promise((resolve) => {
      const t = setTimeout(resolve, ms)
      signal?.addEventListener('abort', () => {
        clearTimeout(t)
        resolve()
      }, { once: true })
    })
  },
}

export interface WatchManagerOptions {
  /** First reconnect delay after a stream error. Default 1000ms. */
  baseBackoffMs?: number
  /** Backoff ceiling. Default 30000ms. */
  maxBackoffMs?: number
  /**
   * How many times to retry the INITIAL list before rejecting `ready`. Bounds a
   * persistent non-fatal failure (401, 5xx, network) so the UI shows an error
   * instead of an infinite spinner. Default 5.
   */
  maxInitialListRetries?: number
  scheduler?: Scheduler
}

/** Handle returned by {@link WatchManager.subscribe}. */
export interface Subscription<T extends K8sObject = K8sObject> {
  /** The TanStack Query cache key this subscription feeds. */
  readonly key: readonly unknown[]
  /** Resolves with the initial LIST (or rejects on a fatal, non-retryable error). */
  readonly ready: Promise<K8sList<T>>
  /** Decrement the ref-count; tears the stream down when it reaches zero. */
  unsubscribe(): void
}

/** HTTP status codes that are not worth retrying a LIST against. */
function isFatalListStatus(code: number): boolean {
  return code === 400 || code === 403 || code === 404 || code === 405 || code === 422
}

interface Entry {
  readonly scope: string
  readonly gvr: GVR
  readonly selectors: Selectors | undefined
  readonly mapKey: string
  readonly key: readonly unknown[]
  refCount: number
  started: boolean
  stopped: boolean
  /** Bumped on (re)start and on stop to invalidate any in-flight run loop. */
  generation: number
  resourceVersion: string | undefined
  backoff: number
  /** Consecutive pre-settlement (initial-list) errors, bounded by maxInitialListRetries. */
  initialErrors: number
  /** Permanent stop signal for the whole entry. */
  teardown: AbortController
  /** The in-flight watch attempt; aborted (without teardown) to cycle the stream. */
  currentAttempt: AbortController | undefined
  /** Aborted to wake an in-progress backoff sleep (refreshAuth / teardown). */
  wake: AbortController | undefined
  initialSettled: boolean
  readonly initial: Promise<K8sList>
  resolveInitial: (list: K8sList) => void
  rejectInitial: (err: unknown) => void
}

interface WatchOutcome {
  kind: 'relist' | 'reconnect'
  /**
   * Whether the watch delivered ≥1 real data event (ADDED/MODIFIED/DELETED).
   * Only real data resets backoff — a bookmark-only or empty stream does not, so
   * a flapping watch paces itself.
   */
  dataProgressed: boolean
}

export class WatchManager {
  private readonly client: GVRClient
  private readonly qc: QueryClient
  private readonly baseBackoffMs: number
  private readonly maxBackoffMs: number
  private readonly maxInitialListRetries: number
  private readonly scheduler: Scheduler
  private readonly entries = new Map<string, Entry>()

  constructor(client: GVRClient, queryClient: QueryClient, opts: WatchManagerOptions = {}) {
    this.client = client
    this.qc = queryClient
    this.baseBackoffMs = opts.baseBackoffMs ?? 1000
    this.maxBackoffMs = opts.maxBackoffMs ?? 30000
    this.maxInitialListRetries = opts.maxInitialListRetries ?? 5
    this.scheduler = opts.scheduler ?? defaultScheduler
  }

  /** Current scope identity, read live from the client's RequestDecorator. */
  get scopeKey(): string {
    return this.client.decorator.scopeKey
  }

  /**
   * Subscribe to the managed list for `gvr` (+ selectors). The first subscriber
   * starts a LIST then a WATCH; the last to unsubscribe tears it down.
   */
  subscribe<T extends K8sObject = K8sObject>(gvr: GVR, selectors?: Selectors): Subscription<T> {
    const e = this.getOrCreate(gvr, selectors)
    e.refCount++
    if (!e.started) this.start(e)
    return {
      key: e.key,
      ready: e.initial as Promise<K8sList<T>>,
      unsubscribe: () => this.release(e),
    }
  }

  /**
   * The promise the `useK8sList` queryFn awaits: the initial LIST for this
   * `(scope, gvr)`. The hook's effect owns the ref-count via {@link subscribe};
   * this also *starts* the entry if nothing has yet, so a queryFn that runs
   * before (or instead of) a subscribe — e.g. a refetch after the cache was
   * cleared under a mounted observer — gets a promise that actually resolves
   * rather than a permanently-pending orphan.
   */
  whenReady<T extends K8sObject = K8sObject>(gvr: GVR, selectors?: Selectors): Promise<K8sList<T>> {
    const e = this.getOrCreate(gvr, selectors)
    if (!e.started) this.start(e)
    return e.initial as Promise<K8sList<T>>
  }

  /**
   * Cycle every live watch so the next connect re-runs the RequestDecorator and
   * carries a freshly-refreshed token, without relisting. The seeded list and
   * stored resourceVersion are preserved. Resets
   * backoff and wakes any in-progress backoff sleep so a refresh that lands
   * mid-reconnect reconnects promptly instead of waiting out the backoff.
   */
  refreshAuth(): void {
    for (const e of this.entries.values()) {
      e.backoff = 0
      e.currentAttempt?.abort()
      e.wake?.abort()
    }
  }

  /**
   * Tear down every watch in `scopeKey` and drop its cached data. Call this when
   * switching project *before* the new-scope subscriptions build, so the old
   * stream can never repopulate the cleared cache (the project-switch bug).
   */
  tearDownScope(scopeKey: string): void {
    for (const e of [...this.entries.values()]) {
      if (e.scope === scopeKey) this.stop(e, true)
    }
    this.qc.removeQueries({ queryKey: scopePrefix(scopeKey) })
  }

  /** Stop every watch and drop all cached data — for teardown on unmount of the
   *  whole console (or between tests). */
  dispose(): void {
    for (const e of [...this.entries.values()]) this.stop(e, true)
  }

  /** Scopes with at least one live entry (debugging/inspection). */
  activeScopes(): string[] {
    return [...new Set([...this.entries.values()].map((e) => e.scope))]
  }

  /** The resume resourceVersion currently stored for an entry (inspection/tests). */
  resourceVersionFor(gvr: GVR, selectors?: Selectors): string | undefined {
    return this.entries.get(entryKey(this.scopeKey, gvr, selectors))?.resourceVersion
  }

  // --- entry lifecycle -----------------------------------------------------

  private getOrCreate(gvr: GVR, selectors?: Selectors): Entry {
    const scope = this.scopeKey
    const mapKey = entryKey(scope, gvr, selectors)
    const existing = this.entries.get(mapKey)
    if (existing) return existing

    let resolveInitial!: (list: K8sList) => void
    let rejectInitial!: (err: unknown) => void
    const initial = new Promise<K8sList>((resolve, reject) => {
      resolveInitial = resolve
      rejectInitial = reject
    })
    const e: Entry = {
      scope,
      gvr,
      selectors,
      mapKey,
      key: listKey(scope, gvr, selectors),
      refCount: 0,
      started: false,
      stopped: false,
      generation: 0,
      resourceVersion: undefined,
      backoff: 0,
      initialErrors: 0,
      teardown: new AbortController(),
      currentAttempt: undefined,
      wake: undefined,
      initialSettled: false,
      initial,
      resolveInitial,
      rejectInitial,
    }
    this.entries.set(mapKey, e)
    return e
  }

  private start(e: Entry): void {
    e.started = true
    const gen = ++e.generation
    void this.run(e, gen)
  }

  private release(e: Entry): void {
    if (e.stopped) return
    e.refCount--
    if (e.refCount <= 0) this.stop(e, true)
  }

  private stop(e: Entry, removeData: boolean): void {
    if (e.stopped) return
    e.stopped = true
    e.started = false
    e.generation++ // any running loop sees `active() === false` and returns
    e.teardown.abort()
    e.currentAttempt?.abort()
    e.wake?.abort() // wake any in-progress backoff sleep so the loop returns
    this.entries.delete(e.mapKey)
    if (removeData) this.qc.removeQueries({ queryKey: e.key, exact: true })
  }

  private active(e: Entry, gen: number): boolean {
    return e.generation === gen && e.started && !e.teardown.signal.aborted
  }

  // --- the run loop --------------------------------------------------------

  private async run(e: Entry, gen: number): Promise<void> {
    let needList = true
    while (this.active(e, gen)) {
      try {
        if (needList) {
          const list = await this.client.list(e.gvr, this.listParams(e))
          if (!this.active(e, gen)) return
          e.initialErrors = 0
          e.resourceVersion = list.metadata.resourceVersion
          this.seedList(e, normalizeList(list))
          needList = false
          if (e.resourceVersion === undefined) {
            // No resourceVersion ⇒ no resumable watch. Keep the seeded list and
            // relist, paced by backoff so a server that always omits the rv
            // degrades to polling instead of a hot LIST loop. Backoff is NOT
            // reset here — only real watch data resets it.
            await this.backoff(e, gen)
            needList = true
            continue
          }
        }

        const outcome = await this.consumeWatch(e, gen)
        if (!this.active(e, gen)) return
        // Reset pacing only when the watch delivered real data — a healthy
        // stream. A bookmark-only / empty / 410-storming stream keeps the
        // growing backoff so it paces itself instead of hot-looping.
        if (outcome.dataProgressed) e.backoff = 0
        if (outcome.kind === 'relist') {
          e.resourceVersion = undefined
          needList = true
        }
        // Re-establish (relist or rewatch) through backoff(): instant when the
        // backoff is 0 (healthy), paced when it has grown.
        await this.backoff(e, gen)
      } catch (err) {
        if (!this.active(e, gen)) return
        if (err instanceof K8sStatusError && err.isGone) {
          e.resourceVersion = undefined
          needList = true
          await this.backoff(e, gen)
          continue
        }
        // Pre-settlement: bound retries so a persistent failure (401, 5xx, or a
        // network error) rejects `ready` instead of spinning a spinner forever;
        // an immediately-fatal status (403/404/405/422) rejects on the first hit.
        if (!e.initialSettled) {
          const code = err instanceof K8sStatusError ? err.code : 0
          if (isFatalListStatus(code) || ++e.initialErrors >= this.maxInitialListRetries) {
            this.settleError(e, err)
            this.stop(e, false)
            return
          }
        }
        // Post-settlement (or within the pre-settlement retry budget): keep the
        // last-known data and resume after backoff. (Surfacing a persistent
        // post-settlement failure as a query error state is an M3 follow-up.)
        if (e.resourceVersion === undefined) needList = true
        await this.backoff(e, gen)
      }
    }
  }

  private async consumeWatch(e: Entry, gen: number): Promise<WatchOutcome> {
    const attempt = new AbortController()
    e.currentAttempt = attempt
    const onTeardown = () => attempt.abort()
    if (e.teardown.signal.aborted) attempt.abort()
    else e.teardown.signal.addEventListener('abort', onTeardown, { once: true })

    let dataProgressed = false
    try {
      for await (const ev of this.client.watch(e.gvr, this.watchParams(e), attempt.signal)) {
        if (!this.active(e, gen)) return { kind: 'reconnect', dataProgressed }
        switch (ev.type) {
          case 'ADDED':
          case 'MODIFIED': {
            dataProgressed = true
            const obj = ev.object as K8sObject
            this.applyUpsert(e, obj)
            this.advanceRV(e, obj)
            break
          }
          case 'DELETED': {
            dataProgressed = true
            const obj = ev.object as K8sObject
            this.applyDelete(e, obj)
            this.advanceRV(e, obj)
            break
          }
          case 'BOOKMARK': {
            // Advances the resume rv but is NOT real data progress (does not
            // reset backoff), so a bookmark-only flapping stream still paces.
            this.advanceRV(e, ev.object as K8sObject)
            break
          }
          case 'ERROR': {
            const st = ev.object as { code?: number }
            const code = st?.code ?? 0
            // 410 Gone, or an error frame with no usable code, re-syncs via a
            // relist rather than blindly resuming a watch the server flagged
            // broken. Any other coded error throws to the run loop's handler.
            if (code === 410 || code === 0) return { kind: 'relist', dataProgressed }
            throw new K8sStatusError(ev.object as K8sStatusError['status'], code)
          }
        }
      }
      return { kind: 'reconnect', dataProgressed }
    } catch (err) {
      // A cycle (refreshAuth) or teardown aborts the attempt; that is not a
      // stream error — let the run loop decide (resume vs. stop via active()).
      if (attempt.signal.aborted) return { kind: 'reconnect', dataProgressed }
      throw err
    } finally {
      e.teardown.signal.removeEventListener('abort', onTeardown)
      // Cancel the underlying watch fetch whenever we stop consuming it (relist,
      // reconnect, or stop) so the previous stream can't linger past the next one.
      attempt.abort()
      if (e.currentAttempt === attempt) e.currentAttempt = undefined
    }
  }

  private async backoff(e: Entry, gen: number): Promise<void> {
    const wait = e.backoff
    e.backoff = e.backoff ? Math.min(this.maxBackoffMs, e.backoff * 2) : this.baseBackoffMs
    if (wait <= 0) return
    // The sleep is woken by teardown (stop aborts e.wake) and by refreshAuth, so
    // a reconnect isn't stuck behind a long backoff. active() is re-checked by
    // the caller after we return.
    e.wake = new AbortController()
    try {
      await this.scheduler.sleep(wait, e.wake.signal)
    } finally {
      e.wake = undefined
    }
    void gen
  }

  // --- the single cache writer ---------------------------------------------

  private seedList(e: Entry, list: K8sList): void {
    // Write the list straight to the cache so the WatchManager is the sole
    // writer even before any observer mounts (and so a relist replaces it
    // wholesale). The watch only starts after this resolves, so there is no
    // race with a watch-event write clobbering the seed.
    this.qc.setQueryData(e.key, list)
    if (!e.initialSettled) {
      e.initialSettled = true
      e.resolveInitial(list) // also unblocks the useK8sList queryFn / `ready`
    }
  }

  private settleError(e: Entry, err: unknown): void {
    if (!e.initialSettled) {
      e.initialSettled = true
      e.rejectInitial(err)
    }
  }

  private applyUpsert(e: Entry, obj: K8sObject): void {
    const id = uidOf(obj)
    this.qc.setQueryData<K8sList>(e.key, (prev) => {
      const base = prev ?? emptyList()
      const items = base.items.slice()
      const i = items.findIndex((o) => uidOf(o) === id)
      if (i >= 0) items[i] = obj
      else items.push(obj)
      return {
        ...base,
        items,
        metadata: {
          ...base.metadata,
          resourceVersion: obj.metadata.resourceVersion ?? base.metadata.resourceVersion,
        },
      }
    })
  }

  private applyDelete(e: Entry, obj: K8sObject): void {
    const id = uidOf(obj)
    this.qc.setQueryData<K8sList>(e.key, (prev) => {
      if (!prev) return prev
      return { ...prev, items: prev.items.filter((o) => uidOf(o) !== id) }
    })
  }

  private advanceRV(e: Entry, obj: K8sObject): void {
    const rv = obj.metadata?.resourceVersion
    if (rv) e.resourceVersion = rv
  }

  private listParams(e: Entry) {
    return { ...e.selectors }
  }

  private watchParams(e: Entry) {
    return { ...e.selectors, resourceVersion: e.resourceVersion, allowWatchBookmarks: true }
  }
}

/** Stable per-object identity: prefer uid, fall back to namespace/name. */
function uidOf(obj: K8sObject): string {
  const m = obj.metadata
  return m?.uid ?? `${m?.namespace ?? ''}/${m?.name ?? ''}`
}

function emptyList(): K8sList {
  return { metadata: {}, items: [] }
}

function normalizeList(list: K8sList): K8sList {
  return list.items ? list : { ...list, items: [] }
}
