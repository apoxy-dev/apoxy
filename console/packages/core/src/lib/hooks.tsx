// React surface over the WatchManager. `useK8sList` subscribes to a
// managed list (ref-counted) and re-renders on changes; `useK8sObject` derives a
// single object from that same managed list via `select` — it does NOT start its
// own GET/watch. Selectors keep re-renders scoped: a row only re-renders when its
// own object changes, because the WatchManager preserves the identity of
// unchanged items and TanStack Query structurally shares `select` output.

import { createContext, useContext, useEffect, useMemo } from 'react'
import type { ReactNode } from 'react'
import { QueryClientProvider, useQuery } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import type { ConsoleClient } from './console-client'
import type { Selectors } from './k8s-paths'
import type { GVR, K8sList, K8sObject } from './k8s-types'
import { entryKey, listKey } from './cache-keys'

const ConsoleClientContext = createContext<ConsoleClient | null>(null)

/** Provides the console client and wires its QueryClient in one component. */
export function ConsoleProvider({
  client,
  children,
}: {
  client: ConsoleClient
  children: ReactNode
}) {
  return (
    <QueryClientProvider client={client.queryClient}>
      <ConsoleClientContext.Provider value={client}>{children}</ConsoleClientContext.Provider>
    </QueryClientProvider>
  )
}

export function useConsoleClient(): ConsoleClient {
  const c = useContext(ConsoleClientContext)
  if (!c) throw new Error('useConsoleClient must be used within <ConsoleProvider>')
  return c
}

export function useWatchManager() {
  return useConsoleClient().watchManager
}

export interface UseK8sListOptions<T extends K8sObject, S> {
  selectors?: Selectors
  /** Map the managed list to derived data; re-renders track the result's identity. */
  select?: (list: K8sList<T>) => S
  /** Skip the subscription and query entirely when false. */
  enabled?: boolean
}

/**
 * Subscribe to the managed list for `gvr`. The returned query reads the single
 * watched cache entry the WatchManager owns; the initial LIST resolves loading,
 * and watch events update it in place.
 */
export function useK8sList<T extends K8sObject = K8sObject, S = K8sList<T>>(
  gvr: GVR,
  opts: UseK8sListOptions<T, S> = {},
): UseQueryResult<S, Error> {
  const mgr = useWatchManager()
  // Scope is read non-reactively here. In M2 a project switch is expected to
  // remount the tree / supply a fresh ConsoleProvider value (or swap the manager
  // imperatively via tearDownScope + re-subscribe). Making `scopeKey` itself
  // reactive (useSyncExternalStore over a decorator-change signal) is deferred to
  // the editions work where the switch UI is wired.
  const scope = mgr.scopeKey
  const selectors = opts.selectors
  const enabled = opts.enabled ?? true

  // String identity of (scope, gvr, selectors): stable across renders so the
  // subscription effect doesn't churn on fresh `gvr`/`selectors` object literals.
  const depKey = useMemo(
    () => entryKey(scope, gvr, selectors),
    [scope, gvr.group, gvr.version, gvr.resource, selectors?.namespace, selectors?.labelSelector, selectors?.fieldSelector],
  )
  const key = useMemo(() => listKey(scope, gvr, selectors), [depKey])

  useEffect(() => {
    if (!enabled) return
    const sub = mgr.subscribe<T>(gvr, selectors)
    return () => sub.unsubscribe()
    // depKey captures gvr+selectors+scope; mgr is stable.
  }, [mgr, depKey, enabled])

  return useQuery<K8sList<T>, Error, S>({
    queryKey: key,
    queryFn: () => mgr.whenReady<T>(gvr, selectors),
    enabled,
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
    ...(opts.select ? { select: opts.select } : {}),
  })
}

export interface UseK8sObjectOptions {
  selectors?: Selectors
  enabled?: boolean
}

/**
 * Derive a single object by name from the managed list — no independent
 * GET/watch. Returns `undefined` until the object appears (or if it
 * is absent). Re-renders only when that object changes.
 */
export function useK8sObject<T extends K8sObject = K8sObject>(
  gvr: GVR,
  name: string,
  opts: UseK8sObjectOptions = {},
): UseQueryResult<T | undefined, Error> {
  return useK8sList<T, T | undefined>(gvr, {
    selectors: opts.selectors,
    enabled: opts.enabled,
    select: (list) => list.items.find((o) => o.metadata.name === name),
  })
}
