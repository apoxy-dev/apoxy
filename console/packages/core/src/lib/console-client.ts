// Wiring helper: bundle the GVR client, a TanStack QueryClient, and the
// WatchManager so the three are constructed consistently (one QueryClient, the
// WatchManager as its sole writer). App entrypoints call this
// once and hand the bundle to <ConsoleProvider>.

import { QueryClient } from '@tanstack/react-query'
import { GVRClient } from './gvr-client'
import type { RequestDecorator } from './request-decorator'
import { WatchManager, type WatchManagerOptions } from './watch-manager'

export interface ConsoleClient {
  queryClient: QueryClient
  gvr: GVRClient
  watchManager: WatchManager
}

export interface CreateConsoleClientOptions {
  decorator: RequestDecorator
  /** Injectable transport; defaults to the global `fetch`. */
  fetch?: typeof fetch
  /** Bring your own QueryClient (e.g. to share devtools); one is made otherwise. */
  queryClient?: QueryClient
  watch?: WatchManagerOptions
}

/**
 * The cache defaults that make the WatchManager the sole writer: nothing
 * refetches on its own (`staleTime: Infinity`), data is never garbage-collected
 * out from under a live watch (`gcTime: Infinity`), and reads don't retry (the
 * WatchManager owns retry/backoff).
 */
function defaultQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: Infinity,
        gcTime: Infinity,
        retry: false,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
      },
    },
  })
}

export function createConsoleClient(opts: CreateConsoleClientOptions): ConsoleClient {
  const gvr = new GVRClient({ decorator: opts.decorator, fetch: opts.fetch })
  const queryClient = opts.queryClient ?? defaultQueryClient()
  const watchManager = new WatchManager(gvr, queryClient, opts.watch)
  return { queryClient, gvr, watchManager }
}
