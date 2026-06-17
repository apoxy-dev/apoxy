// Generic CRUD hooks over the GVR client (APO-776) — the replacement for the
// ~12 copy-paste `api/<resource>/hooks.ts` files. They wrap apply (SSA) and
// delete as TanStack mutations for pending/error state.
//
// SINGLE-WRITER INVARIANT: these deliberately do NOT touch the query cache.
// The WatchManager is the sole cache writer; an apply/delete shows up in the UI
// when its watch event arrives. Optimistic cache writes here would race the
// watch stream and reintroduce the dual-writer bugs M2 exists to prevent.

import { useMutation } from '@tanstack/react-query'
import { useConsoleClient } from './hooks'
import type { ApplyOptions, MutateOptions } from './gvr-client'
import type { GVR, K8sObject, Status } from './k8s-types'

export interface UseApplyResourceResult<T extends K8sObject> {
  apply: (name: string, body: Partial<T> & K8sObject, options?: ApplyOptions) => Promise<T>
  isPending: boolean
  error: Error | null
  reset: () => void
}

/** Create-or-update a resource via Server-Side Apply. */
export function useApplyResource<T extends K8sObject = K8sObject>(gvr: GVR): UseApplyResourceResult<T> {
  const client = useConsoleClient()
  const m = useMutation<T, Error, { name: string; body: Partial<T> & K8sObject; options?: ApplyOptions }>({
    mutationFn: (vars) => client.gvr.apply<T>(gvr, vars.name, vars.body, vars.options),
  })
  return {
    apply: (name, body, options) => m.mutateAsync({ name, body, options }),
    isPending: m.isPending,
    error: m.error,
    reset: m.reset,
  }
}

export interface UseDeleteResourceResult<T extends K8sObject> {
  remove: (name: string, options?: MutateOptions) => Promise<Status | T>
  isPending: boolean
  error: Error | null
  reset: () => void
}

/** Delete a resource by name. */
export function useDeleteResource<T extends K8sObject = K8sObject>(gvr: GVR): UseDeleteResourceResult<T> {
  const client = useConsoleClient()
  const m = useMutation<Status | T, Error, { name: string; options?: MutateOptions }>({
    mutationFn: (vars) => client.gvr.delete<T>(gvr, vars.name, vars.options),
  })
  return {
    remove: (name, options) => m.mutateAsync({ name, options }),
    isPending: m.isPending,
    error: m.error,
    reset: m.reset,
  }
}
