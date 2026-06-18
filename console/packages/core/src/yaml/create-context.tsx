// The create seam (APO-778, reworked for bespoke wizards). A single shared mount
// for *new* objects, opened from anywhere: the list view's "New <kind>" button
// and the ⌘K palette's "New <kind>" command both call `openCreate(entry)`. Create
// now runs through the kind's bespoke `createWizard` (a structured form with an
// optional YAML tab) — there is no generic raw-YAML create — so `openCreate` is
// only wired for kinds that register a wizard.

import { createContext, useContext, useMemo, useState, type ReactNode } from 'react'
import type { ResourceEntry } from '../registry/types'
import type { K8sObject } from '../lib/k8s-types'

export interface CreateApi {
  /** Open the shared YAML tray on a blank skeleton for `entry`'s kind. */
  openCreate: (entry: ResourceEntry) => void
}

const CreateContext = createContext<CreateApi | null>(null)

/** The create API, or `null` when no {@link CreateProvider} is mounted (so the
 *  list view simply omits its "New" affordance, and tests need no provider). */
export function useCreate(): CreateApi | null {
  return useContext(CreateContext)
}

export interface CreateProviderProps {
  children: ReactNode
  /** Notified with the server object after a successful create. */
  onCreated?: (obj: K8sObject) => void
}

export function CreateProvider({ children, onCreated }: CreateProviderProps) {
  const [creating, setCreating] = useState<ResourceEntry | null>(null)
  const api = useMemo<CreateApi>(() => ({ openCreate: (entry) => setCreating(entry) }), [])
  // Only kinds with a bespoke wizard reach here (the "New" affordance is gated on
  // it), but guard anyway so a stray openCreate is a no-op, not a crash.
  const Wizard = creating?.createWizard
  return (
    <CreateContext.Provider value={api}>
      {children}
      {creating && Wizard && (
        <Wizard
          entry={creating}
          open
          onClose={() => setCreating(null)}
          onSaved={(obj) => {
            setCreating(null)
            onCreated?.(obj)
          }}
        />
      )}
    </CreateContext.Provider>
  )
}
