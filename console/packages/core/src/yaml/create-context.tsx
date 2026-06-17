// The create seam (APO-778). A single shared YAML tray for *new* objects, opened
// from anywhere: the list view's "New <kind>" button and the ⌘K palette's
// "New <kind>" command both call `openCreate(entry)`. One tray instance keeps the
// create skeleton + SSA write path in one place rather than duplicating it per
// trigger. The tray opens with no `object`, so it renders the kind's skeleton and
// gates Save on a required `metadata.name` (the structural check).

import { createContext, useContext, useMemo, useState, type ReactNode } from 'react'
import { YamlTray } from './yaml-tray'
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
  return (
    <CreateContext.Provider value={api}>
      {children}
      {creating && (
        <YamlTray
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
