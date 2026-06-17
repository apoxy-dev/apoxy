// The generic resource dispatcher (APO-774/776). The app's single splat route
// renders this with the URL tail under the shell: a slug (`proxies`) is a list,
// a slug + name (`proxies/my-proxy`) is a detail. The slug is resolved against
// the registry, so adding a kind never adds a route.

import type { ReactNode } from 'react'
import { ResourceListView } from './resource-list-view'
import { ResourceDetailView } from './resource-detail-view'
import { Panel, StateMessage } from './views-common'
import type { Registry, ResourceEntry } from './types'

export interface ResourceViewProps {
  registry: Registry
  /** URL tail under the shell, e.g. `proxies` or `proxies/my-proxy`. */
  splat: string
  /** Rendered when the slug matches no registered kind. */
  notFound?: ReactNode
  /** Page-header actions for a list view of `entry`. */
  listActions?: (entry: ResourceEntry) => ReactNode
  /** Page-header actions for a detail view of `entry`/`name`. */
  detailActions?: (entry: ResourceEntry, name: string) => ReactNode
}

export function ResourceView({ registry, splat, notFound, listActions, detailActions }: ResourceViewProps) {
  const segments = splat.split('/').filter(Boolean)
  const slug = segments[0]

  if (!slug) {
    return (
      notFound ?? (
        <Panel>
          <StateMessage>Select a resource from the sidebar.</StateMessage>
        </Panel>
      )
    )
  }

  const entry = registry.byPath(slug)
  if (!entry) {
    return (
      notFound ?? (
        <Panel>
          <StateMessage tone="error">Unknown resource “{slug}”.</StateMessage>
        </Panel>
      )
    )
  }

  // k8s names are URL-safe single segments, so the slug's tail is the raw name
  // (the list view links without encoding, so we don't decode here either).
  const name = segments[1]
  return name ? (
    <ResourceDetailView entry={entry} name={name} actions={detailActions?.(entry, name)} />
  ) : (
    <ResourceListView entry={entry} actions={listActions?.(entry)} />
  )
}
