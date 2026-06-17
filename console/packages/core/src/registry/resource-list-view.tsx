// The generic list view (APO-776): a table driven entirely by the registry
// entry's `columns`, backed by useK8sList (one managed watch, no per-resource
// query hook). The first column links to the object's detail route. Loading,
// empty, and error states are handled here so every kind gets them for free.

import type { ReactNode } from 'react'
import { cn } from '../lib/cn'
import { useK8sList } from '../lib/hooks'
import { useLink } from '../components/chrome/link-context'
import { PageHeader } from '../components/chrome/page-header'
import { Panel, StateMessage } from './views-common'
import type { ResourceEntry } from './types'

export interface ResourceListViewProps {
  entry: ResourceEntry
  /** Right-aligned page-header actions (e.g. a New/YAML button). */
  actions?: ReactNode
  /** Override the default item-count subtitle. */
  subtitle?: ReactNode
}

const TH =
  'border-b border-[color:var(--border-default)] bg-[var(--apx-mist)] px-[var(--sp-4)] py-[var(--sp-3)] text-left text-[length:var(--t-overline)] font-medium uppercase tracking-[0.06em] text-[color:var(--text-muted)]'
const TD = 'border-b border-[color:var(--border-subtle)] px-[var(--sp-4)] py-[14px] align-middle'

export function ResourceListView({ entry, actions, subtitle }: ResourceListViewProps) {
  const Link = useLink()
  const list = useK8sList(entry.gvr)
  const items = list.data?.items ?? []
  const count = items.length
  const defaultSubtitle = list.isPending ? 'Loading…' : `${count} ${count === 1 ? 'item' : 'items'}`
  const lower = entry.displayName.toLowerCase()

  return (
    <div>
      <PageHeader title={entry.displayName} subtitle={subtitle ?? defaultSubtitle} actions={actions} />
      <Panel className="overflow-hidden">
        {list.isError ? (
          <StateMessage tone="error">{list.error?.message ?? 'Failed to load.'}</StateMessage>
        ) : list.isPending ? (
          <StateMessage>Loading {lower}…</StateMessage>
        ) : count === 0 ? (
          <StateMessage>No {lower} yet.</StateMessage>
        ) : (
          <table className="w-full border-collapse text-[length:var(--t-caption)]">
            <thead>
              <tr>
                {entry.columns.map((c) => (
                  <th key={c.id} scope="col" className={TH} style={c.width ? { width: c.width } : undefined}>
                    {c.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((obj, rowIndex) => {
                const name = obj.metadata.name
                // k8s names are URL-safe (DNS labels), so the slug is the raw
                // name — no encode here and no decode at the route, which also
                // removes the malformed-%-escape crash surface.
                const href = name ? `/${entry.path}/${name}` : undefined
                return (
                  <tr
                    key={obj.metadata.uid ?? name ?? `row-${rowIndex}`}
                    className="transition-colors hover:bg-[var(--apx-bone)]"
                  >
                    {entry.columns.map((c, i) => (
                      <td
                        key={c.id}
                        className={cn(TD, c.mono && 'font-mono text-[length:var(--t-micro)] text-[color:var(--text-secondary)]')}
                      >
                        {i === 0 && href ? (
                          <Link
                            to={href}
                            className="font-medium text-[color:var(--text-primary)] no-underline hover:text-[color:var(--text-link-hover)]"
                          >
                            {c.cell(obj)}
                          </Link>
                        ) : (
                          c.cell(obj)
                        )}
                      </td>
                    ))}
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  )
}
