// The generic detail view (APO-776): derives a single object from the managed
// list via useK8sObject (no independent GET/watch) and renders a metadata
// summary plus the raw object. A kind needing bespoke rendering supplies
// `entry.detail`, which replaces the generic body.

import { Fragment, type ReactNode } from 'react'
import { useK8sObject } from '../lib/hooks'
import { PageHeader } from '../components/chrome/page-header'
import { Panel, StateMessage } from './views-common'
import type { ResourceEntry } from './types'
import type { K8sObject } from '../lib/k8s-types'

export interface ResourceDetailViewProps {
  entry: ResourceEntry
  name: string
  /** Right-aligned page-header actions (e.g. YAML/Delete buttons). */
  actions?: ReactNode
}

export function ResourceDetailView({ entry, name, actions }: ResourceDetailViewProps) {
  const q = useK8sObject(entry.gvr, name)
  const obj = q.data
  const subtitle = obj?.metadata.namespace ? `${entry.kind} · ${obj.metadata.namespace}` : entry.kind

  if (q.isError) {
    return (
      <div>
        <PageHeader title={name} subtitle={entry.kind} actions={actions} />
        <Panel>
          <StateMessage tone="error">{q.error?.message ?? 'Failed to load.'}</StateMessage>
        </Panel>
      </div>
    )
  }
  if (!obj) {
    return (
      <div>
        <PageHeader title={name} subtitle={entry.kind} actions={actions} />
        <Panel>
          <StateMessage>{q.isPending ? 'Loading…' : `${entry.kind} “${name}” not found.`}</StateMessage>
        </Panel>
      </div>
    )
  }

  const Detail = entry.detail
  return (
    <div>
      <PageHeader title={name} subtitle={subtitle} actions={actions} />
      {Detail ? <Detail object={obj} entry={entry} /> : <GenericDetail object={obj} />}
    </div>
  )
}

function GenericDetail({ object }: { object: K8sObject }) {
  const meta = object.metadata
  const rows: Array<[string, ReactNode]> = [
    ['Name', meta.name ?? '—'],
    ...(meta.namespace ? [['Namespace', meta.namespace] as [string, ReactNode]] : []),
    ['Created', meta.creationTimestamp ?? '—'],
    ['UID', meta.uid ?? '—'],
  ]
  return (
    <div className="flex flex-col gap-[var(--sp-4)]">
      <Panel className="p-[var(--sp-6)]">
        <dl className="grid grid-cols-[160px_1fr] gap-x-[var(--sp-6)] gap-y-[var(--sp-3)] text-[length:var(--t-caption)]">
          {rows.map(([k, v]) => (
            <Fragment key={k}>
              <dt className="text-[color:var(--text-muted)]">{k}</dt>
              <dd className="font-mono text-[length:var(--t-micro)] text-[color:var(--text-secondary)]">{v}</dd>
            </Fragment>
          ))}
        </dl>
      </Panel>
      <Panel>
        <div className="border-b border-[color:var(--border-default)] bg-[var(--apx-mist)] px-[var(--sp-6)] py-[var(--sp-3)] text-[length:var(--t-overline)] font-medium uppercase tracking-[0.06em] text-[color:var(--text-muted)]">
          Object
        </div>
        <pre className="overflow-auto p-[var(--sp-6)] font-mono text-[length:var(--t-micro)] leading-[var(--lh-snug)] text-[color:var(--text-secondary)]">
          {JSON.stringify(object, null, 2)}
        </pre>
      </Panel>
    </div>
  )
}
