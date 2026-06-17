// The generic detail view (APO-776) wired to the YAML tray (APO-777/778).
// Derives a single object from the managed list via useK8sObject (no independent
// GET/watch) and renders a metadata summary plus the raw object. When the kind
// is `yamlEditable`, an Edit affordance (gated by a SelfSubjectAccessReview, and
// also reachable with `e`) opens the tray over the current object. A kind
// needing bespoke rendering supplies `entry.detail`, which replaces the body.

import { Fragment, useState, type ReactNode } from 'react'
import { useK8sObject } from '../lib/hooks'
import { PageHeader } from '../components/chrome/page-header'
import { Button } from '../components/ui/button'
import { useCan } from './discovery'
import { useKeyboardScope } from '../keyboard/scope-stack'
import { YamlTray } from '../yaml/yaml-tray'
import { Panel, StateMessage } from './views-common'
import type { ResourceEntry } from './types'
import type { K8sObject } from '../lib/k8s-types'

export interface ResourceDetailViewProps {
  entry: ResourceEntry
  name: string
  /** Right-aligned page-header actions (e.g. extra buttons), shown after Edit. */
  actions?: ReactNode
}

export function ResourceDetailView({ entry, name, actions }: ResourceDetailViewProps) {
  const q = useK8sObject(entry.gvr, name)
  const obj = q.data
  const subtitle = obj?.metadata.namespace ? `${entry.kind} · ${obj.metadata.namespace}` : entry.kind

  const [editing, setEditing] = useState(false)
  const canEdit = useCan('update', entry.gvr, {
    name,
    namespace: obj?.metadata.namespace,
    enabled: entry.yamlEditable,
  })

  // `e` opens the tray on an editable, loaded object (shadowed while it is open).
  // Gated by the same SSAR as the Edit button, so the keyboard path can't bypass
  // an access check the button enforces.
  useKeyboardScope({
    level: 'view',
    enabled: entry.yamlEditable && !!obj && !editing && canEdit.allowed,
    bindings: [{ keys: 'e', run: () => setEditing(true) }],
  })

  const editAction =
    entry.yamlEditable && obj ? (
      <Button variant="secondary" size="sm" disabled={!canEdit.allowed} onClick={() => setEditing(true)}>
        Edit
      </Button>
    ) : null

  const headerActions =
    editAction || actions ? (
      <>
        {editAction}
        {actions}
      </>
    ) : undefined

  const tray = entry.yamlEditable ? (
    <YamlTray entry={entry} object={obj} open={editing} onClose={() => setEditing(false)} />
  ) : null

  if (q.isError) {
    return (
      <div>
        <PageHeader title={name} subtitle={entry.kind} actions={headerActions} />
        <Panel>
          <StateMessage tone="error">{q.error?.message ?? 'Failed to load.'}</StateMessage>
        </Panel>
        {tray}
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
      <PageHeader title={name} subtitle={subtitle} actions={headerActions} />
      {Detail ? <Detail object={obj} entry={entry} /> : <GenericDetail object={obj} />}
      {tray}
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
