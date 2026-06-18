// The generic detail view (APO-776) wired to the per-object action set (APO-782
// follow-up). Derives a single object from the managed list via useK8sObject (no
// independent GET/watch) and renders a metadata summary plus the raw object. The
// header carries three affordances, each independently gated:
//   • a "YAML" menu (View / Copy kubectl / Download) — always, with an Edit
//     hand-off to the raw YAML tray when the kind is `yamlEditable`;
//   • an "Edit" button that opens the kind's bespoke wizard (`createWizard`);
//   • a "Delete" button (confirm dialog) gated by a delete SelfSubjectAccessReview.
// A kind needing bespoke rendering supplies `entry.detail`, which replaces the body.

import { Fragment, useState, type ReactNode } from 'react'
import { useK8sObject } from '../lib/hooks'
import { useDeleteResource } from '../lib/mutations'
import { PageHeader } from '../components/chrome/page-header'
import { Button } from '../components/ui/button'
import { ConfirmDialog } from '../components/ui/confirm-dialog'
import { useNavigate } from '../components/chrome/link-context'
import { useCan } from './discovery'
import { useKeyboardScope } from '../keyboard/scope-stack'
import { YamlTray } from '../yaml/yaml-tray'
import { YamlMenu } from '../yaml/yaml-menu'
import { Panel, StateMessage } from './views-common'
import type { ResourceEntry } from './types'
import type { K8sObject } from '../lib/k8s-types'

export interface ResourceDetailViewProps {
  entry: ResourceEntry
  name: string
  /** Right-aligned page-header actions, shown after the built-in affordances. */
  actions?: ReactNode
}

export function ResourceDetailView({ entry, name, actions }: ResourceDetailViewProps) {
  const q = useK8sObject(entry.gvr, name)
  const obj = q.data
  const navigate = useNavigate()
  const subtitle = obj?.metadata.namespace ? `${entry.kind} · ${obj.metadata.namespace}` : entry.kind

  const [editing, setEditing] = useState(false) // bespoke wizard (edit mode)
  const [editingRaw, setEditingRaw] = useState(false) // raw YAML tray
  const [confirmingDelete, setConfirmingDelete] = useState(false)

  const canEdit = useCan('update', entry.gvr, {
    name,
    namespace: obj?.metadata.namespace,
    enabled: !!entry.createWizard,
  })
  // Defer the delete SSAR until the object loads: a namespaced kind needs its
  // namespace in the review, and `obj?.metadata.namespace` is undefined until then.
  const canDelete = useCan('delete', entry.gvr, { name, namespace: obj?.metadata.namespace, enabled: !!obj })
  const del = useDeleteResource(entry.gvr)

  const Wizard = entry.createWizard

  // `e` opens the wizard on an editable, loaded object (shadowed while open).
  useKeyboardScope({
    level: 'view',
    enabled: !!Wizard && !!obj && !editing && canEdit.allowed,
    bindings: [{ keys: 'e', run: () => setEditing(true) }],
  })

  async function onDelete() {
    try {
      await del.remove(name, { namespace: obj?.metadata.namespace })
      setConfirmingDelete(false)
      navigate(`/${entry.path}`)
    } catch {
      // Surfaced in the dialog via `del.error`.
    }
  }

  const headerActions = obj ? (
    <>
      <YamlMenu entry={entry} object={obj} onEditRaw={entry.yamlEditable ? () => setEditingRaw(true) : undefined} />
      {Wizard && (
        <Button variant="secondary" size="sm" disabled={!canEdit.allowed} onClick={() => setEditing(true)}>
          Edit
        </Button>
      )}
      {canDelete.allowed && (
        <Button variant="danger" size="sm" onClick={() => setConfirmingDelete(true)}>
          Delete
        </Button>
      )}
      {actions}
    </>
  ) : (
    actions
  )

  const mounts = (
    <>
      {Wizard && <Wizard entry={entry} object={obj} open={editing} onClose={() => setEditing(false)} />}
      {entry.yamlEditable && <YamlTray entry={entry} object={obj} open={editingRaw} onClose={() => setEditingRaw(false)} />}
      <ConfirmDialog
        open={confirmingDelete}
        title={`Delete ${entry.kind} “${name}”?`}
        body="This permanently removes the object from the cluster. This cannot be undone."
        confirmLabel="Delete"
        pending={del.isPending}
        error={del.error?.message ?? null}
        onConfirm={() => void onDelete()}
        onCancel={() => {
          setConfirmingDelete(false)
          del.reset()
        }}
      />
    </>
  )

  if (q.isError) {
    return (
      <div>
        <PageHeader title={name} subtitle={entry.kind} actions={headerActions} />
        <Panel>
          <StateMessage tone="error">{q.error?.message ?? 'Failed to load.'}</StateMessage>
        </Panel>
        {mounts}
      </div>
    )
  }
  if (!obj) {
    // Keep the mounts here too: if the object is deleted on the server while a
    // tray/wizard is open, this branch takes over and unmounting would discard
    // the user's unsaved edits.
    return (
      <div>
        <PageHeader title={name} subtitle={entry.kind} actions={headerActions} />
        <Panel>
          <StateMessage>{q.isPending ? 'Loading…' : `${entry.kind} “${name}” not found.`}</StateMessage>
        </Panel>
        {mounts}
      </div>
    )
  }

  const Detail = entry.detail
  return (
    <div>
      <PageHeader title={name} subtitle={subtitle} actions={headerActions} />
      {Detail ? <Detail object={obj} entry={entry} /> : <GenericDetail object={obj} />}
      {mounts}
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
