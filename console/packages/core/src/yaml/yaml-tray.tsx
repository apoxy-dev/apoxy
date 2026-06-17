// The YAML tray (APO-777) + its write path (APO-778). A right-side drawer that
// edits one object as YAML, validates per-kind on every keystroke, and saves via
// Server-Side Apply. Two safety rails on the write path:
//   • changed-on-server — the live object (watched, single-writer) advanced past
//     the resourceVersion the editor opened at ⇒ offer to reload.
//   • conflict — SSA without force hit a 409 (another field manager owns a field)
//     ⇒ offer to overwrite (force=true).
// It registers a modal `tray` scope so list-nav keys are shadowed; Esc cancels
// (guarded when dirty) and ⌘S saves, both allowed while the textarea is focused.

import { useLayoutEffect, useMemo, useRef, useState } from 'react'
import { cn } from '../lib/cn'
import { Button } from '../components/ui/button'
import { useApplyResource } from '../lib/mutations'
import { useK8sObject } from '../lib/hooks'
import { K8sStatusError } from '../lib/gvr-client'
import { useKeyboardScope } from '../keyboard/scope-stack'
import type { K8sObject } from '../lib/k8s-types'
import type { ResourceEntry } from '../registry/types'
import { forEditing, fromYaml, skeleton, toYaml } from './yaml-doc'
import { hasBlockingProblems, validateObject, type Problem } from './validate'
import { TextAreaEditor, useTrayEditor, type TrayEditor } from './editor'

export interface YamlTrayProps {
  entry: ResourceEntry
  /** The object to edit; omit to open a create skeleton. */
  object?: K8sObject
  open: boolean
  onClose: () => void
  /** Called with the server's object after a successful apply. */
  onSaved?: (obj: K8sObject) => void
  /** Swap the editor widget (e.g. a CodeMirror-6 implementation). */
  editor?: TrayEditor
}

export function YamlTray({ entry, object, open, onClose, onSaved, editor }: YamlTrayProps) {
  // Explicit prop wins; otherwise the app-installed editor (CodeMirror); else the
  // dependency-free textarea, so the tray always renders (incl. in jsdom tests).
  const provided = useTrayEditor()
  const Editor = editor ?? provided ?? TextAreaEditor

  const [text, setText] = useState('')
  const [baseline, setBaseline] = useState('')
  const [conflict, setConflict] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [confirmingClose, setConfirmingClose] = useState(false)
  const [confirmingReload, setConfirmingReload] = useState(false)
  // Identity (uid) the editor's buffer was last baselined for, so we re-baseline
  // on a genuine new object but never on a live update or a transient drop.
  const baselinedFor = useRef<{ uid: string | undefined } | null>(null)

  const { apply, isPending } = useApplyResource(entry.gvr)

  // Watch the live object (single managed watch, ref-counted) to detect a
  // server-side change while editing. Disabled for the create case (no name).
  const name = object?.metadata.name ?? ''
  const live = useK8sObject(entry.gvr, name, { enabled: open && name !== '' }).data

  // (Re)baseline when the tray opens or the edited object's identity changes.
  // Keyed on uid (stable across MODIFIED), so live updates never clobber edits.
  // Critically, a transient drop to `object === undefined` (e.g. the object is
  // deleted on the server while editing) is IGNORED so the user's buffer and
  // unsaved edits survive instead of being wiped to a create skeleton. A layout
  // effect (pre-paint) so the baseline is set before the first paint.
  const uid = object?.metadata.uid
  useLayoutEffect(() => {
    if (!open) {
      baselinedFor.current = null
      return
    }
    const prev = baselinedFor.current
    const justOpened = prev === null
    const switchedObject = prev !== null && uid !== prev.uid && object !== undefined
    if (!justOpened && !switchedObject) return
    const value = object ? forEditing(object) : skeleton(entry.gvr, entry.kind)
    const yaml = toYaml(value)
    setText(yaml)
    setBaseline(yaml)
    setConflict(false)
    setSaveError(null)
    setConfirmingClose(false)
    setConfirmingReload(false)
    baselinedFor.current = { uid }
    // entry.gvr/kind are stable for a given entry; baseline tracks open + identity.
  }, [open, uid])

  const parsed = useMemo(() => fromYaml(text), [text])
  const problems = useMemo<Problem[]>(
    () =>
      parsed.error
        ? [{ path: '', message: parsed.error, severity: 'error' }]
        : validateObject(parsed.value, entry.schema),
    [parsed, entry.schema],
  )
  const blocking = hasBlockingProblems(problems)

  const dirty = text !== baseline
  // Compare the *editable projection* (forEditing strips status/managedFields/rv)
  // rather than raw resourceVersion, so a status or managed-fields write — which
  // bumps the rv but changes nothing the user is editing — doesn't nag with a
  // false "changed on the server" banner. `baseline` is the projection captured
  // at open/reload, so this is server-now vs. what-we-loaded.
  const liveProjection = useMemo(() => (live ? toYaml(forEditing(live)) : undefined), [live])
  const changedOnServer = open && !!object && liveProjection !== undefined && liveProjection !== baseline
  // Edits to an existing object require a change; a create skeleton can be saved
  // as soon as it validates (its required-name check gates it instead).
  const saveDisabled = isPending || blocking || (!!object && !dirty)

  function reloadFromServer() {
    if (!live) return
    const yaml = toYaml(forEditing(live))
    setText(yaml)
    setBaseline(yaml)
    setConflict(false)
    setSaveError(null)
    setConfirmingReload(false)
  }

  function requestReload() {
    // Reloading replaces the editor with the server copy; confirm first when
    // there are unsaved edits, mirroring the close guard. Cancel any pending
    // close confirm so the two prompts can't show at once.
    if (dirty && !confirmingReload) {
      setConfirmingClose(false)
      setConfirmingReload(true)
      return
    }
    reloadFromServer()
  }

  function requestClose() {
    if (dirty && !confirmingClose) {
      setConfirmingReload(false)
      setConfirmingClose(true)
      return
    }
    onClose()
  }

  async function save(force = false) {
    if (parsed.error) return
    const body = parsed.value as K8sObject | undefined
    const objName = body?.metadata?.name
    if (!body || !objName) return
    // Clear prior failure state so a stale conflict banner can't mask a new,
    // different error (and can't keep the generic error banner suppressed).
    setSaveError(null)
    setConflict(false)
    try {
      const saved = await apply(objName, body, { namespace: body.metadata?.namespace, force })
      onSaved?.(saved)
      onClose()
    } catch (e) {
      if (e instanceof K8sStatusError && (e.code === 409 || e.reason === 'Conflict')) {
        setConflict(true)
        setSaveError(e.message)
      } else {
        setSaveError(e instanceof Error ? e.message : String(e))
      }
    }
  }

  // Modal tray scope: Esc cancels (guarded when dirty), ⌘S saves.
  useKeyboardScope({
    level: 'tray',
    modal: true,
    enabled: open,
    bindings: [
      { keys: 'escape', run: requestClose, allowInEditable: true },
      {
        keys: 'mod+s',
        run: () => {
          if (!saveDisabled) void save()
        },
        allowInEditable: true,
      },
    ],
  })

  if (!open) return null

  const title = object ? `Edit ${entry.kind}` : `New ${entry.kind}`
  const errorCount = problems.filter((p) => p.severity === 'error').length
  const warnCount = problems.filter((p) => p.severity === 'warning').length

  return (
    <div
      role="presentation"
      onMouseDown={requestClose}
      className="fixed inset-0 z-40 flex justify-end bg-[var(--scrim-tray)]"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(e) => e.stopPropagation()}
        className="flex h-full w-full max-w-[640px] flex-col border-l border-[color:var(--border-strong)] bg-[var(--apx-paper)] shadow-[var(--sh-4)]"
      >
        <header className="flex flex-none items-center justify-between border-b border-[color:var(--border-default)] bg-[var(--apx-white)] px-[var(--sp-5)] py-[var(--sp-4)]">
          <div className="min-w-0">
            <h2 className="font-[family-name:var(--font-display)] text-[length:var(--t-h4)] font-medium tracking-[-0.01em] text-[color:var(--text-primary)]">
              {title}
            </h2>
            {name && (
              <div className="truncate font-mono text-[length:var(--t-overline)] text-[color:var(--text-muted)]">{name}</div>
            )}
          </div>
          <button
            type="button"
            onClick={requestClose}
            aria-label="Close"
            className="flex h-7 w-7 flex-none items-center justify-center rounded-none text-[color:var(--text-muted)] transition-colors hover:bg-[var(--apx-mist)] hover:text-[color:var(--text-primary)]"
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
              <path d="M3 3l8 8M11 3l-8 8" strokeLinecap="round" />
            </svg>
          </button>
        </header>

        <div className="flex min-h-0 flex-1 flex-col gap-[var(--sp-3)] p-[var(--sp-5)]">
          {changedOnServer && (
            <Banner tone="warning" role="status">
              {confirmingReload ? (
                <>
                  <span>Discard your edits and load the server version?</span>
                  <span className="flex flex-none gap-[var(--sp-3)]">
                    <button type="button" onClick={() => setConfirmingReload(false)} className="font-medium underline">
                      Keep editing
                    </button>
                    <button type="button" onClick={reloadFromServer} className="font-medium underline">
                      Reload
                    </button>
                  </span>
                </>
              ) : (
                <>
                  <span>This {entry.kind.toLowerCase()} changed on the server since you opened it.</span>
                  <button type="button" onClick={requestReload} className="font-medium underline">
                    Reload
                  </button>
                </>
              )}
            </Banner>
          )}
          {conflict && (
            <Banner tone="error" role="alert">
              <span>Save was rejected — another writer owns one or more fields.</span>
              <button type="button" onClick={() => void save(true)} className="font-medium underline">
                Overwrite
              </button>
            </Banner>
          )}
          {saveError && !conflict && (
            <Banner tone="error" role="alert">
              <span className="truncate">{saveError}</span>
            </Banner>
          )}

          <Editor value={text} onChange={setText} schema={entry.schema} ariaLabel={`${entry.kind} YAML`} />

          <div className="max-h-[28%] flex-none overflow-auto">
            {problems.length === 0 ? (
              <p className="text-[length:var(--t-overline)] text-[color:var(--apx-leaf)]">No problems found.</p>
            ) : (
              <ul className="flex flex-col gap-[2px]">
                {problems.map((p, i) => (
                  <li
                    key={`${p.path}-${i}`}
                    className={cn(
                      'font-mono text-[length:var(--t-overline)]',
                      p.severity === 'error' ? 'text-[color:var(--apx-coral)]' : 'text-[color:var(--apx-amber)]',
                    )}
                  >
                    {p.path || '(root)'}: {p.message}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        <footer className="flex flex-none items-center justify-between gap-[var(--sp-3)] border-t border-[color:var(--border-default)] bg-[var(--apx-white)] px-[var(--sp-5)] py-[var(--sp-4)]">
          <div className="min-w-0 text-[length:var(--t-overline)] text-[color:var(--text-muted)]">
            {confirmingClose ? (
              <span className="text-[color:var(--apx-coral)]">Discard unsaved changes?</span>
            ) : (
              <>
                {errorCount > 0 && <span className="text-[color:var(--apx-coral)]">{errorCount} error{errorCount === 1 ? '' : 's'} </span>}
                {warnCount > 0 && <span className="text-[color:var(--apx-amber)]">{warnCount} warning{warnCount === 1 ? '' : 's'} </span>}
                {dirty && errorCount === 0 && warnCount === 0 && <span>Unsaved changes</span>}
              </>
            )}
          </div>
          <div className="flex flex-none items-center gap-[var(--sp-2)]">
            {confirmingClose ? (
              <>
                <Button variant="ghost" size="sm" onClick={() => setConfirmingClose(false)}>
                  Keep editing
                </Button>
                <Button variant="secondary" size="sm" onClick={onClose}>
                  Discard
                </Button>
              </>
            ) : (
              <>
                <Button variant="ghost" size="sm" onClick={requestClose}>
                  Cancel
                </Button>
                <Button variant="primary" size="sm" disabled={saveDisabled} onClick={() => void save()}>
                  {isPending ? 'Saving…' : 'Save'}
                </Button>
              </>
            )}
          </div>
        </footer>
      </div>
    </div>
  )
}

function Banner({
  tone,
  role,
  children,
}: {
  tone: 'warning' | 'error'
  role: 'status' | 'alert'
  children: React.ReactNode
}) {
  return (
    <div
      role={role}
      className={cn(
        'flex flex-none items-center justify-between gap-[var(--sp-3)] border px-[var(--sp-3)] py-[var(--sp-2)] text-[length:var(--t-body-sm)]',
        tone === 'error'
          ? 'border-[color:var(--apx-coral)] bg-[var(--apx-coral-tint)] text-[color:var(--apx-ink)]'
          : 'border-[color:var(--apx-amber)] bg-[var(--apx-amber-tint)] text-[color:var(--apx-ink)]',
      )}
    >
      {children}
    </div>
  )
}
