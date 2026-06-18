// The reusable create/edit wizard chrome (APO-782 follow-up), modeled on the
// design's EgressGateway wizard (`.eg-wizard`): a right-side tray with a left
// step rail and a paned body. A bespoke wizard supplies its `steps` (the field
// sections); the shell appends a built-in editable **YAML** step — the optional
// raw input — over the SAME draft object, so the form and the YAML stay in sync
// (form edits regenerate the YAML; YAML edits parse back into the draft). The
// docked footer steps Back/Continue and creates/updates via Server-Side Apply.
//
// This is the kind-agnostic shell: clrk's EgressGateway reuses it with its own
// steps. The write path mirrors the YAML tray — conflict (409 → force) and
// changed-on-server (reload) are both handled.

import { Fragment, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { cn } from '../lib/cn'
import { Button } from '../components/ui/button'
import { useApplyResource } from '../lib/mutations'
import { useK8sObject } from '../lib/hooks'
import { K8sStatusError } from '../lib/gvr-client'
import { useKeyboardScope } from '../keyboard/scope-stack'
import type { K8sObject } from '../lib/k8s-types'
import type { ResourceEntry } from '../registry/types'
import { forEditing, fromYaml, toYaml } from './yaml-doc'
import { hasBlockingProblems, validateObject, type Problem } from './validate'
import { TextAreaEditor, useTrayEditor } from './editor'
import { Banner, TrayCloseButton } from './tray-chrome'

// Rail row selection classes, shared by the top-level step buttons and the nested
// sub-item buttons so the two can't drift.
const RAIL_SELECTED = 'bg-[var(--apx-white)] font-medium text-[color:var(--text-primary)] shadow-[inset_2px_0_0_var(--apx-ink)]'
const RAIL_IDLE = 'text-[color:var(--text-muted)] hover:text-[color:var(--text-primary)]'

/** What a wizard step's renderer receives. */
export interface WizardFormProps<T extends K8sObject = K8sObject> {
  /** The current draft object — the single source of truth for every step. */
  draft: T
  /** Replace the draft (the step builds the next object). Regenerates the YAML. */
  setDraft: (next: T) => void
  /** Structural + schema problems for the current draft (already validated). */
  problems: Problem[]
}

/** One sub-item of a collection step (a single listener, route, …): a row in the
 *  step's overview and a nested entry one level down in the rail. */
export interface WizardSubItem {
  /** Stable id for navigation + React key (the kind decides how to derive it). */
  id: string
  /** Rail row + overview primary line. */
  label: string
  /** Overview secondary line (e.g. `HTTPS:443`). */
  summary?: string
}

/** Turns a step into a master-detail collection: a list overview plus a full-pane
 *  editor per item, with every item surfaced one level down in the rail. The list
 *  chrome (rows, add, remove, empty state) is supplied by the shell — the kind only
 *  derives the items from the draft and renders one item's fields. */
export interface WizardCollection<T extends K8sObject = K8sObject> {
  /** Derive the current items from the draft (order = rail + overview order). */
  items: (draft: T) => WizardSubItem[]
  /** Render the full editor for the item with this id. */
  renderItem: (props: WizardFormProps<T> & { itemId: string }) => ReactNode
  /** Singular noun for the empty state + add affordance (e.g. `listener`). */
  noun: string
  /** Append a new item; returns the next draft and the new item's id to focus. */
  onAdd: (draft: T) => { draft: T; focusId: string }
  /** Remove the item with this id; returns the next draft. */
  onRemove: (draft: T, itemId: string) => T
  /** Rail / overview / item-header glyph; defaults to the entry icon. */
  glyph?: ReactNode
}

/** One step in the wizard rail. A plain step renders its own pane; a collection
 *  step (with `collection`) gets the shell's master-detail list + nested rail. */
export interface WizardStep<T extends K8sObject = K8sObject> {
  id: string
  label: string
  /** The step's pane. Optional for a collection step (defaults to the generated
   *  overview) and for the built-in YAML step. */
  render?: (props: WizardFormProps<T>) => ReactNode
  /** Make this a master-detail collection step. */
  collection?: WizardCollection<T>
}

export interface WizardShellProps<T extends K8sObject = K8sObject> {
  entry: ResourceEntry
  /** The object being edited; absent in create mode. */
  object?: T
  open: boolean
  onClose: () => void
  onSaved?: (obj: K8sObject) => void
  /** Build a fresh draft object (apiVersion/kind/metadata/spec) for create mode. */
  emptyDraft: () => T
  /** The kind-specific form steps. The shell appends a built-in YAML step. */
  steps: WizardStep<T>[]
  /** Header glyph; defaults to the entry's icon. */
  glyph?: ReactNode
  /** Built-in YAML step label, or `null` to omit it. Defaults to `YAML`. */
  yamlStepLabel?: string | null
}

const YAML_STEP_ID = '__yaml'

export function WizardShell<T extends K8sObject = K8sObject>({
  entry,
  object,
  open,
  onClose,
  onSaved,
  emptyDraft,
  steps,
  glyph,
  yamlStepLabel = 'YAML',
}: WizardShellProps<T>) {
  const provided = useTrayEditor()
  const Editor = provided ?? TextAreaEditor

  // Navigation: which top-level step is active, and (for a collection step) which
  // sub-item is open — `null` sits at the step's overview list.
  const [stepId, setStepId] = useState<string>('')
  const [itemId, setItemId] = useState<string | null>(null)
  // Whether this wizard is editing an existing object, captured at baseline time
  // so a transient `object === undefined` (the object is deleted on the server
  // mid-edit) doesn't flip the header/footer to "New …" while the buffer survives.
  const [editMode, setEditMode] = useState(!!object)
  const [draft, setDraftState] = useState<T>(() => emptyDraft())
  const [text, setText] = useState('')
  const [baseline, setBaseline] = useState('')
  const [conflict, setConflict] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [confirmingClose, setConfirmingClose] = useState(false)
  const [confirmingReload, setConfirmingReload] = useState(false)
  const baselinedFor = useRef<{ uid: string | undefined } | null>(null)

  const { apply, isPending } = useApplyResource(entry.gvr)

  const name = object?.metadata.name ?? ''
  const live = useK8sObject(entry.gvr, name, { enabled: open && name !== '' }).data

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
    const value = (object ? forEditing(object) : emptyDraft()) as T
    const yaml = toYaml(value)
    setDraftState(value)
    setText(yaml)
    setBaseline(yaml)
    setStepId(steps[0]?.id ?? YAML_STEP_ID)
    setItemId(null)
    setEditMode(!!object)
    setConflict(false)
    setSaveError(null)
    setConfirmingClose(false)
    setConfirmingReload(false)
    baselinedFor.current = { uid }
    // emptyDraft/entry are stable for a given open; baseline tracks open + identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
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

  const setDraft = (next: T) => {
    setDraftState(next)
    setText(toYaml(next))
  }
  const onYamlChange = (next: string) => {
    setText(next)
    const p = fromYaml(next)
    // Only adopt a parsed value that is an object *mapping* — a YAML list or
    // scalar (typeof [] === 'object') would otherwise be stored as the draft and
    // crash a form step that reads `draft.metadata.…`. While the buffer is a
    // non-mapping (or unparseable) the form keeps the last valid draft and the
    // problems strip shows the error.
    if (!p.error && p.value && typeof p.value === 'object' && !Array.isArray(p.value)) {
      setDraftState(p.value as T)
    }
  }

  // Rail / master-detail navigation. Selecting a step lands on its overview;
  // selecting (or adding) a sub-item drills into the full-pane editor.
  const goStep = (id: string) => {
    setStepId(id)
    setItemId(null)
  }
  const openItem = (sId: string, id: string) => {
    setStepId(sId)
    setItemId(id)
  }
  const addItem = (col: WizardCollection<T>, sId: string) => {
    const { draft: next, focusId } = col.onAdd(draft)
    setDraft(next)
    openItem(sId, focusId)
  }
  const removeItem = (col: WizardCollection<T>, sId: string, id: string) => {
    setDraft(col.onRemove(draft, id))
    goStep(sId)
  }

  const liveProjection = useMemo(() => (live ? toYaml(forEditing(live)) : undefined), [live])
  const changedOnServer = open && !!object && liveProjection !== undefined && liveProjection !== baseline

  function reloadFromServer() {
    if (!live) return
    const value = forEditing(live) as T
    setDraftState(value)
    const yaml = toYaml(value)
    setText(yaml)
    setBaseline(yaml)
    setConflict(false)
    setSaveError(null)
    setConfirmingReload(false)
  }
  function requestReload() {
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

  const editing = editMode
  const draftName = (draft.metadata?.name ?? '').trim()
  const saveDisabled = isPending || blocking || draftName === '' || (editing && !dirty)

  // Escape steps out one level: from a sub-item editor back to its overview, and
  // only from the overview/top level does it close the wizard (with the dirty guard).
  const onEscape = () => {
    if (itemId !== null) {
      setItemId(null)
      return
    }
    requestClose()
  }

  useKeyboardScope({
    level: 'tray',
    modal: true,
    enabled: open,
    bindings: [
      { keys: 'escape', run: onEscape, allowInEditable: true },
      {
        keys: 'mod+s',
        run: () => {
          if (!saveDisabled) void save()
        },
        allowInEditable: true,
      },
    ],
  })

  // Build the full rail: the kind's steps + the built-in YAML step.
  const allSteps = useMemo<WizardStep<T>[]>(() => {
    if (yamlStepLabel === null) return steps
    return [...steps, { id: YAML_STEP_ID, label: yamlStepLabel }]
  }, [steps, yamlStepLabel])

  if (!open) return null

  const rawIdx = allSteps.findIndex((s) => s.id === stepId)
  const idx = rawIdx >= 0 ? rawIdx : 0
  const current = allSteps[idx]
  const isYamlStep = current?.id === YAML_STEP_ID
  const isLast = idx === allSteps.length - 1
  const apiVersion = entry.gvr.group ? `${entry.gvr.group}/${entry.gvr.version}` : entry.gvr.version
  const draftNs = draft.metadata?.namespace

  // The active step's pane body (overview list, full-item editor, or plain step).
  // Lives here so it can close over the draft + navigation handlers; the YAML step
  // is rendered separately (full-bleed, framed) and never reaches this.
  const renderPane = (): ReactNode => {
    if (!current) return null
    const col = current.collection
    if (col) {
      const subItems = col.items(draft)
      const activeItem = itemId !== null ? subItems.find((it) => it.id === itemId) : undefined
      // Drilled into one item → the full-pane editor.
      if (activeItem) {
        return (
          <div className="flex flex-col gap-[18px]">
            <button
              type="button"
              onClick={() => setItemId(null)}
              className="inline-flex items-center gap-[6px] self-start font-mono text-[length:var(--t-micro)] uppercase tracking-[0.06em] text-[color:var(--text-muted)] transition-colors hover:text-[color:var(--apx-ink)]"
            >
              <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
                <path d="M8.5 2.5L4 7l4.5 4.5" />
              </svg>
              {current.label}
            </button>
            <div className="flex items-start gap-[12px] border-b border-[color:var(--border-default)] pb-[16px]">
              <span className="flex h-[34px] w-[34px] flex-none items-center justify-center border border-[color:var(--apx-ink)] text-[color:var(--apx-ink)]">
                {col.glyph ?? entry.icon}
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-[length:var(--t-overline)] font-medium uppercase tracking-[0.14em] text-[color:var(--text-muted)]">
                  Edit · {col.noun}
                </div>
                <div className="mt-[3px] truncate font-mono text-[length:var(--t-h5)] font-medium text-[color:var(--text-primary)]">
                  {activeItem.label || `Untitled ${col.noun}`}
                </div>
              </div>
              <Button variant="danger" size="sm" onClick={() => removeItem(col, current.id, activeItem.id)}>
                Remove
              </Button>
            </div>
            <div className="flex flex-col gap-[20px]">{col.renderItem({ draft, setDraft, problems, itemId: activeItem.id })}</div>
          </div>
        )
      }
      // Overview: a custom renderer wins; otherwise the generated list.
      if (current.render) return <div className="flex flex-col gap-[20px]">{current.render({ draft, setDraft, problems })}</div>
      return (
        <div className="flex flex-col gap-[8px]">
          {subItems.length === 0 && (
            <div className="border border-dashed border-[color:var(--border-default)] px-[16px] py-[22px] text-center font-mono text-[length:var(--t-caption)] text-[color:var(--text-disabled)]">
              No {col.noun}s yet — add one to get started.
            </div>
          )}
          {subItems.map((it) => (
            <div key={it.id} className="group flex items-center gap-[11px] border border-[color:var(--border-default)] bg-[var(--apx-white)] px-[12px] py-[11px]">
              <span className="flex h-7 w-7 flex-none items-center justify-center border border-[color:var(--border-default)] text-[color:var(--text-muted)]">
                {col.glyph ?? entry.icon}
              </span>
              <button type="button" onClick={() => openItem(current.id, it.id)} className="min-w-0 flex-1 text-left">
                <div className="truncate font-mono text-[length:var(--t-body-sm)] text-[color:var(--text-primary)]">{it.label || `Untitled ${col.noun}`}</div>
                {it.summary && <div className="mt-[2px] truncate font-mono text-[length:var(--t-micro)] text-[color:var(--text-muted)]">{it.summary}</div>}
              </button>
              <button
                type="button"
                onClick={() => removeItem(col, current.id, it.id)}
                aria-label={`Remove ${it.label || col.noun}`}
                className="flex-none text-[color:var(--text-muted)] transition-colors hover:text-[color:var(--apx-coral)]"
              >
                <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
                  <path d="M2 2l10 10M12 2L2 12" />
                </svg>
              </button>
            </div>
          ))}
          <button
            type="button"
            onClick={() => addItem(col, current.id)}
            className="flex w-full items-center gap-[9px] border border-dashed border-[color:var(--apx-stone)] bg-transparent px-[12px] py-[11px] font-mono text-[length:var(--t-caption)] text-[color:var(--text-muted)] transition-colors hover:border-[color:var(--apx-ink)] hover:bg-[var(--apx-bone)] hover:text-[color:var(--apx-ink)]"
          >
            <span className="flex h-4 w-4 flex-none items-center justify-center border border-current">
              <PlusGlyph />
            </span>
            Add {col.noun}
          </button>
        </div>
      )
    }
    return <div className="flex flex-col gap-[20px]">{current.render?.({ draft, setDraft, problems })}</div>
  }

  return (
    <div role="presentation" onMouseDown={requestClose} className="fixed inset-0 z-40 flex justify-end bg-[var(--scrim-tray)]">
      <div
        role="dialog"
        aria-modal="true"
        aria-label={editing ? `Edit ${entry.kind}` : `New ${entry.kind}`}
        onMouseDown={(e) => e.stopPropagation()}
        className="flex h-full w-full max-w-[860px] flex-col border-l border-[color:var(--apx-ink)] bg-[var(--apx-white)] shadow-[var(--sh-4)]"
      >
        {/* Header: glyph + eyebrow / title / sub + close. */}
        <header className="flex flex-none items-start gap-[var(--sp-3)] border-b border-[color:var(--border-default)] bg-[var(--apx-mist)] px-[20px] py-[16px]">
          <span className="flex h-[34px] w-[34px] flex-none items-center justify-center border border-[color:var(--apx-ink)] text-[color:var(--apx-ink)]">
            {glyph ?? entry.icon}
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-[length:var(--t-overline)] font-medium uppercase tracking-[0.14em] text-[color:var(--text-muted)]">
              {editing ? 'Edit' : 'New'} · {entry.kind}
            </div>
            <div className="mt-[3px] truncate font-mono text-[length:var(--t-h5)] font-medium text-[color:var(--text-primary)]">
              {draftName || `Untitled ${entry.kind.toLowerCase()}`}
            </div>
            <div className="mt-[3px] truncate font-mono text-[length:var(--t-micro)] text-[color:var(--text-muted)]">
              {apiVersion}
              {draftNs ? ` · ${draftNs}` : ''}
            </div>
          </div>
          <TrayCloseButton onClick={requestClose} />
        </header>

        {/* Body: step rail + pane. */}
        <div className="grid min-h-0 flex-1 grid-cols-1 sm:grid-cols-[184px_1fr]">
          <nav className="flex flex-row gap-[2px] overflow-x-auto border-b border-[color:var(--border-default)] bg-[var(--apx-paper)] px-[10px] py-[12px] sm:flex-col sm:overflow-x-visible sm:border-b-0 sm:border-r">
            {allSteps.map((s, i) => {
              const col = s.collection
              const sectionActive = s.id === stepId
              const onOverview = sectionActive && itemId === null
              const subItems = col ? col.items(draft) : []
              return (
                <Fragment key={s.id}>
                  <button
                    type="button"
                    onClick={() => goStep(s.id)}
                    aria-current={onOverview ? 'step' : undefined}
                    className={cn(
                      'flex flex-none items-center gap-[9px] whitespace-nowrap px-[11px] py-[9px] text-left text-[length:var(--t-body-sm)] transition-colors sm:w-full',
                      onOverview ? RAIL_SELECTED : sectionActive ? 'font-medium text-[color:var(--text-primary)]' : RAIL_IDLE,
                    )}
                  >
                    <span
                      className={cn(
                        'flex h-5 w-5 flex-none items-center justify-center border font-mono text-[length:var(--t-micro)]',
                        i < idx
                          ? 'border-[color:var(--apx-ink)] bg-[var(--apx-ink)] text-[color:var(--apx-bone)]'
                          : i === idx
                            ? 'border-[color:var(--apx-ink)] text-[color:var(--apx-ink)]'
                            : 'border-[color:var(--border-default)] text-[color:var(--text-muted)]',
                      )}
                    >
                      {i < idx ? '✓' : i + 1}
                    </span>
                    <span className="min-w-0 flex-1 truncate">{s.label}</span>
                    {col && (
                      <span className="flex-none font-mono text-[length:var(--t-overline)] text-[color:var(--text-disabled)]">{subItems.length}</span>
                    )}
                  </button>
                  {/* Sub-items nested one level down, expanded while their section is active. */}
                  {col && sectionActive && (
                    <div className="flex flex-col gap-[1px] sm:ml-[19px] sm:border-l sm:border-[color:var(--border-subtle)] sm:pl-[8px]">
                      {subItems.map((it) => (
                        <button
                          key={it.id}
                          type="button"
                          onClick={() => openItem(s.id, it.id)}
                          aria-current={itemId === it.id ? 'step' : undefined}
                          className={cn(
                            'flex items-center gap-[8px] whitespace-nowrap px-[8px] py-[6px] text-left transition-colors sm:w-full',
                            itemId === it.id ? RAIL_SELECTED : RAIL_IDLE,
                          )}
                        >
                          <span className="flex h-[15px] w-[15px] flex-none items-center justify-center text-[color:var(--text-muted)]">{col.glyph ?? entry.icon}</span>
                          <span className="min-w-0 flex-1 truncate font-mono text-[length:var(--t-caption)]">{it.label || col.noun}</span>
                        </button>
                      ))}
                      <button
                        type="button"
                        onClick={() => addItem(col, s.id)}
                        className="flex items-center gap-[8px] whitespace-nowrap px-[8px] py-[6px] text-left font-mono text-[length:var(--t-caption)] text-[color:var(--text-disabled)] transition-colors hover:text-[color:var(--apx-ink)] sm:w-full"
                      >
                        <span className="flex h-[15px] w-[15px] flex-none items-center justify-center border border-current">
                          <PlusGlyph />
                        </span>
                        Add {col.noun}
                      </button>
                    </div>
                  )}
                </Fragment>
              )
            })}
          </nav>

          <div className="flex min-h-0 flex-col">
            {(changedOnServer || conflict || saveError) && (
              <div className="flex flex-none flex-col gap-[var(--sp-2)] px-[22px] pt-[18px]">
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
              </div>
            )}

            {isYamlStep ? (
              // Full-bleed editor — the editor's own gutter rule is the only internal
              // line, so there's no box-in-box (the form steps below keep their padding).
              <div className="flex min-h-0 flex-1 flex-col">
                <Editor value={text} onChange={onYamlChange} schema={entry.schema} ariaLabel={`${entry.kind} YAML`} />
              </div>
            ) : (
              <div className="min-h-0 flex-1 overflow-y-auto p-[22px]">{renderPane()}</div>
            )}

            {problems.length > 0 && (
              <div className="max-h-[24%] flex-none overflow-auto border-t border-[color:var(--border-subtle)] px-[22px] py-[12px]">
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
              </div>
            )}
          </div>
        </div>

        {/* Footer: stepped nav + create/save. */}
        <footer className="flex flex-none items-center gap-[var(--sp-3)] border-t border-[color:var(--border-default)] bg-[var(--apx-mist)] px-[20px] py-[13px]">
          {confirmingClose ? (
            <>
              <span className="flex-1 text-[length:var(--t-body-sm)] text-[color:var(--apx-coral)]">Discard unsaved changes?</span>
              <Button variant="ghost" size="sm" onClick={() => setConfirmingClose(false)}>
                Keep editing
              </Button>
              <Button variant="secondary" size="sm" onClick={onClose}>
                Discard
              </Button>
            </>
          ) : itemId !== null ? (
            // Editing a sub-item: stay focused on it; "Done" returns to the overview.
            // (Edits are live on the draft, so there is nothing to save here.)
            <>
              <Button variant="ghost" size="sm" onClick={requestClose}>
                Cancel
              </Button>
              <div className="flex-1" />
              <Button variant="secondary" size="sm" onClick={() => setItemId(null)}>
                Done
              </Button>
            </>
          ) : (
            <>
              <Button variant="ghost" size="sm" onClick={requestClose}>
                Cancel
              </Button>
              <div className="flex-1" />
              {idx > 0 && (
                <Button variant="ghost" size="sm" onClick={() => goStep(allSteps[idx - 1]!.id)}>
                  Back
                </Button>
              )}
              {isLast ? (
                <Button variant="primary" size="sm" disabled={saveDisabled} onClick={() => void save()}>
                  {isPending ? 'Saving…' : editing ? 'Save changes' : `Create ${entry.kind.toLowerCase()}`}
                </Button>
              ) : (
                <Button variant="primary" size="sm" onClick={() => goStep(allSteps[idx + 1]!.id)}>
                  Continue
                </Button>
              )}
            </>
          )}
        </footer>
      </div>
    </div>
  )
}

/** A centered stroke "+" — optically true inside the add-affordance box, where a
 *  text "+" sits off the box's vertical centre. */
function PlusGlyph(): ReactNode {
  return (
    <svg width="9" height="9" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <path d="M5 1.5v7M1.5 5h7" strokeLinecap="round" />
    </svg>
  )
}

