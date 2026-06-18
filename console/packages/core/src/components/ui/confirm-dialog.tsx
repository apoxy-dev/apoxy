// A small centered confirmation modal — the destructive-action gate (e.g.
// "Delete this Gateway?"). Square card on a tray scrim, a danger or default
// confirm button, and an optional error line for a failed action. Registers a
// modal `dialog` scope so Escape cancels and list-nav keys stay shadowed; the
// Cancel button is focused on open so a destructive confirm is never one stray
// Enter away.

import { useEffect, useRef, useState, type ReactNode } from 'react'
import { cn } from '../../lib/cn'
import { Button } from './button'
import { useKeyboardScope } from '../../keyboard/scope-stack'

export interface ConfirmDialogProps {
  open: boolean
  title: string
  body?: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  tone?: 'danger' | 'default'
  /** Disable the buttons and show a busy label while the action runs. */
  pending?: boolean
  /** Shown in the footer when the action failed. */
  error?: string | null
  onConfirm: () => void
  onCancel: () => void
}

const DANGER =
  'inline-flex h-8 items-center justify-center whitespace-nowrap rounded-none px-3 text-[length:var(--t-body-sm)] ' +
  'font-medium text-[color:var(--apx-white)] transition-[filter,background-color] bg-[var(--apx-coral)] ' +
  'hover:brightness-95 focus-visible:outline-none focus-visible:shadow-[var(--sh-focus)] disabled:pointer-events-none disabled:opacity-50'

export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  tone = 'danger',
  pending = false,
  error,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const cancelRef = useRef<HTMLButtonElement>(null)
  // Latches synchronously on the first confirm so a rapid second click/Enter
  // can't fire the destructive action twice before `pending` re-renders the
  // button to disabled. Cleared whenever the dialog opens/closes.
  const [busy, setBusy] = useState(false)
  const working = busy || pending

  useKeyboardScope({
    level: 'dialog',
    modal: true,
    enabled: open,
    bindings: [{ keys: 'escape', run: onCancel, allowInEditable: true }],
  })

  // Focus Cancel on open so the safe choice is the keyboard default; reset the
  // one-shot guard on every open/close transition.
  useEffect(() => {
    setBusy(false)
    if (open) cancelRef.current?.focus()
  }, [open])

  if (!open) return null

  const confirm = () => {
    if (working) return
    setBusy(true)
    onConfirm()
  }

  return (
    <div
      role="presentation"
      onMouseDown={onCancel}
      className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--scrim-tray)] p-[var(--sp-6)]"
    >
      <div
        role="alertdialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(e) => e.stopPropagation()}
        className="flex w-full max-w-[440px] flex-col border border-[color:var(--border-strong)] bg-[var(--apx-white)] shadow-[var(--sh-4)]"
      >
        <div className="flex flex-col gap-[var(--sp-2)] p-[var(--sp-6)]">
          <h2 className="font-[family-name:var(--font-display)] text-[length:var(--t-h4)] font-medium tracking-[-0.01em] text-[color:var(--text-primary)]">
            {title}
          </h2>
          {body && <div className="text-[length:var(--t-body-sm)] leading-[var(--lh-snug)] text-[color:var(--text-secondary)]">{body}</div>}
        </div>
        <footer className="flex items-center justify-between gap-[var(--sp-3)] border-t border-[color:var(--border-default)] bg-[var(--apx-white)] px-[var(--sp-6)] py-[var(--sp-4)]">
          <div className="min-w-0 truncate text-[length:var(--t-overline)] text-[color:var(--apx-coral)]">{error}</div>
          <div className="flex flex-none items-center gap-[var(--sp-2)]">
            <Button ref={cancelRef} variant="ghost" size="sm" disabled={pending} onClick={onCancel}>
              {cancelLabel}
            </Button>
            {tone === 'danger' ? (
              <button type="button" disabled={working} onClick={confirm} className={cn(DANGER)}>
                {working ? 'Working…' : confirmLabel}
              </button>
            ) : (
              <Button variant="primary" size="sm" disabled={working} onClick={confirm}>
                {working ? 'Working…' : confirmLabel}
              </Button>
            )}
          </div>
        </footer>
      </div>
    </div>
  )
}
