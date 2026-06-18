// Shared chrome for the object trays (the manifest viewer, the editable YAML tray,
// and the wizard): the write-path Banner and the header close button. These were
// hand-rolled identically in each tray; keeping one copy stops them drifting.

import type { ReactNode } from 'react'
import { cn } from '../lib/cn'

/** Inline write-path banner — changed-on-server (warning) / conflict + save error
 *  (error). Lays out a message and an optional trailing action. */
export function Banner({ tone, role, children }: { tone: 'warning' | 'error'; role: 'status' | 'alert'; children: ReactNode }) {
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

/** The bordered header close button (Esc also closes). */
export function TrayCloseButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label="Close"
      title="Close (Esc)"
      className="flex h-7 w-7 flex-none items-center justify-center rounded-none border border-[color:var(--border-default)] bg-[var(--apx-white)] text-[color:var(--text-secondary)] transition-colors hover:border-[color:var(--apx-ink)] hover:text-[color:var(--text-primary)]"
    >
      <svg width="12" height="12" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
        <path d="M2 2l10 10M12 2L2 12" />
      </svg>
    </button>
  )
}
