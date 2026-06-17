// Small presentational helpers shared by the generic list and detail views.

import type { ReactNode } from 'react'
import { cn } from '../lib/cn'

/** White, hairline-bordered, square surface — the mockup's `.panel`. */
export function Panel({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <div
      className={cn(
        'rounded-none border border-[color:var(--border-default)] bg-[var(--apx-white)]',
        className,
      )}
    >
      {children}
    </div>
  )
}

/** Centered loading / empty / error message inside a panel. */
export function StateMessage({
  tone = 'muted',
  children,
}: {
  tone?: 'muted' | 'error'
  children: ReactNode
}) {
  return (
    <div
      className={cn(
        'px-[var(--sp-6)] py-[var(--sp-10)] text-center text-[length:var(--t-body-sm)]',
        tone === 'error' ? 'text-[color:var(--apx-coral)]' : 'text-[color:var(--text-muted)]',
      )}
    >
      {children}
    </div>
  )
}
