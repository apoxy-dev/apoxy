import type { HTMLAttributes } from 'react'
import { cn } from '../../lib/cn'

export type BadgeVariant = 'success' | 'warning' | 'danger' | 'info' | 'neutral'

// Square status pills from the mockup: tinted fill, matching hairline border, a
// small square status dot. The four status label colors come from --badge-*-text
// tokens (darker than the accent for contrast on the tint); neutral uses the
// shared --text-secondary. All are tokenized, not inlined, so every variant
// flips in dark mode along with its fill.
const styles: Record<BadgeVariant, { wrap: string; dot: string }> = {
  success: { wrap: 'bg-[var(--apx-leaf-tint)] border-[color:var(--apx-leaf)] text-[color:var(--badge-success-text)]', dot: 'bg-[var(--apx-leaf)]' },
  warning: { wrap: 'bg-[var(--apx-amber-tint)] border-[color:var(--apx-amber)] text-[color:var(--badge-warning-text)]', dot: 'bg-[var(--apx-amber)]' },
  danger: { wrap: 'bg-[var(--apx-coral-tint)] border-[color:var(--apx-coral)] text-[color:var(--badge-danger-text)]', dot: 'bg-[var(--apx-coral)]' },
  info: { wrap: 'bg-[var(--apx-blue-tint)] border-[color:var(--apx-blue)] text-[color:var(--badge-info-text)]', dot: 'bg-[var(--apx-blue)]' },
  neutral: { wrap: 'bg-[var(--apx-mist)] border-[color:var(--border-default)] text-[color:var(--text-secondary)]', dot: 'bg-[var(--apx-graphite)]' },
}

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant
  /** Show the leading status dot. Defaults to true. */
  dot?: boolean
}

export function Badge({ variant = 'neutral', dot = true, className, children, ...props }: BadgeProps) {
  const s = styles[variant]
  return (
    <span
      className={cn(
        'inline-flex items-center gap-[6px] rounded-none border px-[9px] py-[2px] text-[length:var(--t-overline)] font-medium leading-[1.5]',
        s.wrap,
        className,
      )}
      {...props}
    >
      {dot && <span className={cn('h-[6px] w-[6px] flex-none rounded-none', s.dot)} aria-hidden="true" />}
      {children}
    </span>
  )
}
