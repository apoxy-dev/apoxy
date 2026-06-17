import type { HTMLAttributes } from 'react'
import { cn } from '../../lib/cn'

export type BadgeVariant = 'success' | 'warning' | 'danger' | 'info' | 'neutral'

// Square status pills from the mockup: tinted fill, matching hairline border, a
// small square status dot. The darker text tints (#2F5A2D / #74541A / #8A3A28)
// are the mockup's own per-status label colors — inlined, as they have no token.
const styles: Record<BadgeVariant, { wrap: string; dot: string }> = {
  success: { wrap: 'bg-[var(--apx-leaf-tint)] border-[color:var(--apx-leaf)] text-[#2F5A2D]', dot: 'bg-[var(--apx-leaf)]' },
  warning: { wrap: 'bg-[var(--apx-amber-tint)] border-[color:var(--apx-amber)] text-[#74541A]', dot: 'bg-[var(--apx-amber)]' },
  danger: { wrap: 'bg-[var(--apx-coral-tint)] border-[color:var(--apx-coral)] text-[#8A3A28]', dot: 'bg-[var(--apx-coral)]' },
  info: { wrap: 'bg-[var(--apx-blue-tint)] border-[color:var(--apx-blue)] text-[color:var(--apx-blue-deep)]', dot: 'bg-[var(--apx-blue)]' },
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
