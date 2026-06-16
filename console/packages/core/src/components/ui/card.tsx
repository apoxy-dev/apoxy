import type { HTMLAttributes } from 'react'
import { cn } from '../../lib/cn'

/** Warm-white surface, hairline border, square corners, subtle shadow. */
export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'rounded-none border border-[color:var(--border-default)] bg-[var(--apx-white)] p-[var(--sp-6)] shadow-[var(--sh-1)]',
        className,
      )}
      {...props}
    />
  )
}

export function CardTitle({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3
      className={cn(
        'text-[length:var(--t-h4)] font-medium text-[color:var(--text-primary)]',
        className,
      )}
      {...props}
    />
  )
}

export function CardMeta({ className, ...props }: HTMLAttributes<HTMLParagraphElement>) {
  return (
    <p
      className={cn('text-[length:var(--t-caption)] text-[color:var(--text-muted)]', className)}
      {...props}
    />
  )
}
