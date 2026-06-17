// The page header shared by the generic list and detail views: a display-face
// title, an optional subtitle, and right-aligned actions. Matches the mockup's
// 36px TWK Everett heading with tight tracking.

import type { ReactNode } from 'react'

export interface PageHeaderProps {
  title: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
}

export function PageHeader({ title, subtitle, actions }: PageHeaderProps) {
  return (
    <div className="mb-[28px] flex items-end justify-between gap-[var(--sp-6)]">
      <div className="min-w-0">
        <h1 className="font-[family-name:var(--font-display)] text-[36px] font-medium leading-[var(--lh-tight)] tracking-[-0.015em] text-[color:var(--text-primary)]">
          {title}
        </h1>
        {subtitle && (
          <div className="mt-[var(--sp-1)] text-[length:var(--t-body-sm)] text-[color:var(--text-muted)]">
            {subtitle}
          </div>
        )}
      </div>
      {actions && <div className="flex flex-none items-center gap-[var(--sp-2)]">{actions}</div>}
    </div>
  )
}
