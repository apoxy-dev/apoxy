// The fixed top bar (APO-775): breadcrumbs on the left, contextual actions
// (command palette, YAML button, etc.) on the right. White surface, hairline
// underline — the page scrolls beneath it.

import type { ReactNode } from 'react'

export interface TopbarProps {
  breadcrumbs?: ReactNode
  actions?: ReactNode
}

export function Topbar({ breadcrumbs, actions }: TopbarProps) {
  return (
    <header className="sticky top-0 z-10 flex items-center justify-between border-b border-[color:var(--border-default)] bg-[var(--apx-white)] px-[var(--sp-8)] py-[13px]">
      <div className="min-w-0">{breadcrumbs}</div>
      {actions && <div className="flex flex-none items-center gap-[var(--sp-2)]">{actions}</div>}
    </header>
  )
}
