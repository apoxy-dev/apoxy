// The app shell (APO-775): a fixed 240px rail and a work area that stacks the
// topbar over a scrolling page. Pure layout — the sidebar, topbar, and page
// content are passed in, so the same shell serves apoxy and clrk.

import type { ReactNode } from 'react'

export interface AppShellProps {
  sidebar: ReactNode
  topbar?: ReactNode
  children: ReactNode
}

export function AppShell({ sidebar, topbar, children }: AppShellProps) {
  // The rail self-sizes (it animates between expanded/collapsed widths), so the
  // first column is `auto` rather than a fixed 240px.
  return (
    <div className="grid min-h-screen grid-cols-[auto_1fr]">
      {sidebar}
      <div className="flex min-w-0 flex-col bg-[var(--apx-paper)]">
        {topbar}
        <main className="min-w-0 flex-1 px-[var(--sp-8)] pb-[var(--sp-20)] pt-[28px]">{children}</main>
      </div>
    </div>
  )
}
