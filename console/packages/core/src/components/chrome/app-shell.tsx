// The app shell (APO-775): a fixed 240px rail and a work area that stacks the
// topbar over a scrolling page. Pure layout — the sidebar, topbar, and page
// content are passed in, so the same shell serves apoxy and clrk.
//
// The shell fills its parent (`h-full`) and the work area scrolls internally
// rather than scrolling the document. That keeps the rail and topbar in place
// without `position: sticky`/`100vh`, so the shell composes correctly under a
// zoom-scaled root (where viewport units and document scroll misbehave).

import type { ReactNode } from 'react'

export interface AppShellProps {
  sidebar: ReactNode
  topbar?: ReactNode
  children: ReactNode
}

export function AppShell({ sidebar, topbar, children }: AppShellProps) {
  // The rail self-sizes (it animates between expanded/collapsed widths), so the
  // first column is `auto` rather than a fixed 240px. The single row is `1fr`
  // so both the rail and the work area fill the shell's height.
  return (
    <div className="grid h-full grid-cols-[auto_1fr] grid-rows-[1fr] overflow-hidden">
      {sidebar}
      <div className="flex min-h-0 min-w-0 flex-col bg-[var(--apx-paper)]">
        {topbar}
        <main className="min-h-0 min-w-0 flex-1 overflow-y-auto px-[var(--sp-8)] pb-[var(--sp-20)] pt-[28px]">
          {children}
        </main>
      </div>
    </div>
  )
}
