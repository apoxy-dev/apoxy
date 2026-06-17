// The dark side rail (APO-775), generated from the registry sidebar model
// (APO-774). Built to the CLRK dashboard chrome: 240px expanded, 68px collapsed
// (icon-only with tooltips), a collapse toggle in the brand row, group labels
// that become hairline dividers when collapsed. Brand / org-switcher / me slots
// are passed in (the app makes them collapse-aware) so the rail is app-agnostic.
//
// Colors come from the dedicated `--rail-*` tokens (see tokens.css): the rail is
// a dark chrome strip in BOTH light and dark themes, so it can't reuse
// --apx-ink/--apx-bone (which invert in dark mode). The tokens carry the
// design's verbatim rail tints (hairline, hover) too.

import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'
import { useLink } from './link-context'
import type { SidebarModel } from '../../registry/nav'

export interface SidebarProps {
  model: SidebarModel
  /** Slug (`/proxies`) of the active item, for highlight + aria-current. */
  activePath?: string
  /** Render the rail in its 68px icon-only state. */
  collapsed?: boolean
  /** Toggle expand/collapse; the toggle button only renders when provided. */
  onToggleCollapsed?: () => void
  /** Icon for the collapse toggle (e.g. a Carbon side-panel icon). */
  toggleIcon?: ReactNode
  brand?: ReactNode
  /** Slot above the nav (e.g. an org/project switcher). */
  header?: ReactNode
  /** Slot pinned to the bottom (e.g. the signed-in user). */
  footer?: ReactNode
}

const DefaultToggleGlyph = (
  <svg viewBox="0 0 16 16" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
    <rect x="2" y="3" width="12" height="10" rx="1" />
    <path d="M6.5 3v10" />
  </svg>
)

export function Sidebar({
  model,
  activePath,
  collapsed = false,
  onToggleCollapsed,
  toggleIcon,
  brand,
  header,
  footer,
}: SidebarProps) {
  const Link = useLink()
  return (
    <aside
      className={cn(
        'flex h-full flex-col gap-[18px] bg-[var(--rail-bg)] py-[var(--sp-6)] text-[color:var(--rail-text)] transition-[width,padding] duration-200',
        collapsed ? 'w-[68px] px-[var(--sp-2)]' : 'w-[240px] px-[var(--sp-4)]',
      )}
    >
      <div
        className={cn(
          'flex items-baseline border-b border-[color:var(--rail-hairline)] pb-[var(--sp-4)] pt-[4px]',
          collapsed ? 'justify-center gap-0 px-0' : 'gap-[6px] px-[var(--sp-2)]',
        )}
      >
        {!collapsed && brand}
        {onToggleCollapsed && (
          <button
            type="button"
            onClick={onToggleCollapsed}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-expanded={!collapsed}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className={cn(
              'inline-flex h-7 w-7 flex-none items-center justify-center self-center rounded-none bg-transparent text-[color:var(--rail-text-muted)] transition-colors hover:bg-[color:var(--rail-hover)] hover:text-[color:var(--rail-text)]',
              !collapsed && 'ml-auto',
            )}
          >
            {toggleIcon ?? DefaultToggleGlyph}
          </button>
        )}
      </div>

      {header}

      <nav aria-label="Primary" className="flex min-h-0 flex-1 flex-col gap-[1px] overflow-y-auto">
        {model.groups.map((group, groupIndex) => (
          <div key={group.name} className="flex flex-col gap-[1px]">
            {collapsed ? (
              // A hairline between groups when icon-only — but not above the first.
              groupIndex > 0 ? (
                <div aria-hidden="true" className="mx-[8px] my-[7px] border-t border-[color:var(--rail-hairline)]" />
              ) : null
            ) : (
              <div className="px-[10px] pb-[6px] pt-[14px] text-[length:var(--t-micro)] uppercase tracking-[0.16em] text-[color:var(--rail-text-dim)]">
                {group.name}
              </div>
            )}
            {group.items.map((item) => {
              const active = activePath === item.to
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  aria-current={active ? 'page' : undefined}
                  aria-label={collapsed ? item.label : undefined}
                  title={collapsed ? item.label : undefined}
                  className={cn(
                    'flex items-center gap-[10px] rounded-none py-[8px] text-[length:var(--t-body-sm)] font-medium no-underline transition-colors',
                    'hover:bg-[color:var(--rail-hover)] hover:text-[color:var(--rail-text)]',
                    collapsed ? 'justify-center px-0 py-[9px]' : 'px-[10px]',
                    active ? 'bg-[color:var(--rail-hover)] text-[color:var(--rail-text)]' : 'text-[color:var(--rail-text-muted)]',
                  )}
                >
                  {item.icon && (
                    <span aria-hidden="true" className="flex h-4 w-4 flex-none items-center justify-center opacity-85">
                      {item.icon}
                    </span>
                  )}
                  {!collapsed && <span className="min-w-0 truncate">{item.label}</span>}
                </Link>
              )
            })}
          </div>
        ))}
      </nav>

      {footer && <div className="mt-auto border-t border-[color:var(--rail-hairline)] pt-[14px]">{footer}</div>}
    </aside>
  )
}
