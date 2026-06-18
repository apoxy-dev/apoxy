// A small dropdown menu (the design's `.yaml-menu`): a secondary-styled trigger
// with a caret, and a popdown list of two-line items (label + mono sub, optional
// leading icon and trailing kbd). Closes on outside-click or Escape. Generic and
// token-driven so any surface can reuse it — the per-object YAML menu is just one
// consumer. Not a modal: it's a lightweight popover, so it manages its own
// outside-click rather than joining the keyboard scope stack.

import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { cn } from '../../lib/cn'

export interface DropdownItem {
  /** Stable React key. */
  id: string
  /** Primary label. */
  label: string
  /** Secondary mono caption under the label. */
  sub?: string
  /** Leading glyph. */
  icon?: ReactNode
  /** Trailing keyboard hint (rendered as a <kbd>). */
  kbd?: string
  /** Invoked on click; the menu closes first. */
  onSelect: () => void
  /** Draw a hairline separator above this item. */
  separatorBefore?: boolean
  disabled?: boolean
}

export interface DropdownMenuProps {
  /** Trigger label (e.g. `YAML`). */
  label: ReactNode
  /** Trigger leading glyph. */
  icon?: ReactNode
  items: DropdownItem[]
  /** Which edge the menu aligns to. Defaults to `right`. */
  align?: 'left' | 'right'
  /** Accessible name for the trigger. */
  ariaLabel?: string
  /** Extra classes for the trigger button. */
  buttonClassName?: string
  /** Notified when the menu opens/closes (e.g. so a host can shadow a hotkey while open). */
  onOpenChange?: (open: boolean) => void
}

const TRIGGER =
  'inline-flex h-8 items-center gap-[7px] whitespace-nowrap rounded-none border border-[color:var(--apx-ink)] ' +
  'bg-transparent px-3 text-[length:var(--t-body-sm)] font-medium text-[color:var(--apx-ink)] ' +
  'transition-colors hover:bg-[var(--apx-mist)] focus-visible:outline-none focus-visible:shadow-[var(--sh-focus)]'

export function DropdownMenu({ label, icon, items, align = 'right', ariaLabel, buttonClassName, onOpenChange }: DropdownMenuProps) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const menuId = useId()

  // Set the open state and notify the host (so it can shadow a hotkey while open).
  const setMenuOpen = (next: boolean) => {
    setOpen(next)
    onOpenChange?.(next)
  }

  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setMenuOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div ref={ref} className="relative inline-flex">
      <button
        type="button"
        aria-label={ariaLabel}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setMenuOpen(!open)}
        className={cn(TRIGGER, open && 'bg-[var(--apx-bone)]', buttonClassName)}
      >
        {icon}
        {label}
        <svg
          width="10"
          height="10"
          viewBox="0 0 10 10"
          fill="none"
          aria-hidden="true"
          className={cn('transition-transform duration-150', open && 'rotate-180')}
        >
          <path d="M2 4l3 3 3-3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {open && (
        <div
          id={menuId}
          role="menu"
          className={cn(
            'absolute top-[calc(100%+6px)] z-[95] w-[288px] border border-[color:var(--apx-ink)] bg-[var(--apx-white)] p-[5px] shadow-[var(--sh-2)]',
            align === 'right' ? 'right-0' : 'left-0',
          )}
        >
          {items.map((item) => (
            <div key={item.id}>
              {item.separatorBefore && <div className="mx-[6px] my-[4px] h-px bg-[var(--border-subtle)]" />}
              <button
                type="button"
                role="menuitem"
                disabled={item.disabled}
                onClick={() => {
                  setMenuOpen(false)
                  item.onSelect()
                }}
                className="group flex w-full items-center gap-[11px] rounded-none px-[10px] py-[9px] text-left text-[color:var(--text-primary)] transition-colors hover:bg-[var(--apx-bone)] disabled:pointer-events-none disabled:opacity-50"
              >
                {item.icon && (
                  <span className="flex-none text-[color:var(--text-muted)] transition-colors group-hover:text-[color:var(--text-primary)]">
                    {item.icon}
                  </span>
                )}
                <span className="min-w-0 flex-1">
                  <span className="block text-[length:var(--t-body-sm)] font-medium leading-[1.2]">{item.label}</span>
                  {item.sub && (
                    <span className="mt-[2px] block truncate font-mono text-[length:var(--t-micro)] text-[color:var(--text-muted)]">
                      {item.sub}
                    </span>
                  )}
                </span>
                {item.kbd && (
                  <kbd className="flex-none rounded-none border border-[color:var(--border-default)] bg-[var(--apx-paper)] px-[6px] py-px font-mono text-[length:var(--t-overline)] text-[color:var(--text-muted)]">
                    {item.kbd}
                  </kbd>
                )}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
