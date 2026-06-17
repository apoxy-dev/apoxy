// The ⌘K command palette (APO-781): an overlay fed by a flat command list
// (the app builds it from the registry). It composes the M4 primitives — a
// `dialog`-level keyboard scope so it shadows view/tray nav while open, and
// `useListSelection` for ↑/↓/Enter — rather than pulling a palette library, so
// it stays app-agnostic and unit-testable in jsdom. Arrow/Enter are handled on
// the input; Escape and a second ⌘K close it via the scope.

import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { cn } from '../lib/cn'
import { useListSelection } from '../keyboard/selection'
import { useKeyboardScope } from '../keyboard/scope-stack'
import { filterCommands, type Command } from './commands'

export interface CommandPaletteProps {
  open: boolean
  onClose: () => void
  commands: Command[]
  placeholder?: string
  /** Accessible label for the dialog. */
  label?: string
}

export function CommandPalette({
  open,
  onClose,
  commands,
  placeholder = 'Search resources and actions…',
  label = 'Command palette',
}: CommandPaletteProps) {
  const [query, setQuery] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const listId = useId()

  const results = useMemo(() => filterCommands(commands, query), [commands, query])

  const selection = useListSelection({
    count: results.length,
    loop: true,
    initialIndex: 0,
    onActivate: (i) => {
      const cmd = results[i]
      if (cmd) {
        onClose()
        cmd.run()
      }
    },
  })
  const { index, setIndex } = selection

  // Reset query + cursor and focus the field each time the palette opens. The
  // cursor reset here is safe (on open the full list shows, so the count is not
  // stale); the per-query reset below handles the stale-count edge case.
  useEffect(() => {
    if (open) {
      setQuery('')
      setIndex(0)
      // Focus after paint so the input exists and the browser doesn't scroll-jump.
      const id = requestAnimationFrame(() => inputRef.current?.focus())
      return () => cancelAnimationFrame(id)
    }
  }, [open, setIndex])

  // Snap the cursor to the top match whenever the *query* changes. Keyed on the
  // query (not the `results` array identity) so an unrelated re-render that
  // rebuilds `commands` — e.g. discovery refetching while the palette is open —
  // doesn't reset the user's cursor. Run as an effect (post-commit) so setIndex
  // clamps against the NEW result count: a 0-match → N-match edit lands on 0
  // rather than stranding the cursor at -1 where Enter would do nothing.
  useEffect(() => {
    setIndex(0)
  }, [query, setIndex])

  // Keep the highlighted option scrolled into view as the cursor moves.
  useEffect(() => {
    if (!open || index < 0) return
    // `scrollIntoView` is absent in jsdom; optional-call so tests don't throw.
    document.getElementById(`${listId}-opt-${index}`)?.scrollIntoView?.({ block: 'nearest' })
  }, [open, index, listId])

  // Escape / second ⌘K close it; both allowed while the input is focused.
  useKeyboardScope({
    level: 'dialog',
    enabled: open,
    bindings: [
      { keys: 'escape', run: onClose, allowInEditable: true },
      { keys: 'mod+k', run: onClose, allowInEditable: true },
    ],
  })

  if (!open) return null

  const grouped = query.trim() === ''
  // Track every group already given a header, so a group whose commands aren't
  // contiguous in the input list doesn't render a second, splitting header.
  const seenGroups = new Set<string>()

  return (
    <div
      role="presentation"
      onMouseDown={onClose}
      className="fixed inset-0 z-50 flex items-start justify-center bg-[rgba(30,29,28,0.4)] px-[var(--sp-4)] pt-[12vh]"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={label}
        onMouseDown={(e) => e.stopPropagation()}
        className="flex max-h-[68vh] w-full max-w-[560px] flex-col overflow-hidden border border-[color:var(--border-strong)] bg-[var(--apx-white)] shadow-[var(--sh-4)]"
      >
        <input
          ref={inputRef}
          type="text"
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={index >= 0 ? `${listId}-opt-${index}` : undefined}
          value={query}
          placeholder={placeholder}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={selection.onKeyDown}
          className="w-full flex-none border-0 border-b border-[color:var(--border-default)] bg-transparent px-[var(--sp-5)] py-[var(--sp-4)] text-[length:var(--t-body)] text-[color:var(--text-primary)] outline-none placeholder:text-[color:var(--text-muted)]"
        />

        <ul id={listId} role="listbox" aria-label={label} className="min-h-0 flex-1 overflow-y-auto py-[var(--sp-1)]">
          {results.length === 0 ? (
            <li className="px-[var(--sp-5)] py-[var(--sp-6)] text-center text-[length:var(--t-body-sm)] text-[color:var(--text-muted)]">
              No matches
            </li>
          ) : (
            results.map((cmd, i) => {
              const header = grouped && cmd.group && !seenGroups.has(cmd.group) ? cmd.group : undefined
              if (cmd.group) seenGroups.add(cmd.group)
              const active = i === index
              return (
                <li key={cmd.id} role="presentation">
                  {header && (
                    <div className="px-[var(--sp-5)] pb-[var(--sp-1)] pt-[var(--sp-3)] text-[length:var(--t-overline)] uppercase tracking-[0.12em] text-[color:var(--text-muted)]">
                      {header}
                    </div>
                  )}
                  <div
                    id={`${listId}-opt-${i}`}
                    role="option"
                    aria-selected={active}
                    onMouseMove={() => setIndex(i)}
                    onClick={() => {
                      onClose()
                      cmd.run()
                    }}
                    className={cn(
                      'flex cursor-pointer items-center gap-[var(--sp-3)] px-[var(--sp-5)] py-[var(--sp-3)] text-[length:var(--t-body-sm)]',
                      active ? 'bg-[var(--apx-mist)] text-[color:var(--text-primary)]' : 'text-[color:var(--text-secondary)]',
                    )}
                  >
                    {cmd.icon && (
                      <span aria-hidden="true" className="flex h-4 w-4 flex-none items-center justify-center text-[color:var(--text-muted)]">
                        {cmd.icon}
                      </span>
                    )}
                    <span className="min-w-0 flex-1 truncate font-medium">{cmd.title}</span>
                    {cmd.subtitle && (
                      <span className="flex-none truncate font-mono text-[length:var(--t-overline)] text-[color:var(--text-muted)]">
                        {cmd.subtitle}
                      </span>
                    )}
                  </div>
                </li>
              )
            })
          )}
        </ul>
      </div>
    </div>
  )
}
