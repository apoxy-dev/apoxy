// The ⌘K command palette (APO-781): an overlay fed by a flat command list
// (the app builds it from the registry). It composes the M4 primitives — a
// `dialog`-level keyboard scope so it shadows view/tray nav while open, and
// `useListSelection` for ↑/↓/Enter — rather than pulling a palette library, so
// it stays app-agnostic and unit-testable in jsdom. Arrow/Enter are handled on
// the input; Escape and a second ⌘K close it via the scope.
//
// Styled to the design's `.cmdk-*`: a search row with a leading icon + `esc`
// hint, grouped results with a glyph tile and a mono sub-line, live match
// highlighting, and a footer of keyboard hints.

import { Fragment, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { cn } from '../lib/cn'
import { useListSelection } from '../keyboard/selection'
import { useKeyboardScope } from '../keyboard/scope-stack'
import { formatChord, parseSequence } from '../keyboard/keys'
import { filterCommands, type Command } from './commands'

export interface CommandPaletteProps {
  open: boolean
  onClose: () => void
  commands: Command[]
  placeholder?: string
  /** Accessible label for the dialog. */
  label?: string
  /** Optional brand text shown in the footer (the app supplies it; core stays
   *  app-agnostic, so nothing renders when unset). */
  brand?: string
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** A compiled, case-insensitive matcher for the current query. */
interface Matcher {
  set: Set<string>
  re: RegExp
}

/** Build the matcher once per query. Tokens are ordered longest-first so a token
 *  that prefixes another (`g` vs `gw`) doesn't win the alternation and truncate
 *  the longer match. A global regex is safe to reuse across `String.split`,
 *  which ignores `lastIndex`. */
function buildMatcher(query: string): Matcher | null {
  const tokens = query.trim().toLowerCase().split(/\s+/).filter(Boolean)
  if (!tokens.length) return null
  const ordered = tokens.slice().sort((a, b) => b.length - a.length)
  return { set: new Set(tokens), re: new RegExp(`(${ordered.map(escapeRegExp).join('|')})`, 'ig') }
}

/** Wrap each query token where it appears in `text`, preserving the original. */
function highlight(text: string, matcher: Matcher | null): ReactNode {
  if (!matcher) return text
  // `split` with a capture group keeps the delimiters (original case); a part is
  // a match when its lowercase form is one of the tokens.
  return text.split(matcher.re).map((part, i) =>
    part && matcher.set.has(part.toLowerCase()) ? (
      <mark key={i} className="rounded-none bg-[var(--apx-blue-tint)] px-[1px] text-[color:var(--apx-blue-deep)]">
        {part}
      </mark>
    ) : (
      <Fragment key={i}>{part}</Fragment>
    ),
  )
}

const SearchIcon = (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
    <circle cx="7" cy="7" r="4.5" />
    <path d="M10.5 10.5L14 14" strokeLinecap="round" />
  </svg>
)

const FallbackGlyph = (
  <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
    <rect x="2.5" y="2.5" width="11" height="11" />
  </svg>
)

const GoIcon = (
  <svg viewBox="0 0 12 12" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
    <path d="M3 6h6M6.5 3.5 9 6l-2.5 2.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
)

const HINT_KBD =
  'inline-flex min-w-[16px] items-center justify-center rounded-none border border-[color:var(--border-default)] bg-[var(--apx-paper)] px-[4px] py-[1px] font-mono text-[length:var(--t-overline)] text-[color:var(--text-muted)]'

export function CommandPalette({
  open,
  onClose,
  commands,
  placeholder = 'Search resources and actions…',
  label = 'Command palette',
  brand,
}: CommandPaletteProps) {
  const [query, setQuery] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const opener = useRef<HTMLElement | null>(null)
  const listId = useId()

  const results = useMemo(() => filterCommands(commands, query), [commands, query])
  const matcher = useMemo(() => buildMatcher(query), [query])

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

  // On open: capture the opener for focus restore, then reset query + cursor.
  // A layout effect (pre-paint) clears the prior query so reopening never
  // flashes the last search for a frame. On close, the cleanup returns focus to
  // whatever opened the palette (the ⌘K trigger) so keyboard focus isn't
  // stranded on <body>. The per-query reset below handles the stale-count edge.
  useLayoutEffect(() => {
    if (!open) return
    opener.current = (document.activeElement as HTMLElement) ?? null
    setQuery('')
    setIndex(0)
    // Focus after paint so the input exists and the browser doesn't scroll-jump.
    const id = requestAnimationFrame(() => inputRef.current?.focus())
    return () => {
      cancelAnimationFrame(id)
      opener.current?.focus?.()
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

  // Per-group totals for the header counts (only shown in the grouped view).
  const groupCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const cmd of results) if (cmd.group) counts.set(cmd.group, (counts.get(cmd.group) ?? 0) + 1)
    return counts
  }, [results])

  if (!open) return null

  const grouped = query.trim() === ''
  // Track every group already given a header, so a group whose commands aren't
  // contiguous in the input list doesn't render a second, splitting header.
  const seenGroups = new Set<string>()

  return (
    <div
      role="presentation"
      onMouseDown={onClose}
      className="fixed inset-0 z-50 flex items-start justify-center bg-[var(--scrim)] px-[var(--sp-6)] pt-[11vh]"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={label}
        onMouseDown={(e) => e.stopPropagation()}
        className="flex max-h-[min(64vh,560px)] w-[min(640px,94vw)] flex-col overflow-hidden border border-[color:var(--apx-ink)] bg-[var(--surface-card)] shadow-[var(--sh-4)]"
      >
        <div className="flex flex-none items-center gap-[11px] border-b border-[color:var(--border-default)] px-[var(--sp-4)] py-[14px]">
          <span aria-hidden="true" className="flex flex-none text-[color:var(--text-muted)]">
            {SearchIcon}
          </span>
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-autocomplete="list"
            // Guard against the post-narrow render where `index` can briefly
            // exceed the new result count before the query-reset effect runs.
            aria-activedescendant={index >= 0 && index < results.length ? `${listId}-opt-${index}` : undefined}
            value={query}
            placeholder={placeholder}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={selection.onKeyDown}
            className="min-w-0 flex-1 border-0 bg-transparent text-[length:var(--t-body)] text-[color:var(--text-primary)] outline-none placeholder:text-[color:var(--text-disabled)]"
          />
          <kbd className="flex-none rounded-none border border-[color:var(--border-default)] bg-[var(--apx-paper)] px-[7px] py-[2px] font-mono text-[length:var(--t-overline)] text-[color:var(--text-muted)]">
            esc
          </kbd>
        </div>

        <ul id={listId} role="listbox" aria-label={label} className="min-h-0 flex-1 overflow-y-auto p-[6px]">
          {results.length === 0 ? (
            <li className="px-[10px] py-[var(--sp-6)] text-center text-[length:var(--t-body-sm)] text-[color:var(--text-muted)]">
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
                    <div className="flex items-center justify-between px-[10px] pb-[5px] pt-[12px] font-mono text-[length:var(--t-overline)] font-medium uppercase tracking-[0.12em] text-[color:var(--text-muted)]">
                      <span>{header}</span>
                      <span className="text-[color:var(--text-disabled)]">{groupCounts.get(header)}</span>
                    </div>
                  )}
                  <div
                    id={`${listId}-opt-${i}`}
                    role="option"
                    // Pin the name: the match-highlight splits the visible label
                    // into <mark> spans, which would otherwise make the computed
                    // name read "Gate ways". Keep the subtitle in the name.
                    aria-label={cmd.subtitle ? `${cmd.title}, ${cmd.subtitle}` : cmd.title}
                    aria-selected={active}
                    onMouseMove={() => setIndex(i)}
                    onClick={() => {
                      onClose()
                      cmd.run()
                    }}
                    className={cn(
                      'flex cursor-pointer items-center gap-[12px] rounded-none border px-[10px] py-[var(--sp-2)]',
                      active ? 'border-[color:var(--border-default)] bg-[var(--apx-bone)]' : 'border-transparent',
                    )}
                  >
                    <span
                      aria-hidden="true"
                      className={cn(
                        'flex h-[30px] w-[30px] flex-none items-center justify-center border bg-[var(--surface-card)]',
                        active
                          ? 'border-[color:var(--apx-ink)] text-[color:var(--text-primary)]'
                          : 'border-[color:var(--border-default)] text-[color:var(--text-muted)]',
                      )}
                    >
                      {cmd.icon ?? FallbackGlyph}
                    </span>
                    <span className="flex min-w-0 flex-1 flex-col gap-[1px]">
                      <span className="truncate text-[length:var(--t-body-sm)] font-medium text-[color:var(--text-primary)]">
                        {highlight(cmd.title, matcher)}
                      </span>
                      {cmd.subtitle && (
                        <span className="truncate font-mono text-[length:var(--t-micro)] text-[color:var(--text-muted)]">
                          {cmd.subtitle}
                        </span>
                      )}
                    </span>
                    {cmd.keys && (
                      // The command's own key binding, rendered as key tiles — the
                      // palette entry and the shortcut are one and the same source.
                      <span aria-hidden="true" className="flex flex-none items-center gap-[3px]">
                        {parseSequence(cmd.keys).map((chord, ki) => (
                          <kbd key={ki} className={HINT_KBD}>
                            {formatChord(chord)}
                          </kbd>
                        ))}
                      </span>
                    )}
                    <span
                      aria-hidden="true"
                      className={cn('flex-none', active ? 'text-[color:var(--text-muted)]' : 'text-[color:var(--text-disabled)]')}
                    >
                      {GoIcon}
                    </span>
                  </div>
                </li>
              )
            })
          )}
        </ul>

        <div className="flex flex-none items-center justify-between border-t border-[color:var(--border-default)] bg-[var(--apx-paper)] px-[var(--sp-4)] py-[var(--sp-2)] text-[length:var(--t-overline)] text-[color:var(--text-muted)]">
          <div className="flex items-center gap-[var(--sp-4)]">
            <span className="flex items-center gap-[5px]">
              <kbd className={HINT_KBD}>↑</kbd>
              <kbd className={HINT_KBD}>↓</kbd>
              Navigate
            </span>
            <span className="flex items-center gap-[5px]">
              <kbd className={HINT_KBD}>↵</kbd>
              Open
            </span>
            <span className="flex items-center gap-[5px]">
              <kbd className={HINT_KBD}>esc</kbd>
              Close
            </span>
          </div>
          {brand && <span className="font-mono uppercase tracking-[0.14em] text-[color:var(--text-disabled)]">{brand}</span>}
        </div>
      </div>
    </div>
  )
}
