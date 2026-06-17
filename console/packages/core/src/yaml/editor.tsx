// The tray's editor seam (APO-777). The tray talks to an editor through this
// small interface — `value` / `onChange` / `readOnly` — so the widget is
// swappable. The default `TextAreaEditor` is dependency-free (a textarea with a
// synced line-number gutter), which keeps `@apoxy/console-core` light and
// node/jsdom-testable. A CodeMirror-6 editor (syntax highlighting, lint gutter)
// is a drop-in that implements the same props; it belongs in the app layer,
// where a browser-only widget that can't render in jsdom is appropriate.

import { createContext, useContext, useLayoutEffect, useMemo, useRef, type ComponentType, type ReactNode } from 'react'
import { cn } from '../lib/cn'

export interface TrayEditorProps {
  value: string
  onChange: (value: string) => void
  readOnly?: boolean
  ariaLabel?: string
}

/** The contract any tray editor implements; the production CodeMirror swap fits here. */
export type TrayEditor = ComponentType<TrayEditorProps>

// The editor injection seam (APO-777): the YAML tray is mounted *inside* core
// (the detail-view edit affordance and the create flow), so the app can't pass
// an `editor` prop to those mounts directly. Instead the app installs its editor
// once via <TrayEditorProvider> — a browser-only CodeMirror widget that lives in
// the app layer (it can't render in jsdom) — and every tray picks it up. With no
// provider, the tray falls back to the dependency-free TextAreaEditor.
const TrayEditorContext = createContext<TrayEditor | null>(null)

export function TrayEditorProvider({ editor, children }: { editor: TrayEditor; children: ReactNode }) {
  return <TrayEditorContext.Provider value={editor}>{children}</TrayEditorContext.Provider>
}

/** The app-provided tray editor, or null when none is installed (tests, SSR). */
export function useTrayEditor(): TrayEditor | null {
  return useContext(TrayEditorContext)
}

export function TextAreaEditor({ value, onChange, readOnly, ariaLabel = 'YAML editor' }: TrayEditorProps) {
  const taRef = useRef<HTMLTextAreaElement>(null)
  const gutterRef = useRef<HTMLDivElement>(null)

  const lineCount = useMemo(() => Math.max(1, value.split('\n').length), [value])
  const lineNumbers = useMemo(() => Array.from({ length: lineCount }, (_, i) => i + 1), [lineCount])

  // Keep the gutter aligned with the textarea's scroll position.
  useLayoutEffect(() => {
    const ta = taRef.current
    const gutter = gutterRef.current
    if (!ta || !gutter) return
    const sync = () => {
      gutter.scrollTop = ta.scrollTop
    }
    ta.addEventListener('scroll', sync)
    return () => ta.removeEventListener('scroll', sync)
  }, [])

  return (
    <div className="flex min-h-0 flex-1 overflow-hidden border border-[color:var(--border-default)] bg-[var(--apx-white)] font-mono text-[length:var(--t-micro)] leading-[var(--lh-snug)]">
      <div
        ref={gutterRef}
        aria-hidden="true"
        className="flex-none select-none overflow-hidden border-r border-[color:var(--border-subtle)] bg-[var(--apx-mist)] px-[var(--sp-2)] py-[var(--sp-3)] text-right text-[color:var(--text-muted)]"
      >
        {lineNumbers.map((n) => (
          <div key={n} className="tabular-nums">
            {n}
          </div>
        ))}
      </div>
      <textarea
        ref={taRef}
        aria-label={ariaLabel}
        value={value}
        readOnly={readOnly}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        wrap="off"
        onChange={(e) => onChange(e.target.value)}
        // No Tab-to-spaces in read-only mode: it would trap focus and mutate the
        // "immutable" content through the native setter, bypassing `readOnly`.
        onKeyDown={readOnly ? undefined : handleTab}
        className={cn(
          'min-w-0 flex-1 resize-none overflow-auto whitespace-pre bg-transparent px-[var(--sp-3)] py-[var(--sp-3)] text-[color:var(--text-primary)] outline-none',
          readOnly && 'text-[color:var(--text-secondary)]',
        )}
      />
    </div>
  )
}

/** Tab inserts two spaces instead of moving focus, the way a code editor would. */
function handleTab(e: React.KeyboardEvent<HTMLTextAreaElement>): void {
  if (e.key !== 'Tab' || e.shiftKey) return
  e.preventDefault()
  const ta = e.currentTarget
  const { selectionStart, selectionEnd, value } = ta
  const next = `${value.slice(0, selectionStart)}  ${value.slice(selectionEnd)}`
  // React controls the value, so set it through the native setter then dispatch
  // an input event the controlled onChange will pick up.
  const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set
  setter?.call(ta, next)
  ta.dispatchEvent(new Event('input', { bubbles: true }))
  ta.selectionStart = ta.selectionEnd = selectionStart + 2
}
