// A capped, line-numbered viewer for a captured request/response body. The span
// inspector dumps payloads that run up to the gateway's body-capture cap (tens of
// KiB, thousands of lines), so a flat <pre> is unreadable: this gives line numbers,
// a fixed-height scroll, soft JSON tint, a wrap toggle, copy, and a fullscreen
// pop-out. Streamed responses pass multiple views (e.g. Decoded / Raw) and get a
// segmented selector. App-agnostic: it knows nothing about clrk spans, only text.

import {
  memo,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import { Copy, TextWrap, Maximize, Close, type CarbonIconType } from '@carbon/icons-react'
import { cn } from '../../lib/cn'
import { useKeyboardScope } from '../../keyboard/scope-stack'

export interface BodyView {
  /** Stable id; selected by the segmented control when more than one view. */
  id: string
  /** Segmented-control label (e.g. "Decoded" / "Raw"). Omit on a single view. */
  label?: string
  /** The payload text, rendered line-numbered and JSON-tinted. */
  text: string
  /** Captured byte length; falls back to the UTF-8 length of `text`. */
  bytes?: number
  /** Marks a capture that hit the gateway's body cap and was cut short. */
  truncated?: boolean
  /** Footer context, e.g. "raw event stream" or "captured at span open". */
  note?: string
}

export interface BodyBoxProps {
  /** Toolbar title (e.g. "Request body"). */
  title: string
  /** Optional content-type badge (e.g. "text/event-stream"). */
  contentType?: string
  /** One view renders a plain box; two or more add a segmented selector. */
  views: BodyView[]
  /** Scroll cap in px before the body scrolls. Defaults to 300. */
  maxHeight?: number
  className?: string
}

type Tint = 'k' | 's' | 'n'
interface Seg {
  text: string
  tint?: Tint
}

// Fallback when a caller passes an empty `views` array (a misuse); keeps every
// downstream read non-undefined and renders an empty box rather than crashing.
const EMPTY_VIEW: BodyView = { id: '', text: '' }

const TINT_CLASS: Record<Tint, string> = {
  k: 'text-[color:var(--apx-blue)]',
  s: 'text-[color:var(--apx-leaf)]',
  n: 'text-[color:var(--apx-amber)]',
}

// Cheap per-line JSON tint: object keys, quoted string values, and bare
// number/bool/null literals. Not a real tokenizer -- it classifies purely by
// adjacency to ':' so NDJSON, SSE frames, and prose pass through uncolored
// rather than mis-highlighted.
function tintLine(line: string): Seg[] {
  const out: Seg[] = []
  const push = (text: string, tint?: Tint) => {
    if (!text) return
    const last = out[out.length - 1]
    if (last && last.tint === tint) last.text += text
    else out.push({ text, tint })
  }
  let i = 0
  let expectValue = false
  while (i < line.length) {
    const ch = line.charAt(i)
    if (ch === '"') {
      // Consume a quoted string, honoring backslash escapes.
      let j = i + 1
      while (j < line.length) {
        if (line[j] === '\\') {
          j += 2
          continue
        }
        if (line[j] === '"') {
          j += 1
          break
        }
        j += 1
      }
      const str = line.slice(i, j)
      if (expectValue) {
        push(str, 's')
        expectValue = false
      } else {
        // A string is a key when the next non-space char is a colon.
        let k = j
        while (k < line.length && (line[k] === ' ' || line[k] === '\t')) k += 1
        push(str, line[k] === ':' ? 'k' : undefined)
      }
      i = j
      continue
    }
    if (ch === ':') {
      push(':')
      expectValue = true
      i += 1
      continue
    }
    if (ch === ' ' || ch === '\t') {
      push(ch)
      i += 1
      continue
    }
    if (expectValue) {
      // Require a value terminator after the literal so a numeric *prefix* of a
      // larger token (e.g. "2024-06-27", "5xx") is not split-colored.
      const m = /^(-?\d+(?:\.\d+)?|true|false|null)(?=$|[\s,}\]])/.exec(line.slice(i))
      if (m) {
        push(m[0], 'n')
        i += m[0].length
        expectValue = false
        continue
      }
    }
    push(ch)
    expectValue = false
    i += 1
  }
  return out
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) {
    const kib = n / 1024
    const s = kib < 10 ? kib.toFixed(1) : kib.toFixed(0)
    // Roll a value that rounds up to 1024 KiB over to 1.0 MiB.
    if (s !== '1024') return `${s} KiB`
  }
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`
}

const enc = typeof TextEncoder !== 'undefined' ? new TextEncoder() : null
function utf8Len(s: string): number {
  return enc ? enc.encode(s).length : s.length
}

// Copy to the clipboard, resolving to whether it actually succeeded. Falls back
// to execCommand for insecure contexts (clrk-console is served over plain http,
// where navigator.clipboard is undefined) so the caller never reports a false
// success and a rejected write is never an unhandled rejection.
function copyText(text: string): Promise<boolean> {
  if (navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(text).then(() => true, () => execCopy(text))
  }
  return Promise.resolve(execCopy(text))
}
function execCopy(text: string): boolean {
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.top = '0'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}

// The line table is the expensive part of a large body, so it is memoized on the
// tokenized lines (stable per text). Wrap mode lives on the scroll container and
// inherits down via white-space, so toggling wrap never re-renders these rows.
const CodeLines = memo(function CodeLines({ lines }: { lines: Seg[][] }) {
  return (
    <div className="table w-full border-collapse">
      {lines.map((segs, i) => (
        <div key={i} className="group table-row">
          <span
            aria-hidden="true"
            className="sticky left-0 table-cell w-[1%] select-none whitespace-nowrap border-r border-[color:var(--border-subtle)] bg-[var(--apx-bone)] px-[12px] text-right align-top text-[12px] leading-[1.55] text-[color:var(--text-muted)] group-hover:text-[color:var(--text-secondary)]"
          >
            {i + 1}
          </span>
          <code className="table-cell px-[14px] align-top text-[length:var(--t-caption)] leading-[1.55] text-[color:var(--text-primary)] [tab-size:2] group-hover:bg-[color-mix(in_srgb,var(--apx-mist)_55%,transparent)]">
            {segs.length === 0
              ? ' '
              : segs.map((s, j) =>
                  s.tint ? (
                    <span key={j} className={TINT_CLASS[s.tint]}>
                      {s.text}
                    </span>
                  ) : (
                    <span key={j}>{s.text}</span>
                  ),
                )}
          </code>
        </div>
      ))}
    </div>
  )
})

function ToolBtn({
  icon: Icon,
  label,
  active,
  dark,
  onClick,
}: {
  icon: CarbonIconType
  label: string
  active?: boolean
  dark?: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      title={label}
      className={cn(
        'inline-flex cursor-pointer items-center gap-[5px] border border-transparent px-[7px] py-[3px] text-[12px] transition-colors duration-150 [font-family:var(--font-mono)]',
        dark
          ? 'text-[color:var(--apx-stone)] hover:bg-[rgba(255,255,255,0.1)] hover:text-[color:var(--apx-white)]'
          : 'text-[color:var(--text-secondary)] hover:bg-[var(--apx-mist)] hover:text-[color:var(--text-primary)]',
        active &&
          (dark
            ? 'border-[color:var(--apx-stone)] bg-[rgba(255,255,255,0.08)] text-[color:var(--apx-white)]'
            : 'border-[color:var(--apx-fog)] bg-[var(--apx-white)] text-[color:var(--text-primary)]'),
      )}
    >
      <Icon size={13} />
      <span>{label}</span>
    </button>
  )
}

function Pill({ children, dark }: { children: string; dark?: boolean }) {
  return (
    <span
      className={cn(
        'inline-flex shrink-0 border px-[5px] py-px text-[12px] tracking-[0.03em]',
        dark
          ? 'border-[color:var(--apx-stone)] text-[color:var(--apx-stone)]'
          : 'border-[color:var(--border-default)] text-[color:var(--text-muted)]',
      )}
    >
      {children}
    </span>
  )
}

export function BodyBox({ title, contentType, views, maxHeight = 300, className }: BodyBoxProps) {
  const viewsKey = views.map((v) => v.id).join('|')
  const [viewId, setViewId] = useState(views[0]?.id)
  const [wrap, setWrap] = useState(false)
  const [full, setFull] = useState(false)
  const [fullWrap, setFullWrap] = useState(true)
  const [copied, setCopied] = useState(false)
  const copyTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  // Reset the selected view (and close any pop-out) when the inspected body
  // changes underneath us -- the previous viewId may not exist in the new set.
  useEffect(() => {
    setViewId(views[0]?.id)
    setFull(false)
  }, [viewsKey]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => () => clearTimeout(copyTimer.current), [])

  useKeyboardScope({
    level: 'dialog',
    modal: true,
    enabled: full,
    bindings: [{ keys: 'escape', run: () => setFull(false), allowInEditable: true }],
  })

  const view = views.find((v) => v.id === viewId) ?? views[0] ?? EMPTY_VIEW
  const lines = useMemo(() => view.text.split('\n').map(tintLine), [view.text])
  // `|| utf8Len` (not `??`): a captured-byte count of 0 means "unknown" (the
  // span attribute was missing/unparseable), not an empty body, so fall back to
  // the text length rather than rendering "0 B" for a real payload. Memoized so
  // a large body is not re-encoded on every toolbar interaction.
  const bytes = useMemo(() => view.bytes || utf8Len(view.text), [view.bytes, view.text])
  const lineCount = lines.length
  const multi = views.length > 1

  const copy = () => {
    copyText(view.text).then((ok) => {
      if (!ok) return
      setCopied(true)
      clearTimeout(copyTimer.current)
      copyTimer.current = setTimeout(() => setCopied(false), 1100)
    })
  }

  const foot =
    `${lineCount.toLocaleString()} lines · ${fmtBytes(bytes)}` +
    (view.truncated ? ' · truncated' : '') +
    (view.note ? ` · ${view.note}` : '')

  return (
    <div className={cn('border border-[color:var(--border-default)] bg-[var(--apx-paper)] [font-family:var(--font-mono)]', className)}>
      <div className="flex items-center gap-[10px] border-b border-[color:var(--border-subtle)] bg-[var(--apx-bone)] py-[7px] pl-[12px] pr-[10px]">
        <span className="flex min-w-0 items-center gap-[8px] text-[12px] text-[color:var(--text-secondary)]">
          <b className="truncate text-[16px] font-medium text-[color:var(--text-primary)]">{title}</b>
          {contentType && <Pill>{contentType}</Pill>}
          <Pill>{fmtBytes(bytes)}</Pill>
        </span>
        <span className="ml-auto flex items-center gap-[2px]">
          {multi && (
            <span className="mr-[6px] inline-flex border border-[color:var(--border-default)]">
              {views.map((v) => (
                <button
                  key={v.id}
                  type="button"
                  onClick={() => setViewId(v.id)}
                  className={cn(
                    'cursor-pointer px-[9px] py-[3px] text-[12px] transition-colors duration-150 [font-family:var(--font-mono)]',
                    v.id === view.id
                      ? 'bg-[var(--apx-ink)] text-[color:var(--apx-bone)]'
                      : 'text-[color:var(--text-muted)] hover:text-[color:var(--text-primary)]',
                  )}
                >
                  {v.label ?? v.id}
                </button>
              ))}
            </span>
          )}
          <ToolBtn icon={TextWrap} label="Wrap" active={wrap} onClick={() => setWrap((w) => !w)} />
          <ToolBtn icon={Copy} label={copied ? 'Copied' : 'Copy'} active={copied} onClick={copy} />
          <ToolBtn icon={Maximize} label="Fullscreen" onClick={() => setFull(true)} />
        </span>
      </div>

      <div
        className={cn('relative overflow-auto', wrap ? 'whitespace-pre-wrap break-words' : 'whitespace-pre')}
        style={{ maxHeight }}
      >
        {/* Don't mount a second copy of the (potentially thousands-of-row) line
            table behind the fullscreen overlay; the overlay renders its own. */}
        {!full && <CodeLines lines={lines} />}
      </div>

      <div className="flex items-center gap-[10px] border-t border-[color:var(--border-subtle)] bg-[var(--apx-bone)] px-[12px] py-[6px] text-[11px] text-[color:var(--text-muted)]">
        {foot}
      </div>

      {full && (
        <div
          role="presentation"
          onMouseDown={() => setFull(false)}
          className="fixed inset-0 z-50 flex bg-[var(--scrim-tray)] p-[40px] [backdrop-filter:blur(2px)]"
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-label={title}
            onMouseDown={(e) => e.stopPropagation()}
            className="m-auto flex max-h-full w-full max-w-[1000px] flex-col border border-[color:var(--apx-fog)] bg-[var(--apx-paper)] shadow-[var(--sh-4)]"
          >
            <div className="flex items-center gap-[10px] border-b border-[color:var(--border-subtle)] bg-[var(--apx-ink)] py-[7px] pl-[12px] pr-[10px]">
              <span className="flex min-w-0 items-center gap-[8px] text-[12px] text-[color:var(--apx-bone)]">
                <b className="truncate text-[16px] font-medium text-[color:var(--apx-bone)]">
                  {title}
                  {multi && view.label ? ` · ${view.label}` : ''}
                </b>
                <Pill dark>{fmtBytes(bytes)}</Pill>
              </span>
              <span className="ml-auto flex items-center gap-[2px]">
                <ToolBtn icon={TextWrap} label="Wrap" dark active={fullWrap} onClick={() => setFullWrap((w) => !w)} />
                <ToolBtn icon={Copy} label={copied ? 'Copied' : 'Copy'} dark active={copied} onClick={copy} />
                <ToolBtn icon={Close} label="Close" dark onClick={() => setFull(false)} />
              </span>
            </div>
            <div
              className={cn('relative flex-1 overflow-auto', fullWrap ? 'whitespace-pre-wrap break-words' : 'whitespace-pre')}
            >
              <CodeLines lines={lines} />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
