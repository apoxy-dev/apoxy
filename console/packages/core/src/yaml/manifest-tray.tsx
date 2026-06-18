// The read-only manifest viewer (the design's `.yaml-tray`): a right-side drawer
// reached from the per-object "YAML" menu. It renders the object's rendered
// manifest with {@link YamlCode}, a Copy button, and — when the kind is editable
// — an Edit affordance in the footer that hands off to the editable YAML tray.
// Registers a modal `tray` scope so Escape closes it and list-nav keys stay
// shadowed while it's open.

import { useState } from 'react'
import { useKeyboardScope } from '../keyboard/scope-stack'
import { YamlCode } from './yaml-code'
import { TrayCloseButton } from './tray-chrome'

export interface ManifestTrayProps {
  open: boolean
  onClose: () => void
  /** Eyebrow defaults to "Manifest". */
  eyebrow?: string
  title: string
  subtitle?: string
  /** The manifest text to render and copy/download. */
  yaml: string
  /** Suggested download filename (without extension). */
  filename?: string
  /** When present, the footer shows an Edit button that calls this. */
  onEdit?: () => void
}

export function ManifestTray({ open, onClose, eyebrow = 'Manifest', title, subtitle, yaml, filename, onEdit }: ManifestTrayProps) {
  const [copied, setCopied] = useState(false)

  useKeyboardScope({
    level: 'tray',
    modal: true,
    enabled: open,
    bindings: [{ keys: 'escape', run: onClose, allowInEditable: true }],
  })

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(yaml)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    } catch {
      // Clipboard denied (insecure context / permission) — leave the label as-is.
    }
  }

  const download = () => {
    const blob = new Blob([yaml], { type: 'text/yaml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${filename ?? title}.yaml`
    // Append before click and defer the revoke — Firefox cancels a same-tick revoke
    // and requires the anchor to be in the document.
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 0)
  }

  if (!open) return null

  return (
    <div role="presentation" onMouseDown={onClose} className="fixed inset-0 z-40 flex justify-end bg-[var(--scrim-tray)]">
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={`Manifest for ${title}`}
        onMouseDown={(e) => e.stopPropagation()}
        className="flex h-full w-full max-w-[660px] flex-col border-l border-[color:var(--apx-ink)] bg-[var(--apx-white)] shadow-[var(--sh-4)]"
      >
        <header className="flex flex-none items-start gap-[var(--sp-3)] border-b border-[color:var(--border-default)] bg-[var(--apx-mist)] px-[var(--sp-5)] py-[var(--sp-4)]">
          <div className="min-w-0 flex-1">
            <div className="text-[length:var(--t-overline)] font-medium uppercase tracking-[0.16em] text-[color:var(--text-muted)]">
              {eyebrow}
            </div>
            <div
              title={title}
              className="mt-[3px] truncate font-[family-name:var(--font-display)] text-[length:var(--t-h4)] font-medium leading-[1.2] text-[color:var(--text-primary)]"
            >
              {title}
            </div>
            {subtitle && <div className="mt-[4px] truncate font-mono text-[length:var(--t-micro)] text-[color:var(--text-muted)]">{subtitle}</div>}
          </div>
          <div className="flex flex-none items-center gap-[var(--sp-2)]">
            <button
              type="button"
              onClick={copy}
              className="inline-flex h-8 min-w-[86px] items-center justify-center gap-[6px] rounded-none border border-[color:var(--apx-ink)] bg-transparent px-3 text-[length:var(--t-body-sm)] font-medium text-[color:var(--apx-ink)] transition-colors hover:bg-[var(--apx-mist)]"
            >
              {copied ? (
                <>
                  <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
                    <path d="M3 7l3 3 5-6" />
                  </svg>
                  Copied
                </>
              ) : (
                <>
                  <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
                    <rect x="4" y="4" width="8" height="8" />
                    <path d="M4 8H2V2h6v2" />
                  </svg>
                  Copy
                </>
              )}
            </button>
            <TrayCloseButton onClick={onClose} />
          </div>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto bg-[var(--apx-paper)]">
          <YamlCode text={yaml} />
        </div>

        <footer className="flex flex-none items-center justify-between border-t border-[color:var(--border-default)] bg-[var(--apx-white)] px-[var(--sp-5)] py-[var(--sp-3)]">
          <div className="font-mono text-[length:var(--t-micro)] text-[color:var(--text-muted)]">
            <kbd className="rounded-none border border-[color:var(--border-default)] bg-[var(--apx-mist)] px-[6px] py-px text-[color:var(--text-secondary)]">esc</kbd> to close
          </div>
          <div className="flex flex-none items-center gap-[var(--sp-2)]">
            <button
              type="button"
              onClick={download}
              className="inline-flex h-8 items-center gap-[6px] rounded-none px-3 text-[length:var(--t-body-sm)] font-medium text-[color:var(--apx-ink)] transition-colors hover:bg-[var(--apx-mist)]"
            >
              <svg width="12" height="12" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
                <path d="M7 1v8M3 6l4 4 4-4M2 12h10" />
              </svg>
              Download
            </button>
            {onEdit && (
              <button
                type="button"
                onClick={onEdit}
                className="inline-flex h-8 items-center gap-[6px] rounded-none border border-[color:var(--apx-ink)] bg-transparent px-3 text-[length:var(--t-body-sm)] font-medium text-[color:var(--apx-ink)] transition-colors hover:bg-[var(--apx-mist)]"
              >
                <svg width="12" height="12" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
                  <path d="M2 10v2h2L11 5l-2-2z" />
                </svg>
                Edit
              </button>
            )}
          </div>
        </footer>
      </aside>
    </div>
  )
}

