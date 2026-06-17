// A square 32px icon button for the top bar (the design's `.icobtn`): docs,
// theme toggle, notifications. Renders a <button> by default, or an <a> when
// `href` is set (so the docs link opens a real URL / new tab). The optional
// `badge` shows the coral notification dot. App-agnostic: the caller passes the
// 16px glyph as children.

import type { ReactNode } from 'react'

export interface IconButtonProps {
  /** Accessible name (aria-label + title). */
  label: string
  /** When set, renders an anchor to this URL instead of a button. */
  href?: string
  /** Anchor target (defaults to `_blank` for external links when href is set). */
  target?: string
  onClick?: () => void
  /** Reflects a two-state control (e.g. the theme toggle) via aria-pressed. */
  pressed?: boolean
  /** Show the coral notification dot in the top-right. */
  badge?: boolean
  /** The 16px icon. */
  children: ReactNode
}

// `--border-strong` (not `--apx-ink`) on hover so dark mode lands on graphite
// rather than the inverted near-white ink.
const BASE =
  'relative inline-flex h-8 w-8 flex-none items-center justify-center rounded-none border border-[color:var(--border-default)] bg-[var(--surface-card)] text-[color:var(--text-primary)] transition-colors hover:border-[color:var(--border-strong)]'

function Badge() {
  return (
    <span
      aria-hidden="true"
      className="absolute right-[5px] top-[5px] h-[6px] w-[6px] rounded-full border border-[color:var(--surface-card)] bg-[var(--apx-coral)]"
    />
  )
}

export function IconButton({ label, href, target, onClick, pressed, badge, children }: IconButtonProps) {
  // The badge dot is decorative (aria-hidden), so fold the unread state into the
  // accessible name for assistive tech.
  const name = badge ? `${label}, unread` : label
  if (href) {
    // Default external (absolute) links to a new tab; leave same-page links in place.
    const isExternal = /^https?:\/\//i.test(href)
    return (
      <a
        href={href}
        target={target ?? (isExternal ? '_blank' : undefined)}
        rel={isExternal ? 'noreferrer' : undefined}
        aria-label={name}
        title={label}
        onClick={onClick}
        className={BASE}
      >
        {children}
        {badge && <Badge />}
      </a>
    )
  }
  return (
    <button
      type="button"
      aria-label={name}
      title={label}
      aria-pressed={pressed}
      onClick={onClick}
      className={BASE}
    >
      {children}
      {badge && <Badge />}
    </button>
  )
}
