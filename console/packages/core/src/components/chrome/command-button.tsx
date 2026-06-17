// The command-palette trigger in the top bar. A visual placeholder for M3 — the
// cmdk palette itself is M4 — so it renders the ⌘K affordance and calls
// `onOpen` if wired, doing nothing otherwise.

export interface CommandButtonProps {
  onOpen?: () => void
  placeholder?: string
}

export function CommandButton({ onOpen, placeholder = 'Search…' }: CommandButtonProps) {
  return (
    <button
      type="button"
      onClick={onOpen}
      className="flex w-[280px] max-w-[32vw] items-center gap-[var(--sp-2)] rounded-none border border-[color:var(--border-default)] bg-[var(--apx-bone)] px-[10px] py-[var(--sp-2)] text-[length:var(--t-body-sm)] text-[color:var(--text-muted)]"
    >
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
        <circle cx="6" cy="6" r="4" />
        <path d="M9 9l3 3" strokeLinecap="round" />
      </svg>
      <span className="truncate">{placeholder}</span>
      <kbd className="ml-auto rounded-none border border-[color:var(--border-default)] bg-[var(--apx-mist)] px-[6px] py-[2px] font-mono text-[length:var(--t-overline)] text-[color:var(--text-secondary)]">
        ⌘K
      </kbd>
    </button>
  )
}
