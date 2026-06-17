// The command-palette trigger in the top bar (the design's `.cmd` search box):
// a search icon, a placeholder prompt, and the ⌘K hint. Clicking opens the
// palette. Built to the design: 280px, 6px/10px padding, bone surface, hover
// raises the border/text.

export interface CommandButtonProps {
  onOpen?: () => void
  placeholder?: string
}

export function CommandButton({ onOpen, placeholder = 'Search…' }: CommandButtonProps) {
  return (
    <button
      type="button"
      onClick={onOpen}
      className="flex w-[280px] max-w-[32vw] min-w-0 flex-[0_1_280px] items-center gap-[var(--sp-2)] rounded-none border border-[color:var(--border-default)] bg-[var(--apx-bone)] px-[10px] py-[6px] text-left text-[length:var(--t-body-sm)] text-[color:var(--text-muted)] transition-colors hover:border-[color:var(--text-secondary)] hover:text-[color:var(--text-secondary)]"
    >
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true" className="flex-none">
        <circle cx="6" cy="6" r="4" />
        <path d="M9 9l3 3" strokeLinecap="round" />
      </svg>
      <span className="min-w-0 flex-1 truncate">{placeholder}</span>
      <kbd className="ml-auto flex-none rounded-none border border-[color:var(--border-default)] bg-[var(--apx-mist)] px-[6px] py-[2px] font-mono text-[length:var(--t-micro)] text-[color:var(--text-secondary)]">
        ⌘K
      </kbd>
    </button>
  )
}
