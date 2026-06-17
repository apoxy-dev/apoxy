// Register key bindings straight off the command list (APO-781). The ⌘K palette
// and the keyboard both read the same `Command[]`, so a command's `keys` spec is
// its shortcut *and* its palette entry — they can't drift. Every kind with a
// registry `shortcut` contributes a `g`-sequence go-to for free; adding a kind
// adds its chord with no extra wiring.

import { useMemo } from 'react'
import { useKeyboardScope, type KeyBinding, type ScopeLevel } from '../keyboard/scope-stack'
import type { Command } from './commands'

export interface UseCommandKeyBindingsOptions {
  /** Scope level the bindings register at. Defaults to `global` (g-sequences are
   *  shadowed by an open tray/dialog like any other global binding). */
  level?: ScopeLevel | number
  /** Skip registration entirely when false. */
  enabled?: boolean
}

/**
 * Register a keyboard scope from the commands that carry a `keys` spec. Commands
 * without one are palette-only; the rest fire their `run` from the keyboard too.
 */
export function useCommandKeyBindings(commands: Command[], opts: UseCommandKeyBindingsOptions = {}): void {
  const bindings = useMemo<KeyBinding[]>(
    () =>
      commands
        .filter((c) => c.keys)
        .map((c) => ({ keys: c.keys!, run: () => c.run(), description: c.title })),
    [commands],
  )
  useKeyboardScope({ level: opts.level ?? 'global', enabled: opts.enabled, bindings })
}
