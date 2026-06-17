// The keyboard scope stack (APO-779): a single document-level key dispatcher
// with a priority stack — global < view < tray < dialog. A *modal* scope (the
// YAML tray, a dialog, the command palette) shadows everything below it, so
// list-nav keys never fire while a tray is open. Bindings may be SEQUENCES
// (`g i`) for Linear-style g-navigation; a pending prefix is held briefly and
// cleared on timeout. Typing into an input only triggers bindings explicitly
// marked `allowInEditable` (⌘S, Escape) — never bare letters.

import { createContext, useContext, useEffect, useId, useMemo, useRef } from 'react'
import type { ReactNode } from 'react'
import {
  type Chord,
  detectMac,
  eventChord,
  isEditableTarget,
  isModifierOnly,
  parseSequence,
  sequenceEquals,
  sequenceStartsWith,
} from './keys'

/** Canonical scope priorities; higher shadows lower. */
export const ScopePriority = {
  global: 0,
  view: 10,
  tray: 20,
  dialog: 30,
} as const

export type ScopeLevel = keyof typeof ScopePriority

/** One key binding within a scope. */
export interface KeyBinding {
  /** Binding spec: a chord (`mod+k`) or sequence (`g i`). */
  keys: string
  /** Invoked when matched; the raw event is passed so the handler can inspect it. */
  run: (e: KeyboardEvent) => void
  /** Shown in help/affordances. */
  description?: string
  /** Allow this binding to fire while a text input is focused (⌘S, Escape). */
  allowInEditable?: boolean
}

export interface KeyboardScope {
  /** Stable id; defaults to a generated one. */
  id?: string
  /** Stack level (or a raw number for fine control). */
  level: ScopeLevel | number
  bindings: KeyBinding[]
  /** When true (default for tray/dialog), shadows all lower-priority scopes. */
  modal?: boolean
  /** Skip this scope entirely when false. */
  enabled?: boolean
}

interface RegisteredScope extends KeyboardScope {
  id: string
  priority: number
  parsed: Array<{ binding: KeyBinding; seq: Chord[] }>
}

interface ScopeRegistry {
  register(scope: RegisteredScope): void
  unregister(id: string): void
}

const ScopeRegistryContext = createContext<ScopeRegistry | null>(null)

function priorityOf(level: ScopeLevel | number): number {
  return typeof level === 'number' ? level : ScopePriority[level]
}

export interface KeyboardScopeProviderProps {
  children: ReactNode
  /** How long a pending g-sequence prefix is held before it resets. */
  sequenceTimeoutMs?: number
  /** Force ⌘ vs Ctrl as `mod` (defaults to platform detection). */
  isMac?: boolean
}

/**
 * Installs the single keydown listener and holds the scope stack. All scopes
 * register through context, so the listener — and the sequence/modal logic —
 * lives in exactly one place.
 */
export function KeyboardScopeProvider({ children, sequenceTimeoutMs = 1200, isMac }: KeyboardScopeProviderProps) {
  const mac = isMac ?? detectMac()
  const scopes = useRef<Map<string, RegisteredScope>>(new Map())
  const pending = useRef<Chord[]>([])
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const registry = useMemo<ScopeRegistry>(
    () => ({
      register: (scope) => scopes.current.set(scope.id, scope),
      unregister: (id) => scopes.current.delete(id),
    }),
    [],
  )

  useEffect(() => {
    function clearPending() {
      pending.current = []
      if (timer.current) {
        clearTimeout(timer.current)
        timer.current = null
      }
    }

    function activeScopes(): RegisteredScope[] {
      const all = [...scopes.current.values()].filter((s) => s.enabled !== false)
      // The topmost modal scope shadows everything below it.
      let floor = -Infinity
      for (const s of all) {
        const modal = s.modal ?? (s.priority >= ScopePriority.tray)
        if (modal && s.priority > floor) floor = s.priority
      }
      return all
        .filter((s) => s.priority >= floor)
        .sort((a, b) => b.priority - a.priority)
    }

    // Match `seqSoFar` against active bindings. Returns 'ran' if a complete
    // binding fired, 'pending' if it is a proper prefix of some longer binding,
    // or 'none'. `editable` restricts to allowInEditable bindings.
    function dispatch(seqSoFar: Chord[], e: KeyboardEvent, editable: boolean): 'ran' | 'pending' | 'none' {
      const ordered = activeScopes()
      // Exact match wins, highest-priority scope first.
      for (const scope of ordered) {
        for (const { binding, seq } of scope.parsed) {
          if (editable && !binding.allowInEditable) continue
          if (sequenceEquals(seq, seqSoFar)) {
            e.preventDefault()
            binding.run(e)
            return 'ran'
          }
        }
      }
      // No exact hit: is this a proper prefix of a longer binding?
      for (const scope of ordered) {
        for (const { binding, seq } of scope.parsed) {
          if (editable && !binding.allowInEditable) continue
          if (seq.length > seqSoFar.length && sequenceStartsWith(seq, seqSoFar)) {
            return 'pending'
          }
        }
      }
      return 'none'
    }

    function onKeyDown(e: KeyboardEvent) {
      const chord = eventChord(e, mac)
      if (isModifierOnly(chord)) return
      const editable = isEditableTarget(e.target)

      // `seq` is the sequence actually being dispatched — it must track the
      // retry below, or a freshly-started sequence would be stored with the
      // dead prefix still attached and could never complete.
      let seq = [...pending.current, chord]
      let result = dispatch(seq, e, editable)

      // A dead sequence (`g` then an unrelated key): drop the prefix and retry
      // the fresh chord on its own, so the new key isn't swallowed.
      if (result === 'none' && pending.current.length > 0) {
        clearPending()
        seq = [chord]
        result = dispatch(seq, e, editable)
      }

      if (result === 'ran') {
        clearPending()
        return
      }
      if (result === 'pending') {
        e.preventDefault()
        pending.current = seq
        if (timer.current) clearTimeout(timer.current)
        timer.current = setTimeout(clearPending, sequenceTimeoutMs)
        return
      }
      // 'none' — nothing matched; ensure no stale prefix lingers.
      clearPending()
    }

    window.addEventListener('keydown', onKeyDown)
    return () => {
      window.removeEventListener('keydown', onKeyDown)
      if (timer.current) clearTimeout(timer.current)
      // Drop any pending prefix so a re-subscribe (mac/timeout change) can't
      // resume a half-typed sequence with no timer left to expire it.
      pending.current = []
    }
  }, [mac, sequenceTimeoutMs])

  return <ScopeRegistryContext.Provider value={registry}>{children}</ScopeRegistryContext.Provider>
}

/**
 * Register a keyboard scope for the lifetime of the calling component. Bindings
 * are re-read on every render (via a ref), so handlers always close over fresh
 * state without re-subscribing. A no-op when rendered outside a provider, so
 * components stay usable in isolation/tests.
 */
export function useKeyboardScope(scope: KeyboardScope): void {
  const registry = useContext(ScopeRegistryContext)
  const generatedId = useId()
  const id = scope.id ?? generatedId

  // Hold the latest scope in a ref so the registered entry reflects current
  // bindings/enabled without churning the registry on every keystroke.
  const latest = useRef(scope)
  latest.current = scope

  useEffect(() => {
    if (!registry) return
    const parsed = () =>
      latest.current.bindings.map((binding) => ({ binding, seq: parseSequence(binding.keys) }))
    // Register a live view: the registry reads `bindings`/`enabled` through
    // getters so updates between renders are visible without re-registering.
    const entry: RegisteredScope = {
      id,
      get level() {
        return latest.current.level
      },
      priority: priorityOf(scope.level),
      get bindings() {
        return latest.current.bindings
      },
      get modal() {
        return latest.current.modal
      },
      get enabled() {
        return latest.current.enabled
      },
      get parsed() {
        return parsed()
      },
    }
    registry.register(entry)
    return () => registry.unregister(id)
    // Re-register only when the id or numeric priority changes; binding/enabled
    // updates flow through the getters above.
  }, [registry, id, priorityOf(scope.level)])
}
