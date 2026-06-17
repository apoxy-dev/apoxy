// Key-chord parsing + matching for the keyboard scope stack (APO-779). A chord
// is one keypress with modifiers (`mod+k`, `shift+enter`, `escape`, `j`, `?`);
// a binding may be a SEQUENCE of chords (`g i`) for Linear-style g-navigation.
// `mod` is the platform's primary modifier — ⌘ on macOS, Ctrl elsewhere — so a
// single binding spec works on both. Pure and DOM-free except {@link eventChord}.

/** One normalized keypress: a base key plus modifier flags. */
export interface Chord {
  /** Lowercased key: a character (`k`, `?`) or a named key (`escape`, `arrowup`, `enter`). */
  key: string
  /** The platform primary modifier (⌘ on mac, Ctrl elsewhere). */
  mod: boolean
  shift: boolean
  alt: boolean
}

/** Aliases so specs can read naturally; normalized to the canonical key name. */
const KEY_ALIASES: Record<string, string> = {
  esc: 'escape',
  up: 'arrowup',
  down: 'arrowdown',
  left: 'arrowleft',
  right: 'arrowright',
  return: 'enter',
  space: ' ',
  spacebar: ' ',
}

function normalizeKey(raw: string): string {
  const k = raw.toLowerCase()
  return KEY_ALIASES[k] ?? k
}

/** Parse one chord token like `mod+shift+k` into a {@link Chord}. */
export function parseChord(token: string): Chord {
  const parts = token
    .trim()
    .split('+')
    .map((p) => p.trim())
    .filter(Boolean)
  const chord: Chord = { key: '', mod: false, shift: false, alt: false }
  for (const part of parts) {
    const p = part.toLowerCase()
    if (p === 'mod' || p === 'cmd' || p === 'ctrl' || p === 'control' || p === 'meta') chord.mod = true
    else if (p === 'shift') chord.shift = true
    else if (p === 'alt' || p === 'option' || p === 'opt') chord.alt = true
    else chord.key = normalizeKey(part)
  }
  return chord
}

/**
 * Parse a binding spec into its sequence of chords. Space-separated tokens are
 * a sequence (`g i`); `+`-joined tokens are one chord (`mod+k`). A literal
 * space chord is written as `space`.
 */
export function parseSequence(spec: string): Chord[] {
  return spec
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map(parseChord)
}

/** The chord a keyboard event represents. `mod` reads ⌘ on mac, Ctrl elsewhere. */
export function eventChord(e: KeyboardEvent, isMac = detectMac()): Chord {
  return {
    key: normalizeKey(e.key),
    mod: isMac ? e.metaKey : e.ctrlKey,
    shift: e.shiftKey,
    alt: e.altKey,
  }
}

/** True when the platform's primary modifier is ⌘ (so specs map to the right key). */
export function detectMac(): boolean {
  const nav = typeof navigator !== 'undefined' ? navigator : undefined
  // `platform` is deprecated but still the most reliable mac signal; fall back
  // to the UA. Defaults to false (Ctrl) when neither is available (e.g. SSR).
  const probe = `${nav?.platform ?? ''} ${nav?.userAgent ?? ''}`.toLowerCase()
  return /mac|iphone|ipad|ipod/.test(probe)
}

export function chordEquals(a: Chord, b: Chord): boolean {
  return a.key === b.key && a.mod === b.mod && a.shift === b.shift && a.alt === b.alt
}

/** True when `seq` starts with `prefix` (used to detect a pending g-sequence). */
export function sequenceStartsWith(seq: Chord[], prefix: Chord[]): boolean {
  if (prefix.length > seq.length) return false
  for (let i = 0; i < prefix.length; i++) {
    // i < prefix.length <= seq.length, so both are defined.
    if (!chordEquals(seq[i]!, prefix[i]!)) return false
  }
  return true
}

export function sequenceEquals(a: Chord[], b: Chord[]): boolean {
  return a.length === b.length && sequenceStartsWith(a, b)
}

/** A chord that is purely a modifier press (no base key yet) — never a binding. */
export function isModifierOnly(chord: Chord): boolean {
  return chord.key === '' || chord.key === 'shift' || chord.key === 'control' || chord.key === 'meta' || chord.key === 'alt'
}

const DISPLAY_KEYS: Record<string, string> = {
  escape: 'Esc',
  enter: '↵',
  arrowup: '↑',
  arrowdown: '↓',
  arrowleft: '←',
  arrowright: '→',
  ' ': 'Space',
}

/** Human-readable chord for help/menus (`⌘K`, `g then i`). */
export function formatChord(chord: Chord, isMac = detectMac()): string {
  const parts: string[] = []
  if (chord.mod) parts.push(isMac ? '⌘' : 'Ctrl')
  if (chord.alt) parts.push(isMac ? '⌥' : 'Alt')
  if (chord.shift) parts.push('⇧')
  const key = DISPLAY_KEYS[chord.key] ?? (chord.key.length === 1 ? chord.key.toUpperCase() : capitalize(chord.key))
  parts.push(key)
  return parts.join(isMac ? '' : '+')
}

export function formatSequence(seq: Chord[], isMac = detectMac()): string {
  return seq.map((c) => formatChord(c, isMac)).join(' then ')
}

function capitalize(s: string): string {
  return s ? s[0]!.toUpperCase() + s.slice(1) : s
}

/**
 * Whether an event target is a text-entry surface (input, textarea, select,
 * contenteditable). Single-key bindings (`j`, `g`) are suppressed while typing;
 * only `mod`-combos and `escape` reach the scope stack from these targets.
 */
export function isEditableTarget(target: EventTarget | null): boolean {
  if (!target || !(target instanceof Element)) return false
  const el = target as HTMLElement
  const tag = el.tagName
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true
  // `isContentEditable` is `undefined` on non-editable elements in some DOM
  // implementations (jsdom); coerce so the result is always a boolean.
  return el.isContentEditable === true
}
