// @apoxy/console-core — keyboard navigation (APO-779/780): the scope stack,
// chord/sequence parsing, list + Miller selection cursors, and virtualization
// math. Pure logic and DOM-free helpers, so the movement rules are unit-tested
// directly and the same primitives back the table, the palette, and the tray.

export {
  KeyboardScopeProvider,
  useKeyboardScope,
  ScopePriority,
  type KeyboardScopeProviderProps,
  type KeyboardScope,
  type KeyBinding,
  type ScopeLevel,
} from './scope-stack'

export {
  parseChord,
  parseSequence,
  eventChord,
  chordEquals,
  sequenceEquals,
  sequenceStartsWith,
  formatChord,
  formatSequence,
  isEditableTarget,
  detectMac,
  type Chord,
} from './keys'

export {
  useListSelection,
  useMillerSelection,
  nextIndex,
  moveMiller,
  type ListSelection,
  type MillerSelection,
  type MillerCursor,
  type UseListSelectionOptions,
  type UseMillerSelectionOptions,
} from './selection'

export { computeWindow, type WindowInput, type WindowResult } from './windowing'
