// @apoxy/console-core — command palette (APO-781): the command model, the
// registry-fed command builder, the pure filter/rank, and the ⌘K overlay.

export {
  buildResourceCommands,
  filterCommands,
  scoreCommand,
  isSubsequence,
  type Command,
  type BuildResourceCommandsOptions,
  type ScoredCommand,
} from './commands'

export { useCommandKeyBindings, type UseCommandKeyBindingsOptions } from './command-bindings'

export { CommandPalette, type CommandPaletteProps } from './command-palette'
