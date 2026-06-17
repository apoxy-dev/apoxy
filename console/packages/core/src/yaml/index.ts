// @apoxy/console-core — YAML tray (APO-777) + write path (APO-778): the editing
// drawer, its editor seam, the YAML round-trip, and the per-kind validation.

export { YamlTray, type YamlTrayProps } from './yaml-tray'
export { TextAreaEditor, type TrayEditor, type TrayEditorProps } from './editor'
export { forEditing, toYaml, fromYaml, skeleton, type ParseResult } from './yaml-doc'
export {
  validateObject,
  hasBlockingProblems,
  type JSONSchema,
  type JsonType,
  type Problem,
  type Severity,
} from './validate'
