// @apoxy/console-core — YAML tray (APO-777) + write path (APO-778): the editing
// drawer, its editor seam, the YAML round-trip, and the per-kind validation.

export { YamlTray, type YamlTrayProps } from './yaml-tray'
export { CreateProvider, useCreate, type CreateApi, type CreateProviderProps } from './create-context'
export { TextAreaEditor, TrayEditorProvider, useTrayEditor, type TrayEditor, type TrayEditorProps } from './editor'
export { YamlCode, type YamlCodeProps } from './yaml-code'
export { ManifestTray, type ManifestTrayProps } from './manifest-tray'
export { YamlMenu, kubectlApplyCommand, type YamlMenuProps } from './yaml-menu'
export {
  WizardShell,
  type WizardShellProps,
  type WizardFormProps,
  type WizardStep,
  type WizardSubItem,
  type WizardCollection,
} from './wizard-shell'
export {
  FormSection,
  Field,
  TextField,
  SelectField,
  SegField,
  FieldRow,
  type FormSectionProps,
  type FieldProps,
} from '../components/form'
export { forEditing, toYaml, fromYaml, skeleton, type ParseResult } from './yaml-doc'
export {
  validateObject,
  hasBlockingProblems,
  type JSONSchema,
  type JsonType,
  type Problem,
  type Severity,
} from './validate'
