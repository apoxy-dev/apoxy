// The editor the app installs into console-core's YAML tray. CodeMirror is heavy
// (~145 kB gzip) and only needed once a tray is actually opened, so it's
// lazy-loaded; the dependency-free TextAreaEditor covers the brief import and
// any environment where the chunk can't load.

import { lazy, Suspense } from 'react'
import { TextAreaEditor, type TrayEditorProps } from '@apoxy/console-core'

const CodeMirrorEditor = lazy(() =>
  import('./codemirror-editor').then((m) => ({ default: m.CodeMirrorEditor })),
)

export function TrayEditor(props: TrayEditorProps) {
  return (
    <Suspense fallback={<TextAreaEditor {...props} />}>
      <CodeMirrorEditor {...props} />
    </Suspense>
  )
}
