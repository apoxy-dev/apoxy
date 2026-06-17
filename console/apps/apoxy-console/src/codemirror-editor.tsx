// A CodeMirror-6 implementation of console-core's TrayEditor seam (APO-777): the
// production swap for the dependency-free TextAreaEditor, adding YAML syntax
// highlighting, a lint gutter (parse errors), and schema-aware completion (keys +
// enum/boolean values from the focused kind's JSON Schema). It's browser-only —
// CodeMirror can't render in jsdom — so it lives in the app and is installed once
// via <TrayEditorProvider>; tests and SSR fall back to the textarea. The pure
// completion resolver in ./schema/yaml-completion is unit-tested on its own.
//
// We compose a curated extension set rather than `basicSetup` so the editor wears
// the Apoxy design, not CodeMirror's defaults: no stock blue active-line band, no
// stock highlight palette. Both the theme and the syntax colors are driven by the
// design tokens (var(--apx-*) / var(--text-*)), so the editor flips with the
// app's light/dark theme for free — never a hardcoded hex.

import { useEffect, useRef } from 'react'
import { EditorState, Compartment } from '@codemirror/state'
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, drawSelection } from '@codemirror/view'
import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands'
import { syntaxHighlighting, HighlightStyle, indentOnInput, bracketMatching } from '@codemirror/language'
import { autocompletion, completionKeymap, type CompletionContext, type CompletionResult } from '@codemirror/autocomplete'
import { yaml } from '@codemirror/lang-yaml'
import { linter, lintGutter, type Diagnostic } from '@codemirror/lint'
import { tags as t } from '@lezer/highlight'
import { parseDocument } from 'yaml'
import type { JSONSchema, TrayEditorProps } from '@apoxy/console-core'
import { completeYaml } from './schema/yaml-completion'

// Surface YAML *syntax* errors in the lint gutter. Schema and structural problems
// are shown in the tray's own problem list below the editor; this is the
// editor-native parse feedback the textarea couldn't give.
const yamlLinter = linter((view): Diagnostic[] => {
  const text = view.state.doc.toString()
  const len = text.length
  const doc = parseDocument(text, { prettyErrors: false })
  return doc.errors.map((err) => {
    const [from, to] = err.pos
    return {
      from: Math.min(from, len),
      to: Math.min(Math.max(to, from + 1), len),
      severity: 'error',
      message: err.message,
    }
  })
})

// Schema-aware completion source: keys (from the kind's `properties`) and
// enum/boolean values, computed by the pure resolver. The active kind's schema is
// read live through `getSchema()` so the create tray — which reuses one editor
// across kinds — always completes against the current kind, not the first opened.
function schemaCompletion(getSchema: () => JSONSchema | undefined) {
  return (ctx: CompletionContext): CompletionResult | null => {
    const result = completeYaml(ctx.state.doc.toString(), ctx.pos, getSchema())
    if (!result || result.suggestions.length === 0) return null
    return {
      from: result.from,
      to: result.to,
      // Keep the same list open while the user types more of the token.
      validFor: /^[\w.\-/]*$/,
      options: result.suggestions.map((s) => ({
        label: s.label,
        type: s.kind === 'value' ? 'constant' : 'property',
        detail: s.detail,
      })),
    }
  }
}

// Syntax palette, keyed off the real @lezer/yaml node tags. Restrained and
// on-brand: keys carry the single blue accent, quoted strings the success green,
// everything structural (punctuation, separators, doc markers) recedes to muted —
// so a spec reads as mostly ink-on-paper, not a rainbow.
const apoxyHighlight = HighlightStyle.define([
  { tag: t.definition(t.propertyName), color: 'var(--apx-blue-deep)', fontWeight: '500' }, // mapping keys
  { tag: t.content, color: 'var(--text-primary)' }, // plain scalar values
  { tag: t.string, color: 'var(--apx-leaf)' }, // quoted strings
  { tag: [t.comment, t.lineComment], color: 'var(--text-muted)', fontStyle: 'italic' },
  { tag: [t.typeName, t.keyword], color: 'var(--apx-blue)' }, // !!tags, %directives
  { tag: t.labelName, color: 'var(--apx-amber)' }, // &anchors / *aliases
  { tag: [t.meta, t.attributeValue], color: 'var(--text-muted)' }, // --- doc markers
  { tag: [t.punctuation, t.separator, t.brace, t.squareBracket], color: 'var(--text-muted)' },
  { tag: t.invalid, color: 'var(--apx-coral)' },
])

const editorTheme = EditorView.theme({
  '&': {
    height: '100%',
    fontSize: 'var(--t-micro)',
    backgroundColor: 'var(--apx-white)',
    color: 'var(--text-primary)',
  },
  '.cm-scroller': {
    overflow: 'auto',
    fontFamily: 'var(--font-mono)',
    lineHeight: 'var(--lh-snug)',
  },
  '.cm-content': {
    padding: 'var(--sp-3) 0',
    caretColor: 'var(--apx-ink)',
  },
  '.cm-line': { padding: '0 var(--sp-4)' },
  '&.cm-focused': { outline: 'none' },
  '.cm-cursor, .cm-dropCursor': { borderLeftColor: 'var(--apx-ink)' },
  // Selection in the design's informational blue tint, focused or not (drawSelection
  // renders its own layer, so the native ::selection gray never shows through).
  '.cm-selectionBackground, &.cm-focused .cm-selectionBackground': {
    backgroundColor: 'var(--apx-blue-tint)',
  },
  // Kill CodeMirror's default sky-blue active-line band; a 4% ink wash is enough
  // to track the caret without shouting (and flips with the theme via --apx-ink).
  '.cm-activeLine': { backgroundColor: 'color-mix(in srgb, var(--apx-ink) 4%, transparent)' },
  '.cm-activeLineGutter': { backgroundColor: 'transparent', color: 'var(--text-primary)' },
  // Gutter: warm inset surface, hairline divider, de-emphasized numbers — matches
  // the TextAreaEditor fallback so the two read as the same editor.
  '.cm-gutters': {
    backgroundColor: 'var(--apx-mist)',
    color: 'var(--text-muted)',
    border: 'none',
    borderRight: '1px solid var(--border-subtle)',
  },
  '.cm-lineNumbers .cm-gutterElement': { padding: '0 var(--sp-2) 0 var(--sp-3)' },
  '.cm-matchingBracket': { backgroundColor: 'var(--apx-blue-tint)', outline: 'none' },
  // Completion dropdown: dress CodeMirror's default (a stock bright-blue list) in
  // the design — a paper card, 0px radius, hairline border, mono type — so it
  // reads like the command palette, not a foreign widget. All token-driven, so it
  // flips with the light/dark theme.
  '.cm-tooltip.cm-tooltip-autocomplete': {
    border: '1px solid var(--border-default)',
    borderRadius: '0',
    backgroundColor: 'var(--surface-card)',
    boxShadow: 'var(--sh-4)',
  },
  '.cm-tooltip-autocomplete > ul': {
    fontFamily: 'var(--font-mono)',
    fontSize: 'var(--t-micro)',
    maxHeight: '14em',
  },
  '.cm-tooltip-autocomplete > ul > li': {
    padding: '2px var(--sp-3)',
    color: 'var(--text-primary)',
    lineHeight: 'var(--lh-snug)',
  },
  '.cm-tooltip-autocomplete > ul > li[aria-selected]': {
    backgroundColor: 'var(--apx-blue-tint)',
    color: 'var(--apx-blue-deep)',
  },
  // Matched portion: the design's blue accent + weight instead of the default
  // underline; detail (e.g. "required") recedes to muted, upright not italic.
  '.cm-completionMatchedText': {
    textDecoration: 'none',
    color: 'var(--apx-blue-deep)',
    fontWeight: '600',
  },
  '.cm-completionDetail': {
    color: 'var(--text-muted)',
    fontStyle: 'normal',
    marginLeft: 'var(--sp-2)',
  },
  // The leading type glyph (property vs value): keep it, just de-emphasized.
  '.cm-completionIcon': { color: 'var(--text-muted)', opacity: '0.7', paddingRight: 'var(--sp-2)' },
})

export function CodeMirrorEditor({ value, onChange, readOnly, schema, ariaLabel = 'YAML editor' }: TrayEditorProps) {
  const host = useRef<HTMLDivElement | null>(null)
  const view = useRef<EditorView | null>(null)
  const readOnlyComp = useRef(new Compartment())
  // Keep the latest onChange callable without recreating the view each render.
  const onChangeRef = useRef(onChange)
  onChangeRef.current = onChange
  // Likewise the active schema, so the completion source (built once at view
  // creation) always sees the current kind's schema even as the prop changes.
  const schemaRef = useRef<JSONSchema | undefined>(schema)
  schemaRef.current = schema

  // Create the editor once; value/readOnly/ariaLabel are synced by the effects
  // below so an in-flight edit (and the cursor) is never torn down.
  useEffect(() => {
    if (!host.current) return
    const listener = EditorView.updateListener.of((u) => {
      if (u.docChanged) onChangeRef.current(u.state.doc.toString())
    })
    const state = EditorState.create({
      doc: value,
      extensions: [
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightActiveLine(),
        history(),
        drawSelection(),
        indentOnInput(),
        bracketMatching(),
        syntaxHighlighting(apoxyHighlight),
        yaml(),
        lintGutter(),
        yamlLinter,
        autocompletion({ override: [schemaCompletion(() => schemaRef.current)] }),
        // completionKeymap first so Enter/Tab accept an open completion, falling
        // through to newline/indent when the tooltip is closed.
        keymap.of([...completionKeymap, ...defaultKeymap, ...historyKeymap, indentWithTab]),
        editorTheme,
        readOnlyComp.current.of(EditorState.readOnly.of(!!readOnly)),
        listener,
      ],
    })
    const v = new EditorView({ state, parent: host.current })
    v.contentDOM.setAttribute('aria-label', ariaLabel)
    view.current = v
    return () => {
      v.destroy()
      view.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- create once.
  }, [])

  // Push external value changes (baseline reset, reload-from-server) into the
  // doc, but skip when the text already matches — the common case where our own
  // edit round-tripped back through props — so the cursor isn't disturbed.
  useEffect(() => {
    const v = view.current
    if (!v) return
    const current = v.state.doc.toString()
    if (current !== value) {
      v.dispatch({ changes: { from: 0, to: current.length, insert: value } })
    }
  }, [value])

  useEffect(() => {
    view.current?.dispatch({
      effects: readOnlyComp.current.reconfigure(EditorState.readOnly.of(!!readOnly)),
    })
  }, [readOnly])

  return (
    <div
      ref={host}
      className="min-h-0 flex-1 overflow-hidden border border-[color:var(--border-default)] bg-[var(--apx-white)]"
    />
  )
}
