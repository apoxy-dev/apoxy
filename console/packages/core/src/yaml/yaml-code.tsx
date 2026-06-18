// Read-only YAML renderer (the design's `.yaml-code`): a borderless, line-
// numbered block with a fixed 46px gutter and light per-line syntax tinting
// (keys, values, punctuation, list dashes, doc separators). The single vertical
// rule is the gutter's right hairline — no card border — so it never reads as a
// box-in-box, and the fixed gutter means the text never shifts when line numbers
// cross 9 → 10. Used by the manifest viewer and the wizard's live preview; the
// editable surface is the CodeMirror/textarea editor, not this.

import { useMemo, type ReactNode } from 'react'

export interface YamlCodeProps {
  text: string
}

export function YamlCode({ text }: YamlCodeProps) {
  const lines = useMemo(() => text.split('\n'), [text])
  return (
    <pre className="m-0 py-[var(--yaml-block-pad)] font-mono text-[length:var(--t-caption)] leading-[var(--yaml-line-h)]">
      {lines.map((ln, i) => (
        <div key={i} className="flex items-baseline hover:bg-[var(--apx-bone)]">
          <span className="w-[var(--yaml-gutter-w)] flex-none select-none border-r border-[color:var(--border-subtle)] pr-[var(--yaml-gutter-gap)] text-right text-[length:var(--t-micro)] text-[color:var(--text-disabled)]">
            {i + 1}
          </span>
          <code className="flex-1 whitespace-pre-wrap break-words pl-[var(--yaml-text-pad)] text-[color:var(--text-secondary)]">
            {colorLine(ln)}
          </code>
        </div>
      ))}
    </pre>
  )
}

/** Lightweight per-line tinting: doc separators, list dashes, and `key: value`. */
function colorLine(ln: string): ReactNode {
  if (ln === '---') return <span className="tracking-[0.1em] text-[color:var(--text-disabled)]">---</span>
  const m = /^(\s*)(-\s+)?(.*)$/.exec(ln)
  if (!m) return ln
  const indent = m[1] ?? ''
  const dash = m[2] ?? ''
  const rest = m[3] ?? ''
  const kv = /^([A-Za-z0-9_.\-/[\]]+)(:)(\s*)(.*)$/.exec(rest)
  if (kv) {
    return (
      <>
        {indent}
        {dash && <span className="text-[color:var(--apx-stone)]">{dash}</span>}
        <span className="font-medium text-[color:var(--text-primary)]">{kv[1]}</span>
        <span className="text-[color:var(--text-disabled)]">{kv[2]}</span>
        {kv[3]}
        {kv[4] && <span className="text-[color:var(--apx-blue-deep)]">{kv[4]}</span>}
      </>
    )
  }
  return (
    <>
      {indent}
      {dash && <span className="text-[color:var(--apx-stone)]">{dash}</span>}
      <span className="text-[color:var(--apx-blue-deep)]">{rest}</span>
    </>
  )
}
