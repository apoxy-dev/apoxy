import { describe, expect, it } from 'vitest'
import type { JSONSchema } from '@apoxy/console-core'
import { completeYaml } from './yaml-completion'

// A schema shaped like the generated per-kind ones: a whole-object root carrying
// `$defs`, with `spec` a `$ref` into them (bare def keys, no `#/` prefix).
const schema: JSONSchema = {
  type: 'object',
  $defs: {
    Spec: {
      type: 'object',
      required: ['mode'],
      properties: {
        mode: { type: 'string', enum: ['http', 'tcp'] },
        enabled: { type: 'boolean' },
        replicas: { type: 'integer' },
        listener: { $ref: 'Listener' },
        rules: { type: 'array', items: { $ref: 'Rule' } },
      },
    },
    Listener: {
      type: 'object',
      properties: { port: { type: 'integer' }, protocol: { type: 'string', enum: ['TCP', 'UDP'] } },
    },
    Rule: { type: 'object', properties: { name: { type: 'string' }, weight: { type: 'integer' } } },
  },
  properties: { spec: { $ref: 'Spec' } },
}

/** Place the cursor at the `|` marker; returns the cleaned text + offset. */
function at(doc: string): { text: string; pos: number } {
  const pos = doc.indexOf('|')
  return { text: doc.slice(0, pos) + doc.slice(pos + 1), pos }
}

function labels(doc: string, root: JSONSchema | undefined = schema): string[] {
  const { text, pos } = at(doc)
  return completeYaml(text, pos, root)?.suggestions.map((s) => s.label) ?? []
}

describe('completeYaml — keys', () => {
  it('offers the k8s envelope keys at the root', () => {
    expect(labels('|')).toEqual(expect.arrayContaining(['apiVersion', 'kind', 'metadata', 'spec']))
  })

  it('resolves $ref to offer spec properties under `spec:`', () => {
    const got = labels('spec:\n  |')
    expect(got).toEqual(expect.arrayContaining(['mode', 'enabled', 'replicas', 'listener', 'rules']))
    expect(got).not.toContain('apiVersion') // not the root container
  })

  it('marks required properties', () => {
    const { text, pos } = at('spec:\n  |')
    const mode = completeYaml(text, pos, schema)!.suggestions.find((s) => s.label === 'mode')
    expect(mode?.detail).toBe('required')
  })

  it('descends through a nested object', () => {
    expect(labels('spec:\n  listener:\n    |')).toEqual(expect.arrayContaining(['port', 'protocol']))
  })

  it('offers item properties inside an array element (`- `)', () => {
    expect(labels('spec:\n  rules:\n    - |')).toEqual(expect.arrayContaining(['name', 'weight']))
  })

  it('drops keys already present as siblings', () => {
    const got = labels('spec:\n  mode: http\n  |')
    expect(got).toContain('replicas')
    expect(got).not.toContain('mode')
  })

  it('still offers envelope keys at the root with no schema', () => {
    expect(labels('|', undefined)).toEqual(expect.arrayContaining(['apiVersion', 'kind', 'metadata', 'spec']))
  })
})

describe('completeYaml — values', () => {
  it('offers enum values after `key: `', () => {
    expect(labels('spec:\n  mode: |')).toEqual(['http', 'tcp'])
  })

  it('offers true/false for a boolean field', () => {
    expect(labels('spec:\n  enabled: |')).toEqual(['true', 'false'])
  })

  it('offers enum values for a nested field', () => {
    expect(labels('spec:\n  listener:\n    protocol: |')).toEqual(['TCP', 'UDP'])
  })

  it('replaces only the typed value token', () => {
    const { text, pos } = at('spec:\n  mode: ht|')
    const res = completeYaml(text, pos, schema)!
    // `from` points at the start of `ht`, so accepting replaces just the value.
    expect(text.slice(res.from, res.to)).toBe('ht')
    expect(res.suggestions.map((s) => s.label)).toEqual(['http', 'tcp'])
  })

  it('offers nothing for a free scalar (no enum/boolean)', () => {
    const { text, pos } = at('spec:\n  replicas: |')
    expect(completeYaml(text, pos, schema)).toBeNull()
  })
})

describe('completeYaml — non-completable positions', () => {
  it('returns null mid-key before the value space', () => {
    const { text, pos } = at('spec:\n  mode:|')
    expect(completeYaml(text, pos, schema)).toBeNull()
  })
})
