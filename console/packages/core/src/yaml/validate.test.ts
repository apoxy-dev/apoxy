import { describe, expect, it } from 'vitest'
import { hasBlockingProblems, validateObject, type JSONSchema } from './validate'

const ok = { apiVersion: 'core.apoxy.dev/v1alpha2', kind: 'Proxy', metadata: { name: 'p1' } }

describe('structural k8s checks (always on)', () => {
  it('passes a well-formed object', () => {
    expect(validateObject(ok)).toEqual([])
  })
  it('flags a non-object document', () => {
    const p = validateObject('nope')
    expect(p).toHaveLength(1)
    expect(p[0]!.severity).toBe('error')
  })
  it('requires apiVersion, kind, and metadata.name', () => {
    const p = validateObject({ metadata: {} })
    const paths = p.map((x) => x.path)
    expect(paths).toContain('.apiVersion')
    expect(paths).toContain('.kind')
    expect(paths).toContain('.metadata.name')
  })
  it('flags an empty name', () => {
    const p = validateObject({ ...ok, metadata: { name: '' } })
    expect(p.some((x) => x.path === '.metadata.name')).toBe(true)
  })
})

describe('schema validation (optional)', () => {
  const schema: JSONSchema = {
    type: 'object',
    properties: {
      apiVersion: { type: 'string' },
      kind: { type: 'string' },
      metadata: { type: 'object' },
      spec: {
        type: 'object',
        required: ['replicas'],
        additionalProperties: false,
        properties: {
          replicas: { type: 'integer', minimum: 1, maximum: 9 },
          mode: { type: 'string', enum: ['edge', 'mesh'] },
        },
      },
    },
  }

  it('accepts a valid spec', () => {
    expect(validateObject({ ...ok, spec: { replicas: 3, mode: 'edge' } }, schema)).toEqual([])
  })
  it('flags a type mismatch', () => {
    const p = validateObject({ ...ok, spec: { replicas: 'three' } }, schema)
    expect(p.some((x) => x.path === '.spec.replicas' && /integer/.test(x.message))).toBe(true)
  })
  it('flags a missing required property', () => {
    const p = validateObject({ ...ok, spec: {} }, schema)
    expect(p.some((x) => x.path === '.spec.replicas' && /required/.test(x.message))).toBe(true)
  })
  it('flags an out-of-range number', () => {
    const p = validateObject({ ...ok, spec: { replicas: 99 } }, schema)
    expect(p.some((x) => /≤ 9/.test(x.message))).toBe(true)
  })
  it('flags an enum violation', () => {
    const p = validateObject({ ...ok, spec: { replicas: 1, mode: 'spaceship' } }, schema)
    expect(p.some((x) => x.path === '.spec.mode' && /one of/.test(x.message))).toBe(true)
  })
  it('warns (not errors) on an unknown field under additionalProperties:false', () => {
    const p = validateObject({ ...ok, spec: { replicas: 1, bogus: true } }, schema)
    const unknown = p.find((x) => x.path === '.spec.bogus')
    expect(unknown?.severity).toBe('warning')
    expect(hasBlockingProblems(p)).toBe(false)
  })
  it('accepts null when nullable', () => {
    const s: JSONSchema = { type: 'object', properties: { x: { type: 'string', nullable: true } } }
    expect(validateObject({ ...ok, x: null }, s)).toEqual([])
  })
  it('validates array items', () => {
    const s: JSONSchema = { type: 'object', properties: { tags: { type: 'array', items: { type: 'string' } } } }
    const p = validateObject({ ...ok, tags: ['a', 2] }, s)
    expect(p.some((x) => x.path === '.tags[1]')).toBe(true)
  })
})

describe('hasBlockingProblems', () => {
  it('is true only for error-severity problems', () => {
    expect(hasBlockingProblems([{ path: '', message: 'x', severity: 'warning' }])).toBe(false)
    expect(hasBlockingProblems([{ path: '', message: 'x', severity: 'error' }])).toBe(true)
  })
})
