// Per-kind validation for the YAML tray (APO-777). Two layers:
//   1. Always-on k8s structural checks — apiVersion/kind/metadata.name must be
//      present and well-typed, since Server-Side Apply rejects an object without
//      them. These run with or without a schema.
//   2. An optional compact JSON-Schema check against `entry.schema` (a subset:
//      type, required, properties, items, enum, additionalProperties, and the
//      common numeric/string bounds). The apiserver remains the real authority;
//      this is fast editor feedback, so it is advisory and never blocks beyond
//      the structural errors.
// Kept dependency-free and synchronous so it runs on every keystroke.

/** The JSON-Schema subset the tray understands. Unknown keywords are ignored. */
export interface JSONSchema {
  type?: JsonType | JsonType[]
  properties?: Record<string, JSONSchema>
  required?: string[]
  items?: JSONSchema
  enum?: unknown[]
  additionalProperties?: boolean | JSONSchema
  minimum?: number
  maximum?: number
  minLength?: number
  maxLength?: number
  /** OpenAPI/k8s nullable flag — when true, `null` is accepted for any type. */
  nullable?: boolean
}

export type JsonType = 'string' | 'number' | 'integer' | 'boolean' | 'object' | 'array' | 'null'

export type Severity = 'error' | 'warning'

export interface Problem {
  /** JSON-path-ish location, e.g. `.spec.replicas` or `` (root). */
  path: string
  message: string
  severity: Severity
}

/** True when there is at least one blocking (error-severity) problem. */
export function hasBlockingProblems(problems: Problem[]): boolean {
  return problems.some((p) => p.severity === 'error')
}

/** Validate a parsed object: always-on structural checks plus optional schema. */
export function validateObject(value: unknown, schema?: JSONSchema): Problem[] {
  const problems: Problem[] = []
  structuralChecks(value, problems)
  if (schema && isPlainObject(value)) validateAgainstSchema(value, schema, '', problems)
  return problems
}

/** The k8s identity fields Server-Side Apply requires, checked unconditionally. */
function structuralChecks(value: unknown, problems: Problem[]): void {
  if (!isPlainObject(value)) {
    problems.push({ path: '', message: 'Document must be a mapping (an object).', severity: 'error' })
    return
  }
  requireString(value, 'apiVersion', problems)
  requireString(value, 'kind', problems)

  const meta = value.metadata
  if (meta === undefined) {
    problems.push({ path: '.metadata', message: 'metadata is required.', severity: 'error' })
  } else if (!isPlainObject(meta)) {
    problems.push({ path: '.metadata', message: 'metadata must be a mapping.', severity: 'error' })
  } else {
    const name = meta.name
    if (name === undefined || name === '') {
      problems.push({ path: '.metadata.name', message: 'metadata.name is required.', severity: 'error' })
    } else if (typeof name !== 'string') {
      problems.push({ path: '.metadata.name', message: 'metadata.name must be a string.', severity: 'error' })
    }
  }
}

function requireString(obj: Record<string, unknown>, key: string, problems: Problem[]): void {
  const v = obj[key]
  if (v === undefined || v === '') {
    problems.push({ path: `.${key}`, message: `${key} is required.`, severity: 'error' })
  } else if (typeof v !== 'string') {
    problems.push({ path: `.${key}`, message: `${key} must be a string.`, severity: 'error' })
  }
}

function validateAgainstSchema(value: unknown, schema: JSONSchema, path: string, problems: Problem[]): void {
  if (value === null) {
    if (schema.nullable || matchesType(null, schema.type)) return
    if (schema.type) problems.push({ path, message: `Expected ${typeName(schema.type)}, got null.`, severity: 'error' })
    return
  }

  if (schema.type && !matchesType(value, schema.type)) {
    problems.push({ path, message: `Expected ${typeName(schema.type)}, got ${jsTypeOf(value)}.`, severity: 'error' })
    return // a type mismatch makes deeper checks meaningless
  }

  if (schema.enum && !schema.enum.some((e) => deepEqualScalar(e, value))) {
    problems.push({ path, message: `Must be one of: ${schema.enum.map(String).join(', ')}.`, severity: 'error' })
  }

  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) {
      problems.push({ path, message: `Must be ≥ ${schema.minimum}.`, severity: 'error' })
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      problems.push({ path, message: `Must be ≤ ${schema.maximum}.`, severity: 'error' })
    }
  }

  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      problems.push({ path, message: `Must be at least ${schema.minLength} characters.`, severity: 'error' })
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      problems.push({ path, message: `Must be at most ${schema.maxLength} characters.`, severity: 'error' })
    }
  }

  if (isPlainObject(value)) {
    for (const key of schema.required ?? []) {
      if (value[key] === undefined) {
        problems.push({ path: `${path}.${key}`, message: `${key} is required.`, severity: 'error' })
      }
    }
    const props = schema.properties ?? {}
    for (const [key, child] of Object.entries(value)) {
      const sub = props[key]
      if (sub) {
        validateAgainstSchema(child, sub, `${path}.${key}`, problems)
      } else if (schema.additionalProperties === false) {
        // Unknown field is a warning, not an error: schemas can lag the server,
        // and the apiserver — not the console — is the authority on rejection.
        problems.push({ path: `${path}.${key}`, message: `Unknown field "${key}".`, severity: 'warning' })
      } else if (isSchema(schema.additionalProperties)) {
        validateAgainstSchema(child, schema.additionalProperties, `${path}.${key}`, problems)
      }
    }
  }

  if (Array.isArray(value) && schema.items) {
    value.forEach((item, i) => validateAgainstSchema(item, schema.items as JSONSchema, `${path}[${i}]`, problems))
  }
}

// --- type helpers -----------------------------------------------------------

function matchesType(value: unknown, type: JSONSchema['type']): boolean {
  if (!type) return true
  const types = Array.isArray(type) ? type : [type]
  return types.some((t) => matchesOne(value, t))
}

function matchesOne(value: unknown, t: JsonType): boolean {
  switch (t) {
    case 'string':
      return typeof value === 'string'
    case 'boolean':
      return typeof value === 'boolean'
    case 'number':
      return typeof value === 'number'
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value)
    case 'object':
      return isPlainObject(value)
    case 'array':
      return Array.isArray(value)
    case 'null':
      return value === null
  }
}

function typeName(type: JSONSchema['type']): string {
  return Array.isArray(type) ? type.join(' | ') : String(type)
}

function jsTypeOf(value: unknown): string {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  return typeof value
}

function deepEqualScalar(a: unknown, b: unknown): boolean {
  return a === b
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isSchema(v: boolean | JSONSchema | undefined): v is JSONSchema {
  return typeof v === 'object' && v !== null
}
