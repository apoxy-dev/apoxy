/**
 * APO-777 — per-kind schema codegen for the YAML tray.
 *
 * Extracts, from the apiserver OpenAPI (the same `console/openapi.json` that
 * drives schema.d.ts), a compact JSON-Schema per resource kind for the tray's
 * advisory validation. We keep only the small subset `@apoxy/console-core`'s
 * validator understands (type/required/enum/bounds/properties/items/
 * additionalProperties/$ref), drop everything else (descriptions, formats,
 * x-kubernetes-*), and validate only `spec` — the structural k8s checks already
 * cover apiVersion/kind/metadata.name, and `status` is stripped before editing.
 *
 * Each kind's schema carries the transitive closure of the sub-schemas its spec
 * `$ref`s reach, in a `$defs` map; the validator resolves refs against it. Output
 * is sorted deterministically so the CI codegen-drift gate stays byte-stable.
 */

const PREFIX = 'com.github.apoxy-dev.apoxy.api.'
const JSON_TYPES = new Set(['string', 'number', 'integer', 'boolean', 'object', 'array', 'null'])

type AnySchema = Record<string, unknown>
type Subset = Record<string, unknown>

export interface OpenAPIDoc {
  components?: { schemas?: Record<string, AnySchema> }
  definitions?: Record<string, AnySchema>
}

function schemasOf(doc: OpenAPIDoc): Record<string, AnySchema> {
  return doc.components?.schemas ?? doc.definitions ?? {}
}

/** Bare schema key from a `#/components/schemas/<key>` (or `#/definitions/<key>`) ref. */
function refKey(ref: string): string {
  return ref.replace(/^#\/(?:components\/schemas|definitions)\//, '')
}

/** Keep only a `type` (or type[]) the validator recognizes; drop the rest. */
function keepType(type: unknown): unknown {
  if (typeof type === 'string') return JSON_TYPES.has(type) ? type : undefined
  if (Array.isArray(type) && type.every((t) => typeof t === 'string' && JSON_TYPES.has(t))) return type
  return undefined
}

/**
 * Convert one OpenAPI node to the validator subset, calling `addRef` for every
 * `$ref` it encounters so the caller can build the `$defs` closure.
 */
function toSubset(node: AnySchema | undefined, addRef: (key: string) => void): Subset {
  if (!node || typeof node !== 'object') return {}
  if (typeof node.$ref === 'string') {
    const key = refKey(node.$ref)
    addRef(key)
    return { $ref: key }
  }
  // Unwrap a single-element allOf (a common `$ref` wrapper some generators emit).
  if (Array.isArray(node.allOf) && node.allOf.length === 1) {
    return toSubset(node.allOf[0] as AnySchema, addRef)
  }

  const out: Subset = {}
  const type = keepType(node.type)
  if (type !== undefined) out.type = type
  if (node.nullable === true) out.nullable = true
  if (Array.isArray(node.enum)) out.enum = node.enum
  for (const k of ['minimum', 'maximum', 'minLength', 'maxLength'] as const) {
    if (typeof node[k] === 'number') out[k] = node[k]
  }
  if (Array.isArray(node.required) && node.required.length > 0) out.required = node.required

  if (node.properties && typeof node.properties === 'object') {
    const props: Record<string, Subset> = {}
    for (const [k, v] of Object.entries(node.properties as Record<string, AnySchema>)) {
      props[k] = toSubset(v, addRef)
    }
    out.properties = props
  }
  if (node.items) out.items = toSubset(node.items as AnySchema, addRef)
  if (node.additionalProperties === false) out.additionalProperties = false
  else if (node.additionalProperties && typeof node.additionalProperties === 'object') {
    out.additionalProperties = toSubset(node.additionalProperties as AnySchema, addRef)
  }
  return out
}

/** Convert `start` and the transitive closure of schemas its `$ref`s reach. */
function withClosure(
  start: AnySchema,
  schemas: Record<string, AnySchema>,
): { root: Subset; defs: Record<string, Subset> } {
  const defs: Record<string, Subset> = {}
  const queue: string[] = []
  const addRef = (key: string) => {
    if (!(key in defs)) {
      defs[key] = {} // placeholder so a ref cycle doesn't re-queue
      queue.push(key)
    }
  }
  const root = toSubset(start, addRef)
  while (queue.length > 0) {
    const key = queue.shift()!
    defs[key] = toSubset(schemas[key], addRef)
  }
  return { root, defs }
}

/** True for a top-level k8s object schema (excludes `…List` collections). */
function isResource(key: string, schema: AnySchema): boolean {
  if (key.endsWith('List')) return false
  const p = schema.properties as Record<string, unknown> | undefined
  return !!p && 'apiVersion' in p && 'kind' in p && 'metadata' in p
}

/** Derive the k8s GVK from an apoxy OpenAPI schema key (`<dir>` → `<dir>.apoxy.dev`). */
function gvkFromKey(key: string): { group: string; version: string; kind: string } | null {
  if (!key.startsWith(PREFIX)) return null
  const rest = key.slice(PREFIX.length).split('.')
  if (rest.length !== 3) return null
  const [dir, version, kind] = rest
  return { group: `${dir}.apoxy.dev`, version, kind }
}

/** Build the `spec`-constraining schema (with `$defs` closure) for one kind. */
function kindSchema(rootKey: string, schemas: Record<string, AnySchema>): Subset {
  const root = schemas[rootKey]
  const props = root.properties as Record<string, AnySchema> | undefined
  const specProp = props?.spec
  if (!specProp) return { type: 'object' }
  const { root: spec, defs } = withClosure(specProp, schemas)
  return { type: 'object', properties: { spec }, $defs: defs }
}

/** A `"group/version/Kind"` → JSON-Schema map for every resource kind in `doc`. */
export function buildResourceSchemas(doc: OpenAPIDoc): Record<string, Subset> {
  const schemas = schemasOf(doc)
  const out: Record<string, Subset> = {}
  for (const key of Object.keys(schemas).sort()) {
    const schema = schemas[key]
    if (!isResource(key, schema)) continue
    const gvk = gvkFromKey(key)
    if (!gvk) continue
    out[`${gvk.group}/${gvk.version}/${gvk.kind}`] = kindSchema(key, schemas)
  }
  return out
}

/** Recursively sort object keys (arrays kept in order) for byte-stable output. */
function sortDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortDeep)
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {}
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = sortDeep((v as Record<string, unknown>)[k])
    }
    return out
  }
  return v
}

const BANNER =
  '// GENERATED by console/scripts/generate-schema.ts (openapi → tray schemas) — do not edit by hand.\n'

/** Render the `resource-schemas.ts` module source for `doc`. */
export function emitResourceSchemasModule(doc: OpenAPIDoc): string {
  const map = sortDeep(buildResourceSchemas(doc))
  const literal = JSON.stringify(map, null, 2)
  return (
    BANNER +
    "import type { JSONSchema } from '@apoxy/console-core'\n\n" +
    `export const RESOURCE_SCHEMAS: Record<string, JSONSchema> = ${literal}\n`
  )
}
