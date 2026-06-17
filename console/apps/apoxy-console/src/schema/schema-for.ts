// Per-kind tray validation schemas, keyed by k8s GVK and generated from the
// apiserver OpenAPI (see scripts/openapi-to-schemas.ts). Resolving by GVK keeps
// registry entries declarative: they name the kind, and the schema is looked up.

import type { JSONSchema } from '@apoxy/console-core'
import { RESOURCE_SCHEMAS } from './resource-schemas'

/** The tray validation schema for a kind, or `undefined` when none was generated
 *  (the tray then falls back to the always-on structural k8s checks). */
export function schemaFor(group: string, version: string, kind: string): JSONSchema | undefined {
  return RESOURCE_SCHEMAS[`${group}/${version}/${kind}`]
}
