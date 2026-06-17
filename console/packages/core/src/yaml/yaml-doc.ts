// YAML <-> object round-trip for the tray (APO-777). JSON is valid YAML and the
// apply path sends JSON, so this is purely the editor's presentation: render an
// object as readable YAML, parse the edited text back, and strip the
// server-owned fields a user should never hand-edit (managedFields, uid,
// resourceVersion, the whole status subresource) before presenting it for edit.

import { parse, stringify } from 'yaml'
import type { GVR, K8sObject } from '../lib/k8s-types'

/** Metadata keys the apiserver owns; removed before editing and not sent on apply. */
const SERVER_META_KEYS = [
  'managedFields',
  'creationTimestamp',
  'deletionTimestamp',
  'deletionGracePeriodSeconds',
  'uid',
  'resourceVersion',
  'generation',
  'selfLink',
  'ownerReferences',
] as const

/**
 * A copy of `obj` with server-owned noise removed, suitable for editing: the
 * status subresource and the generated metadata fields are dropped, leaving the
 * spec, name/namespace, labels, and annotations the user actually authors.
 */
export function forEditing<T extends K8sObject>(obj: T): Record<string, unknown> {
  const clone = structuredClone(obj) as Record<string, unknown>
  delete clone.status
  const meta = clone.metadata as Record<string, unknown> | undefined
  if (meta) {
    for (const k of SERVER_META_KEYS) delete meta[k]
  }
  return clone
}

/** Serialize a value as YAML for the editor (2-space indent, no anchors). */
export function toYaml(value: unknown): string {
  return stringify(value, { indent: 2, aliasDuplicateObjects: false })
}

export interface ParseResult {
  /** The parsed value when the text is valid YAML (may be null/scalar). */
  value?: unknown
  /** A human-readable parse error when the text is not valid YAML. */
  error?: string
}

/** Parse edited YAML text, returning either the value or a readable error. */
export function fromYaml(text: string): ParseResult {
  try {
    return { value: parse(text) }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    return { error: msg }
  }
}

/**
 * A minimal create skeleton for a kind, used when the tray opens with no
 * existing object: just the apiVersion/kind/name the user fills in.
 */
export function skeleton(gvr: GVR, kind: string): Record<string, unknown> {
  const apiVersion = gvr.group ? `${gvr.group}/${gvr.version}` : gvr.version
  return {
    apiVersion,
    kind,
    metadata: { name: '' },
    spec: {},
  }
}
