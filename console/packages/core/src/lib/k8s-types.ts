// Runtime-facing Kubernetes API types for the GVR client and WatchManager.
// These alias the generated OpenAPI meta types where one exists so
// the hand-written client stays honest with the Go source, and add the small
// generic envelopes (GVR, K8sList, WatchEvent) the schema does not name.

import type { components } from '../schema/schema'

type Schemas = components['schemas']

/** Standard object metadata as served by the apiserver. */
export type ObjectMeta = Schemas['io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta']
/** Standard list metadata (carries the `resourceVersion` the watch resumes from). */
export type ListMeta = Schemas['io.k8s.apimachinery.pkg.apis.meta.v1.ListMeta']
/** The apiserver's failure envelope, returned as the body of non-2xx responses. */
export type Status = Schemas['io.k8s.apimachinery.pkg.apis.meta.v1.Status']

/**
 * Group/Version/Resource address. `resource` is the lowercase plural
 * (e.g. `proxies`). `group` is empty (`''`) for the core `/api/v1` group.
 *
 * Whether a resource is namespaced is a property of the *request*, not the GVR:
 * apoxy resources are cluster-scoped and project scoping is a RequestDecorator
 * concern, so `namespace` is an optional per-call parameter rather
 * than part of the address.
 */
export interface GVR {
  group: string
  version: string
  resource: string
}

/** Minimal shape every served object shares; feature types narrow `T` further. */
export interface K8sObject {
  apiVersion?: string
  kind?: string
  metadata: ObjectMeta
}

/** A Kubernetes list response: typed items plus the list `resourceVersion`. */
export interface K8sList<T extends K8sObject = K8sObject> {
  apiVersion?: string
  kind?: string
  metadata: ListMeta
  items: T[]
}

/** Watch event verbs as sent on the NDJSON watch stream. */
export type WatchEventType = 'ADDED' | 'MODIFIED' | 'DELETED' | 'BOOKMARK' | 'ERROR'

/**
 * A single watch event. For ADDED/MODIFIED/DELETED/BOOKMARK `object` is the
 * resource (BOOKMARK carries only `metadata.resourceVersion`); for ERROR it is
 * a {@link Status}.
 */
export interface WatchEvent<T extends K8sObject = K8sObject> {
  type: WatchEventType
  object: T | Status
}
