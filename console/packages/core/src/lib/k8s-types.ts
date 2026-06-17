// Runtime-facing Kubernetes API types for the GVR client and WatchManager.
//
// The meta types below (ObjectMeta, ListMeta, Status and their nested shapes)
// mirror `k8s.io/apimachinery/pkg/apis/meta/v1`. They are identical on every
// Kubernetes-convention apiserver, so they are hand-written here rather than
// pulled from any one app's generated OpenAPI — that keeps this package
// app-agnostic (no apoxy/clrk schema bundled in core). Feature packages bring
// their own typed spec/status and intersect them with {@link K8sObject}.

/** A wall-clock timestamp in RFC3339 form, as the apiserver serializes it. */
export type Time = string

/** Identifies an owning object (same namespace as the dependent, or cluster-scoped). */
export interface OwnerReference {
  apiVersion: string
  kind: string
  name: string
  uid: string
  controller?: boolean
  blockOwnerDeletion?: boolean
}

/** A single server-side-apply field-manager entry. */
export interface ManagedFieldsEntry {
  manager?: string
  operation?: string
  apiVersion?: string
  time?: Time
  fieldsType?: string
  fieldsV1?: Record<string, unknown>
  subresource?: string
}

/** Standard object metadata as served by the apiserver. */
export interface ObjectMeta {
  name?: string
  generateName?: string
  namespace?: string
  uid?: string
  resourceVersion?: string
  generation?: number
  creationTimestamp?: Time
  deletionTimestamp?: Time
  deletionGracePeriodSeconds?: number
  labels?: Record<string, string>
  annotations?: Record<string, string>
  finalizers?: string[]
  ownerReferences?: OwnerReference[]
  managedFields?: ManagedFieldsEntry[]
  selfLink?: string
}

/** Standard list metadata (carries the `resourceVersion` the watch resumes from). */
export interface ListMeta {
  resourceVersion?: string
  continue?: string
  remainingItemCount?: number
  selfLink?: string
}

/** One machine-readable cause attached to a {@link Status} failure. */
export interface StatusCause {
  reason?: string
  message?: string
  field?: string
}

/** Extended detail the server may attach to a {@link Status} failure. */
export interface StatusDetails {
  name?: string
  group?: string
  kind?: string
  uid?: string
  causes?: StatusCause[]
  retryAfterSeconds?: number
}

/** The apiserver's failure envelope, returned as the body of non-2xx responses. */
export interface Status {
  apiVersion?: string
  kind?: string
  metadata?: ListMeta
  status?: string
  message?: string
  reason?: string
  details?: StatusDetails
  code?: number
}

/**
 * Group/Version/Resource address. `resource` is the lowercase plural
 * (e.g. `widgets`). `group` is empty (`''`) for the core `/api/v1` group.
 *
 * Whether a resource is namespaced is a property of the *request*, not the GVR:
 * cluster-scoped resources and project scoping (a RequestDecorator concern) mean
 * `namespace` is an optional per-call parameter rather than part of the address.
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
