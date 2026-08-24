export { cn } from './cn'

// Kubernetes API types
export type {
  GVR,
  K8sObject,
  K8sList,
  ObjectMeta,
  ListMeta,
  Status,
  WatchEvent,
  WatchEventType,
} from './k8s-types'

// RequestDecorator seam
export type { RequestDecorator, DecorateInput, DecorateResult } from './request-decorator'
export {
  ProjectRequestDecorator,
  type ProjectRequestDecoratorOptions,
} from './request-decorator'

// Generic GVR client
export { GVRClient, K8sStatusError } from './gvr-client'
export type {
  GVRClientOptions,
  ApplyOptions,
  MutateOptions,
  SubresourceOptions,
} from './gvr-client'
export type { Selectors, ListParams, QueryParams, WatchParams } from './k8s-paths'
export type { WatchTransport, WatchTransportRequest } from './watch-transport'
export {
  WebSocketWatchTransport,
  WATCH_MULTIPLEXER_PATH,
  WATCH_WEBSOCKET_PROTOCOL,
  WATCH_BEARER_PROTOCOL_PREFIX,
} from './websocket-watch-transport'
export type {
  WebSocketWatchTransportOptions,
  WatchSocketFactory,
} from './websocket-watch-transport'

// Cache keys
export { listKey, gvrKey, scopePrefix, entryKey } from './cache-keys'

// WatchManager — the sole cache writer
export { WatchManager } from './watch-manager'
export type { WatchManagerOptions, Subscription, Scheduler } from './watch-manager'

// Client wiring + React surface
export { createConsoleClient } from './console-client'
export type { ConsoleClient, CreateConsoleClientOptions } from './console-client'
export {
  ConsoleProvider,
  useConsoleClient,
  useWatchManager,
  useK8sList,
  useK8sObject,
} from './hooks'
export type { UseK8sListOptions, UseK8sObjectOptions } from './hooks'

// Generic CRUD hooks (apply/delete) — never write the cache
export { useApplyResource, useDeleteResource } from './mutations'
export type { UseApplyResourceResult, UseDeleteResourceResult } from './mutations'

// PostHog product analytics (router-agnostic; posthog-js loaded lazily)
export { capturePageview, captureEvent, useAnalyticsPageviews } from './analytics'
