import type { WatchEvent, K8sObject } from './k8s-types'

/** One decorated Kubernetes watch request. */
export interface WatchTransportRequest {
  url: string
  headers: Headers
  signal?: AbortSignal
}

/** Transport seam for Kubernetes watch streams. */
export interface WatchTransport {
  watch<T extends K8sObject = K8sObject>(
    request: WatchTransportRequest,
  ): AsyncGenerator<WatchEvent<T>>
  dispose?(): void
}
