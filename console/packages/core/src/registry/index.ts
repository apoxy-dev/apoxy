// @apoxy/console-core — resource registry (the M3 spine).

export type {
  Registry,
  RegistryGroup,
  ResourceEntry,
  ResourceEntryInput,
  ResourceColumn,
  ResourceDetailProps,
  WizardProps,
} from './types'
export { createRegistry, defineResource } from './registry'

// Sidebar + breadcrumb generation
export { buildSidebar, buildBreadcrumbs } from './nav'
export type {
  SidebarItem,
  SidebarGroupModel,
  SidebarModel,
  BuildSidebarOptions,
  Breadcrumb,
  BreadcrumbSwitch,
  BreadcrumbSwitchOption,
  BuildBreadcrumbsOptions,
} from './nav'

// Discovery + SSAR gating (replaces the /capabilities endpoint)
export {
  DiscoveryClient,
  AccessReviewClient,
  parseAggregatedDiscovery,
  servedPredicate,
  accessReviewBody,
  useDiscovery,
  useCan,
} from './discovery'
export type {
  DiscoveryDoc,
  DiscoveryClientOptions,
  DiscoveryResult,
  ServedGVRs,
  AccessReviewClientOptions,
  AccessReviewAttributes,
  Verb,
  UseCanOptions,
  CanResult,
} from './discovery'

// Generic renderers + the splat-route dispatcher
export { ResourceView, type ResourceViewProps } from './resource-view'
export {
  ResourceListView,
  type ResourceListViewProps,
} from './resource-list-view'
export {
  ResourceDetailView,
  type ResourceDetailViewProps,
} from './resource-detail-view'
export { Panel, StateMessage } from './views-common'
