// The single generic resource route: every kind's list and detail flow through
// this splat. The URL tail (`proxies` or `proxies/my-proxy`) is resolved
// against the registry by <ResourceView>, so adding a kind needs no new route.

import { createFileRoute } from '@tanstack/react-router'
import { ResourceView } from '@apoxy/console-core'
import { registry } from '../registry'

export const Route = createFileRoute('/_shell/$')({ component: ResourcePage })

function ResourcePage() {
  const { _splat } = Route.useParams()
  return <ResourceView registry={registry} splat={_splat ?? ''} />
}
