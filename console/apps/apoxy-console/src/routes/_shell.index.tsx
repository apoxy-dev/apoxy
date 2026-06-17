// Overview (`/`): a registry-driven landing grid linking to each kind. The
// metrics/KPI dashboard from the mockup is feature content (live workers,
// charts) and lands with the feature packages in M5; this is the generic
// entrypoint the shell needs now.

import { createFileRoute } from '@tanstack/react-router'
import { Card, CardMeta, CardTitle, PageHeader, useLink } from '@apoxy/console-core'
import { registry } from '../registry'

export const Route = createFileRoute('/_shell/')({ component: Overview })

function Overview() {
  const Link = useLink()
  return (
    <div>
      <PageHeader title="Overview" subtitle="Resources in this project" />
      <div className="grid grid-cols-[repeat(auto-fill,minmax(240px,1fr))] gap-[var(--sp-4)]">
        {registry.all().map((e) => (
          <Link key={e.path} to={`/${e.path}`} className="no-underline">
            <Card className="h-full transition-colors hover:border-[color:var(--apx-ink)]">
              <CardTitle>{e.displayName}</CardTitle>
              <CardMeta>
                {e.gvr.group}/{e.gvr.version}
              </CardMeta>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  )
}
