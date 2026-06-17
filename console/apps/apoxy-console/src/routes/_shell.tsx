// The pathless layout route: it owns the fixed chrome (collapsible rail +
// topbar) and renders the matched page through <Outlet>. Sidebar and
// breadcrumbs derive from the registry + current location, so the shell never
// names a kind directly. Collapse state is persisted to localStorage.

import { useCallback, useMemo, useState } from 'react'
import { createFileRoute, Outlet, useLocation } from '@tanstack/react-router'
import {
  AppShell,
  Breadcrumbs,
  CommandButton,
  LinkProvider,
  Sidebar,
  Topbar,
  buildBreadcrumbs,
  buildSidebar,
  cn,
  useDiscovery,
} from '@apoxy/console-core'
import { SidePanelClose, SidePanelOpen } from '@carbon/icons-react'
import { registry } from '../registry'
import { RouterLink } from '../router-link'

export const Route = createFileRoute('/_shell')({ component: Shell })

const COLLAPSE_KEY = 'apoxy.console.sidebar-collapsed'
function readCollapsed(): boolean {
  try {
    return globalThis.localStorage?.getItem(COLLAPSE_KEY) === '1'
  } catch {
    return false
  }
}
function writeCollapsed(v: boolean): void {
  try {
    globalThis.localStorage?.setItem(COLLAPSE_KEY, v ? '1' : '0')
  } catch {
    /* storage unavailable — collapse just won't persist */
  }
}

function Shell() {
  const { pathname } = useLocation()
  const segments = pathname.split('/').filter(Boolean)
  const slug = segments[0]
  // k8s names are URL-safe single segments — use the raw segment (no decode, so
  // a malformed %-escape in the URL can't throw and crash the chrome).
  const name = segments[1]
  const entry = slug ? registry.byPath(slug) : undefined

  const [collapsed, setCollapsed] = useState(readCollapsed)
  const toggleCollapsed = useCallback(() => {
    setCollapsed((c) => {
      const next = !c
      writeCollapsed(next)
      return next
    })
  }, [])

  const { isServed } = useDiscovery()
  const model = useMemo(() => buildSidebar(registry, { isServed }), [isServed])
  const crumbs = buildBreadcrumbs(entry, name, { root: { label: 'Apoxy', to: '/' } })
  const activePath = slug ? `/${slug}` : '/'

  return (
    <LinkProvider component={RouterLink}>
      <AppShell
        sidebar={
          <Sidebar
            model={model}
            activePath={activePath}
            collapsed={collapsed}
            onToggleCollapsed={toggleCollapsed}
            toggleIcon={collapsed ? <SidePanelOpen size={16} /> : <SidePanelClose size={16} />}
            brand={<Brand />}
            footer={<UserFooter collapsed={collapsed} />}
          />
        }
        topbar={
          <Topbar
            breadcrumbs={<Breadcrumbs items={crumbs} />}
            actions={<CommandButton placeholder="Search resources…" />}
          />
        }
      >
        <Outlet />
      </AppShell>
    </LinkProvider>
  )
}

function Brand() {
  return (
    <span className="font-[family-name:var(--font-display)] text-[length:var(--t-h5)] font-medium tracking-[-0.01em] text-[color:var(--apx-bone)]">
      apoxy
    </span>
  )
}

function UserFooter({ collapsed }: { collapsed: boolean }) {
  return (
    <div className={cn('flex items-center', collapsed ? 'justify-center gap-0' : 'gap-[10px]')}>
      <span className="flex h-7 w-7 flex-none items-center justify-center rounded-full bg-[var(--surface-canvas)] text-[length:var(--t-overline)] font-semibold text-[color:var(--apx-ink)]">
        U
      </span>
      {!collapsed && (
        <div className="min-w-0">
          <div className="truncate text-[length:var(--t-body-sm)] font-medium text-[color:var(--apx-bone)]">Signed in</div>
          <div className="truncate font-mono text-[length:var(--t-overline)] text-[color:var(--apx-stone)]">console</div>
        </div>
      )}
    </div>
  )
}
