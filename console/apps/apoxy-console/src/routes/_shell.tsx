// The pathless layout route: it owns the fixed chrome (collapsible rail +
// topbar) and renders the matched page through <Outlet>. Sidebar and
// breadcrumbs derive from the registry + current location, so the shell never
// names a kind directly. It also installs the M4 keyboard layer: a scope-stack
// provider, the ⌘K command palette (registry-fed), and g-navigation. Collapse
// state is persisted to localStorage.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { createFileRoute, Outlet, useLocation, useRouter } from '@tanstack/react-router'
import {
  AppShell,
  Breadcrumbs,
  CommandButton,
  CommandPalette,
  CreateProvider,
  IconButton,
  KeyboardScopeProvider,
  LinkProvider,
  Sidebar,
  Topbar,
  TrayEditorProvider,
  buildBreadcrumbs,
  buildResourceCommands,
  buildSidebar,
  cn,
  useCommandKeyBindings,
  useCreate,
  useDiscovery,
  useKeyboardScope,
  type Command,
} from '@apoxy/console-core'
import { SidePanelClose, SidePanelOpen } from '@carbon/icons-react'
import { registry } from '../registry'
import { TrayEditor } from '../tray-editor'
import { RouterLink } from '../router-link'
import { rootCrumbLabel } from '../project-context'
import { applyTheme, readTheme, storeTheme, THEME_KEY, type Theme } from '../theme'
import wordmark from '../assets/apoxy-wordmark.svg'

const DOCS_URL = 'https://docs.apoxy.dev'
// One prompt shared by the top-bar trigger and the palette input.
const SEARCH_PLACEHOLDER = 'Search resources, actions…'

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
  // The scope provider must wrap the whole shell so the palette, list nav, and
  // tray all register against one stack. CreateProvider owns the single shared
  // "new object" tray, opened from the list "New" button and the ⌘K palette.
  // TrayEditorProvider installs the CodeMirror editor into every YAML tray.
  return (
    <TrayEditorProvider editor={TrayEditor}>
      <KeyboardScopeProvider>
        <CreateProvider>
          <ShellBody />
        </CreateProvider>
      </KeyboardScopeProvider>
    </TrayEditorProvider>
  )
}

function ShellBody() {
  const router = useRouter()
  const navigate = useCallback(
    (to: string) => {
      void router.navigate({ to: to as never })
    },
    [router],
  )

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
  // The root crumb names the deployment: the project slug, or `localhost` when
  // self-hosted — not a fixed "Apoxy" label.
  const crumbs = buildBreadcrumbs(entry, name, { root: { label: rootCrumbLabel, to: '/' } })
  const activePath = slug ? `/${slug}` : '/'

  // ⌘K command palette, fed by the registry (+ an Overview entry). `onCreate`
  // adds a "New <kind>" command for each editable kind, opening the shared tray.
  const { openCreate } = useCreate() ?? {}
  const [paletteOpen, setPaletteOpen] = useState(false)
  const commands = useMemo<Command[]>(
    () => [
      { id: 'home', title: 'Overview', group: 'Go to', keywords: ['home', 'dashboard'], keys: 'g h', run: () => navigate('/') },
      ...buildResourceCommands(registry, { navigate, isServed, onCreate: openCreate }),
    ],
    [navigate, isServed, openCreate],
  )

  // g-navigation is derived from the command list: every command with a `keys`
  // spec (Overview's `g h`, each kind's `g <shortcut>`) registers its binding
  // from the same source the palette renders, so the two can't drift.
  useCommandKeyBindings(commands)
  useKeyboardScope({
    level: 'global',
    bindings: [{ keys: 'mod+k', run: () => setPaletteOpen(true) }],
  })

  return (
    <LinkProvider component={RouterLink} navigate={navigate}>
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
            actions={
              <>
                <CommandButton placeholder={SEARCH_PLACEHOLDER} onOpen={() => setPaletteOpen(true)} />
                <IconButton label="Documentation" href={DOCS_URL}>
                  {DocsIcon}
                </IconButton>
                <ThemeToggle />
                <IconButton label="Notifications" badge>
                  {BellIcon}
                </IconButton>
              </>
            }
          />
        }
      >
        <Outlet />
      </AppShell>
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        commands={commands}
        placeholder={SEARCH_PLACEHOLDER}
        brand="apoxy"
      />
    </LinkProvider>
  )
}

function Brand() {
  // The design's wordmark (near-black art) inverted to read white on the dark
  // rail, with a mono product suffix — "apoxy console".
  return (
    <>
      <img src={wordmark} alt="Apoxy" className="h-[20px] w-auto [filter:invert(1)_brightness(2)]" />
      <span className="font-mono text-[length:var(--t-micro)] uppercase tracking-[0.14em] text-[color:var(--rail-text-dim)]">
        console
      </span>
    </>
  )
}

// Sun / moon glyphs for the theme toggle (the design's `Ico.sun` / `Ico.moon`),
// hand-rolled so the core IconButton stays icon-library-agnostic.
const SunIcon = (
  <svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
    <circle cx="8" cy="8" r="3" />
    <path d="M8 1.5v1.6M8 12.9v1.6M1.5 8h1.6M12.9 8h1.6M3.4 3.4l1.1 1.1M11.5 11.5l1.1 1.1M3.4 12.6l1.1-1.1M11.5 4.5l1.1-1.1" />
  </svg>
)
const MoonIcon = (
  <svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" aria-hidden="true">
    <path d="M13.2 9.6A5.5 5.5 0 116.4 2.8a4.4 4.4 0 006.8 6.8z" />
  </svg>
)
const DocsIcon = (
  <svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
    <path d="M3 2h7l3 3v9H3z" />
    <path d="M10 2v3h3M5 8h6M5 11h4" />
  </svg>
)
const BellIcon = (
  <svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
    <path d="M4 6a4 4 0 018 0v3l1 2H3l1-2zM6 13a2 2 0 004 0" />
  </svg>
)

function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(readTheme)
  useEffect(() => {
    applyTheme(theme)
  }, [theme])
  // Follow a theme change made in another tab.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === THEME_KEY) setTheme(readTheme())
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])
  const dark = theme === 'dark'
  const toggle = () => {
    setTheme((cur) => {
      const next: Theme = cur === 'dark' ? 'light' : 'dark'
      storeTheme(next)
      return next
    })
  }
  return (
    <IconButton label={dark ? 'Switch to light mode' : 'Switch to dark mode'} pressed={dark} onClick={toggle}>
      {dark ? SunIcon : MoonIcon}
    </IconButton>
  )
}

function UserFooter({ collapsed }: { collapsed: boolean }) {
  return (
    <div className={cn('flex items-center', collapsed ? 'justify-center gap-0' : 'gap-[10px]')}>
      <span className="flex h-7 w-7 flex-none items-center justify-center rounded-full bg-[var(--rail-text)] text-[length:var(--t-overline)] font-semibold text-[color:var(--rail-bg)]">
        U
      </span>
      {!collapsed && (
        <div className="min-w-0">
          <div className="truncate text-[length:var(--t-body-sm)] font-medium text-[color:var(--rail-text)]">Signed in</div>
          <div className="truncate font-mono text-[length:var(--t-overline)] text-[color:var(--rail-text-dim)]">console</div>
        </div>
      )}
    </div>
  )
}
