// The generic list view (APO-776) with keyboard navigation + virtualization
// (APO-780). A table driven by the registry entry's `columns`, backed by
// useK8sList (one managed watch). j/k (and ↑/↓ when the table is focused) move a
// row cursor; Enter opens the highlighted row. Long lists are windowed with
// spacer rows so only the visible slice renders. Loading/empty/error states are
// handled here so every kind gets them for free.

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { cn } from '../lib/cn'
import { useK8sList } from '../lib/hooks'
import { useLink, useNavigate } from '../components/chrome/link-context'
import { PageHeader } from '../components/chrome/page-header'
import { Button } from '../components/ui/button'
import { useKeyboardScope } from '../keyboard/scope-stack'
import { useListSelection } from '../keyboard/selection'
import { computeWindow } from '../keyboard/windowing'
import { useCan } from './discovery'
import { useCreate } from '../yaml/create-context'
import { Panel, StateMessage } from './views-common'
import type { ResourceEntry } from './types'
import type { K8sObject } from '../lib/k8s-types'

export interface ResourceListViewProps {
  entry: ResourceEntry
  /** Right-aligned page-header actions (e.g. a New/YAML button). */
  actions?: ReactNode
  /** Override the default item-count subtitle. */
  subtitle?: ReactNode
}

const TH =
  'border-b border-[color:var(--border-default)] bg-[var(--apx-mist)] px-[var(--sp-4)] py-[var(--sp-3)] text-left text-[length:var(--t-overline)] font-medium uppercase tracking-[0.06em] text-[color:var(--text-muted)]'
// `whitespace-nowrap` keeps cell content on one line: a row can't grow past
// ROW_HEIGHT, so the windowing/scroll math below stays exact (overflow goes to
// the container's horizontal scroll, not a second line).
const TD = 'border-b border-[color:var(--border-subtle)] whitespace-nowrap px-[var(--sp-4)] align-middle'

// Fixed row height drives the windowing math; rows are pinned to it so the
// spacer heights stay exact.
const ROW_HEIGHT = 48
const VIRTUALIZE_THRESHOLD = 80
const VIEWPORT_MAX = 640

export function ResourceListView({ entry, actions, subtitle }: ResourceListViewProps) {
  const Link = useLink()
  const navigate = useNavigate()
  const list = useK8sList(entry.gvr)
  const items = useMemo(() => list.data?.items ?? [], [list.data])
  const count = items.length

  // "New <kind>": open the shared create tray, gated by `yamlEditable` and a
  // create SelfSubjectAccessReview. Only offered when a CreateProvider is mounted
  // (`create` is null in isolation/tests), so the list stays usable on its own.
  const create = useCreate()
  const canCreate = useCan('create', entry.gvr, { enabled: entry.yamlEditable && !!create })
  const showCreate = !!create && entry.yamlEditable && canCreate.allowed
  useKeyboardScope({
    level: 'view',
    enabled: showCreate,
    bindings: [{ keys: 'n', run: () => create?.openCreate(entry) }],
  })
  const newAction = showCreate ? (
    <Button variant="primary" size="sm" onClick={() => create?.openCreate(entry)}>
      New {entry.kind}
    </Button>
  ) : null
  const headerActions =
    newAction || actions ? (
      <>
        {newAction}
        {actions}
      </>
    ) : undefined

  const hrefOf = (obj: K8sObject | undefined): string | undefined =>
    obj?.metadata.name ? `/${entry.path}/${obj.metadata.name}` : undefined

  // Stable per-row identity so the cursor follows the selected object across
  // live watch updates (a delete/reorder must not silently re-point Enter).
  const keys = useMemo(() => items.map((o) => o.metadata.uid ?? o.metadata.name ?? ''), [items])

  const selection = useListSelection({
    count,
    keys,
    onActivate: (i) => {
      const href = hrefOf(items[i])
      if (href) navigate(href)
    },
  })
  const { index, setIndex } = selection

  // View-level shortcuts: j/k move, Enter opens. Bare letters, so they are
  // suppressed while typing and shadowed when a tray/dialog is open.
  useKeyboardScope({
    level: 'view',
    enabled: count > 0,
    bindings: [
      { keys: 'j', run: () => selection.move(1) },
      { keys: 'k', run: () => selection.move(-1) },
      { keys: 'enter', run: () => selection.activate() },
    ],
  })

  // Virtualization: window the rows once the list is long enough to matter.
  const virtualize = count > VIRTUALIZE_THRESHOLD
  const scrollRef = useRef<HTMLDivElement>(null)
  const headerRef = useRef<HTMLTableSectionElement>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const win = virtualize
    ? computeWindow({ scrollTop, viewportHeight: VIEWPORT_MAX, itemHeight: ROW_HEIGHT, count, overscan: 6 })
    : { start: 0, end: count, paddingTop: 0, paddingBottom: 0, totalHeight: count * ROW_HEIGHT }
  const visible = items.slice(win.start, win.end)

  // Keep the cursor row visible: adjust the scroll container for windowed lists
  // (the row may not be mounted), else scroll the row element into view.
  useEffect(() => {
    if (index < 0) return
    if (virtualize) {
      const el = scrollRef.current
      if (!el) return
      // The non-sticky <thead> sits in the same scroll container, so the row's
      // real top is the header height plus its windowed offset.
      const headerH = headerRef.current?.offsetHeight ?? 0
      const top = headerH + index * ROW_HEIGHT
      const bottom = top + ROW_HEIGHT
      if (top < el.scrollTop) el.scrollTop = top
      else if (bottom > el.scrollTop + el.clientHeight) el.scrollTop = bottom - el.clientHeight
    } else {
      document.getElementById(`${entry.path}-row-${index}`)?.scrollIntoView?.({ block: 'nearest' })
    }
  }, [index, virtualize, entry.path])

  // Drive arrow/Home/End navigation from the focused table, but leave Enter to
  // the global view scope — which defers to a focused row link — so a focused
  // link's own activation isn't hijacked by the cursor row.
  const onNavKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== 'Enter') selection.onKeyDown(e)
  }

  const defaultSubtitle = list.isPending ? 'Loading…' : `${count} ${count === 1 ? 'item' : 'items'}`
  const lower = entry.displayName.toLowerCase()

  const table = (
    <table className="w-full border-collapse text-[length:var(--t-caption)]">
      <thead ref={headerRef}>
        <tr>
          {entry.columns.map((c) => (
            <th key={c.id} scope="col" className={TH} style={c.width ? { width: c.width } : undefined}>
              {c.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {win.paddingTop > 0 && (
          <tr aria-hidden="true">
            <td colSpan={entry.columns.length} style={{ height: win.paddingTop, padding: 0, border: 0 }} />
          </tr>
        )}
        {visible.map((obj, i) => {
          const rowIndex = win.start + i
          const name = obj.metadata.name
          // k8s names are URL-safe (DNS labels), so the slug is the raw name —
          // no encode here and no decode at the route.
          const href = name ? `/${entry.path}/${name}` : undefined
          const selected = rowIndex === index
          return (
            <tr
              id={`${entry.path}-row-${rowIndex}`}
              key={obj.metadata.uid ?? name ?? `row-${rowIndex}`}
              aria-selected={selected}
              onMouseMove={() => setIndex(rowIndex)}
              style={{ height: ROW_HEIGHT }}
              className={cn(
                'transition-colors',
                selected ? 'bg-[var(--apx-bone)] ring-1 ring-inset ring-[color:var(--border-default)]' : 'hover:bg-[var(--apx-bone)]',
              )}
            >
              {entry.columns.map((c, ci) => (
                <td
                  key={c.id}
                  className={cn(TD, c.mono && 'font-mono text-[length:var(--t-micro)] text-[color:var(--text-secondary)]')}
                >
                  {ci === 0 && href ? (
                    <Link
                      to={href}
                      className="font-medium text-[color:var(--text-primary)] no-underline hover:text-[color:var(--text-link-hover)]"
                    >
                      {c.cell(obj)}
                    </Link>
                  ) : (
                    c.cell(obj)
                  )}
                </td>
              ))}
            </tr>
          )
        })}
        {win.paddingBottom > 0 && (
          <tr aria-hidden="true">
            <td colSpan={entry.columns.length} style={{ height: win.paddingBottom, padding: 0, border: 0 }} />
          </tr>
        )}
      </tbody>
    </table>
  )

  return (
    <div>
      <PageHeader title={entry.displayName} subtitle={subtitle ?? defaultSubtitle} actions={headerActions} />
      <Panel className="overflow-hidden">
        {list.isError ? (
          <StateMessage tone="error">{list.error?.message ?? 'Failed to load.'}</StateMessage>
        ) : list.isPending ? (
          <StateMessage>Loading {lower}…</StateMessage>
        ) : count === 0 ? (
          <StateMessage>No {lower} yet.</StateMessage>
        ) : virtualize ? (
          <div
            ref={scrollRef}
            tabIndex={0}
            onKeyDown={onNavKeyDown}
            onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
            style={{ maxHeight: VIEWPORT_MAX }}
            className="overflow-auto outline-none"
          >
            {table}
          </div>
        ) : (
          // Focusable so ↑/↓ drive the row cursor when the table has focus (j/k
          // work globally via the scope above; arrows are scoped to focus so they
          // don't hijack page scroll elsewhere).
          <div tabIndex={0} onKeyDown={onNavKeyDown} className="outline-none">
            {table}
          </div>
        )}
      </Panel>
    </div>
  )
}
