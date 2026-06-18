// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MillerBrowser, type MillerColumnDef, type MillerItem } from './miller-browser'

afterEach(cleanup)

// A tiny three-level tree: listener → route → rule, so we can assert the
// left→right cascade without dragging in any Gateway-API types.
const TREE: Record<string, Record<string, string[]>> = {
  web: { 'app-route': ['/a', '/b'], 'api-route': ['/v1'] },
  admin: { 'ops-route': ['/ops'] },
  edge: { 'edge-route': ['/e'] },
}

const COLUMNS: MillerColumnDef[] = [
  { id: 'listeners', label: 'Listeners' },
  { id: 'routes', label: 'Routes', emptyMessage: 'Pick a listener' },
  { id: 'rules', label: 'Rules', emptyMessage: 'Pick a route' },
]

function getItems(col: number, selected: (string | null)[]): MillerItem[] {
  if (col === 0) return Object.keys(TREE).map((id) => ({ id, name: id, status: 'ok' as const }))
  if (col === 1) {
    const l = selected[0]
    return l ? Object.keys(TREE[l] ?? {}).map((id) => ({ id, name: id })) : []
  }
  const l = selected[0]
  const r = selected[1]
  const rules = (l && r && TREE[l]?.[r]) || []
  return rules.map((id) => ({ id, name: id, mono: true }))
}

function col(label: string): HTMLElement {
  return screen.getByRole('rowgroup', { name: label })
}
function rowNames(label: string): string[] {
  return within(col(label))
    .queryAllByRole('row')
    .map((r) => r.textContent ?? '')
}
function focusGrid(): HTMLElement {
  const grid = screen.getByRole('grid')
  grid.focus()
  return grid
}

describe('MillerBrowser', () => {
  it('auto-selects the first row of every column, cascading left→right', () => {
    render(<MillerBrowser columns={COLUMNS} getItems={getItems} />)
    // listener "web" → its routes; route "app-route" → its rules.
    expect(rowNames('Routes')).toEqual(['app-route', 'api-route'])
    expect(rowNames('Rules')).toEqual(['/a', '/b'])
    expect(within(col('Listeners')).getByRole('row', { name: 'web' }).getAttribute('aria-selected')).toBe('true')
  })

  it('re-derives downstream columns when an upstream row is picked', () => {
    render(<MillerBrowser columns={COLUMNS} getItems={getItems} />)
    fireEvent.click(within(col('Listeners')).getByRole('row', { name: 'admin' }))
    expect(rowNames('Routes')).toEqual(['ops-route'])
    expect(rowNames('Rules')).toEqual(['/ops'])
  })

  it('clears a stale downstream pick when the parent changes', () => {
    render(<MillerBrowser columns={COLUMNS} getItems={getItems} />)
    // Drill into web → api-route → /v1, then jump to admin: the old route/rule
    // ids no longer exist, so the cascade falls back to admin's first path.
    fireEvent.click(within(col('Routes')).getByRole('row', { name: 'api-route' }))
    expect(rowNames('Rules')).toEqual(['/v1'])
    fireEvent.click(within(col('Listeners')).getByRole('row', { name: 'admin' }))
    expect(within(col('Routes')).getByRole('row', { name: 'ops-route' }).getAttribute('aria-selected')).toBe('true')
    expect(rowNames('Rules')).toEqual(['/ops'])
  })

  it('renders a column empty-state when there is nothing to show', () => {
    // A getItems that yields no listeners → routes/rules columns are empty.
    render(<MillerBrowser columns={COLUMNS} getItems={() => []} />)
    expect(col('Routes').textContent).toContain('Pick a listener')
    expect(within(col('Routes')).queryAllByRole('row')).toHaveLength(0)
  })

  it('moves the selection with the arrow keys (↓ within a column, → across)', () => {
    render(<MillerBrowser columns={COLUMNS} getItems={getItems} />)
    const grid = focusGrid()
    // ↓ in the Listeners column moves web → admin, recascading downstream.
    fireEvent.keyDown(grid, { key: 'ArrowDown' })
    expect(within(col('Listeners')).getByRole('row', { name: 'admin' }).getAttribute('aria-selected')).toBe('true')
    expect(rowNames('Routes')).toEqual(['ops-route'])
  })

  it('advances multiple rows on repeated ArrowDown (reads fresh state each keystroke)', () => {
    render(<MillerBrowser columns={COLUMNS} getItems={getItems} />)
    const grid = focusGrid()
    fireEvent.keyDown(grid, { key: 'ArrowDown' }) // web → admin
    fireEvent.keyDown(grid, { key: 'ArrowDown' }) // admin → edge (would stick on admin if stale)
    expect(within(col('Listeners')).getByRole('row', { name: 'edge' }).getAttribute('aria-selected')).toBe('true')
    expect(rowNames('Routes')).toEqual(['edge-route'])
  })

  it('reports the resolved selection through onSelectionChange', () => {
    const onSel = vi.fn()
    render(<MillerBrowser columns={COLUMNS} getItems={getItems} onSelectionChange={onSel} />)
    expect(onSel).toHaveBeenLastCalledWith(['web', 'app-route', '/a'])
    fireEvent.click(within(col('Listeners')).getByRole('row', { name: 'admin' }))
    expect(onSel).toHaveBeenLastCalledWith(['admin', 'ops-route', '/ops'])
  })

  it('fires a per-row edit affordance without changing selection', () => {
    const onEdit = vi.fn()
    const items = (col: number): MillerItem[] =>
      col === 0 ? [{ id: 'web', name: 'web', onEdit }] : []
    render(<MillerBrowser columns={[COLUMNS[0]!]} getItems={items} />)
    fireEvent.click(within(col('Listeners')).getByTitle('Edit'))
    expect(onEdit).toHaveBeenCalledTimes(1)
  })

  it('filters rows through getItems when a search box is shown', () => {
    const items = (c: number, _sel: (string | null)[], q: string): MillerItem[] =>
      c === 0 ? Object.keys(TREE).filter((id) => id.includes(q)).map((id) => ({ id, name: id })) : []
    render(<MillerBrowser columns={[COLUMNS[0]!]} getItems={items} searchPlaceholder="Filter…" />)
    expect(rowNames('Listeners')).toEqual(['web', 'admin', 'edge'])
    fireEvent.change(screen.getByPlaceholderText('Filter…'), { target: { value: 'ed' } })
    expect(rowNames('Listeners')).toEqual(['edge'])
  })

  it('focuses the search box on "/"', () => {
    render(<MillerBrowser columns={[COLUMNS[0]!]} getItems={() => []} searchPlaceholder="Filter…" />)
    const input = screen.getByPlaceholderText('Filter…')
    expect(document.activeElement).not.toBe(input)
    fireEvent.keyDown(document, { key: '/' })
    expect(document.activeElement).toBe(input)
  })

  it('renders a column footer below its rows, given the resolved selection', () => {
    const cols: MillerColumnDef[] = [{ id: 'a', label: 'Listeners', footer: (sel) => <div>chosen:{sel[0]}</div> }]
    render(<MillerBrowser columns={cols} getItems={getItems} />)
    expect(col('Listeners').textContent).toContain('chosen:web')
  })

  it('renders a weight meter for items that carry one', () => {
    const items = (c: number): MillerItem[] => (c === 0 ? [{ id: 'b', name: 'b', meter: { value: 73 } }] : [])
    render(<MillerBrowser columns={[COLUMNS[0]!]} getItems={items} />)
    expect(col('Listeners').textContent).toContain('73%')
  })
})
