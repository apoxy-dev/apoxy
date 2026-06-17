// Keyboard selection cursors (APO-780). Two shapes:
//   • useListSelection — a 1-D cursor for tables and the palette list
//     (↑/↓/Home/End/Enter, optional wrap).
//   • useMillerSelection — a 2-D cursor for Miller columns (←/→ switch column,
//     ↑/↓ move within it), where each column can hold a different row count.
// Both keep their cursor in React state and expose a stable `onKeyDown`, so the
// movement logic is component-agnostic and the math is unit-testable in isolation
// via the exported pure reducers.

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'

// --- 1-D list ---------------------------------------------------------------

/** Next index for a vertical move; clamps, or wraps when `loop`. `-1` means none. */
export function nextIndex(current: number, delta: number, count: number, loop: boolean): number {
  if (count <= 0) return -1
  if (current < 0) return delta > 0 ? 0 : count - 1
  const raw = current + delta
  if (loop) return ((raw % count) + count) % count
  return Math.min(count - 1, Math.max(0, raw))
}

export interface UseListSelectionOptions {
  count: number
  /** Wrap from last↔first instead of stopping at the ends. Defaults to false. */
  loop?: boolean
  /** Activate (Enter) the row at `index`. */
  onActivate?: (index: number) => void
  /** Initial cursor; `-1` (default) means nothing selected. */
  initialIndex?: number
  /**
   * Optional stable identity for each row (parallel to `count`). When supplied,
   * the cursor follows the *selected item* across list mutations — a delete or
   * reorder under the cursor re-points it to the same item's new position rather
   * than leaving it on whatever now sits at the old index.
   */
  keys?: readonly string[]
}

export interface ListSelection {
  index: number
  setIndex: (index: number) => void
  move: (delta: number) => void
  activate: () => void
  /** Attach to a focusable container to drive the cursor with the keyboard. */
  onKeyDown: (e: { key: string; preventDefault: () => void }) => void
}

export function useListSelection(opts: UseListSelectionOptions): ListSelection {
  const { count, loop = false, onActivate, initialIndex = -1, keys } = opts
  const [index, setIndexState] = useState(initialIndex)

  // Without identity keys, just keep the cursor in range as the list shrinks
  // (rows deleted under it). With keys, the anchor effect below owns range too.
  useEffect(() => {
    if (keys) return
    if (index > count - 1) setIndexState(count > 0 ? count - 1 : -1)
  }, [count, index, keys])

  // Identity anchoring: when `keys` changes, move the cursor to follow the item
  // it pointed at to that item's new position (pre-paint, so the highlight never
  // visibly jumps to the wrong row). Done off the *previous* keys so we know
  // which item was selected before the mutation.
  const prevKeys = useRef<readonly string[] | undefined>(keys)
  useLayoutEffect(() => {
    const pk = prevKeys.current
    prevKeys.current = keys
    if (!keys || !pk || pk === keys) return
    setIndexState((cur) => {
      if (cur < 0) return cur
      const selected = pk[cur]
      if (selected === undefined) return clampIndex(cur, keys.length)
      const at = keys.indexOf(selected)
      return at >= 0 ? at : clampIndex(cur, keys.length)
    })
  }, [keys])

  const ref = useRef({ index, count, loop, onActivate })
  ref.current = { index, count, loop, onActivate }

  const setIndex = useCallback((i: number) => setIndexState(clampIndex(i, ref.current.count)), [])
  const move = useCallback(
    (delta: number) => setIndexState((cur) => nextIndex(cur, delta, ref.current.count, ref.current.loop)),
    [],
  )
  const activate = useCallback(() => {
    const { index: i, count: c, onActivate: cb } = ref.current
    if (cb && i >= 0 && i < c) cb(i)
  }, [])

  const onKeyDown = useCallback(
    (e: { key: string; preventDefault: () => void }) => {
      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault()
          move(1)
          break
        case 'ArrowUp':
          e.preventDefault()
          move(-1)
          break
        case 'Home':
          e.preventDefault()
          setIndex(0)
          break
        case 'End':
          e.preventDefault()
          setIndex(ref.current.count - 1)
          break
        case 'Enter':
          e.preventDefault()
          activate()
          break
      }
    },
    [move, setIndex, activate],
  )

  return { index, setIndex, move, activate, onKeyDown }
}

function clampIndex(i: number, count: number): number {
  if (count <= 0) return -1
  return Math.min(count - 1, Math.max(0, i))
}

// --- 2-D Miller columns -----------------------------------------------------

export interface MillerCursor {
  col: number
  row: number
}

/**
 * Move a Miller cursor. `columns` is the row-count of each column. Horizontal
 * moves keep the row but clamp it to the destination column's length (a shorter
 * column lands the cursor on its last row); vertical moves clamp within the
 * current column. Empty columns are skipped horizontally.
 */
export function moveMiller(cursor: MillerCursor, dCol: number, dRow: number, columns: number[]): MillerCursor {
  if (columns.length === 0) return { col: 0, row: -1 }

  if (dCol !== 0) {
    let col = cursor.col
    const step = dCol > 0 ? 1 : -1
    // Skip over empty columns so ←/→ always lands somewhere selectable.
    let landed = false
    for (let i = 0; i < columns.length; i++) {
      const next = col + step
      if (next < 0 || next >= columns.length) break
      col = next
      if ((columns[col] ?? 0) > 0) {
        landed = true
        break
      }
    }
    // Only empty columns lie in this direction — keep the current selection
    // rather than walking the cursor onto an empty column and deselecting.
    if (!landed) return cursor
    const rows = columns[col] ?? 0
    const row = Math.min(cursor.row < 0 ? 0 : cursor.row, rows - 1)
    return { col, row }
  }

  const rows = columns[cursor.col] ?? 0
  if (rows <= 0) return { col: cursor.col, row: -1 }
  const row = cursor.row < 0 ? (dRow > 0 ? 0 : rows - 1) : Math.min(rows - 1, Math.max(0, cursor.row + dRow))
  return { col: cursor.col, row }
}

export interface UseMillerSelectionOptions {
  /** Row count of each column, left to right. */
  columns: number[]
  onActivate?: (cursor: MillerCursor) => void
  initial?: MillerCursor
}

export interface MillerSelection {
  cursor: MillerCursor
  setCursor: (cursor: MillerCursor) => void
  activate: () => void
  onKeyDown: (e: { key: string; preventDefault: () => void }) => void
}

export function useMillerSelection(opts: UseMillerSelectionOptions): MillerSelection {
  const { columns, onActivate, initial = { col: 0, row: -1 } } = opts
  const [cursor, setCursor] = useState<MillerCursor>(initial)

  const ref = useRef({ cursor, columns, onActivate })
  ref.current = { cursor, columns, onActivate }

  // Columns key so the effect re-clamps when column shapes change.
  const colsKey = useMemo(() => columns.join(','), [columns])
  useEffect(() => {
    setCursor((cur) => {
      const cols = ref.current.columns
      if (cols.length === 0) return { col: 0, row: -1 }
      const col = Math.min(cur.col, cols.length - 1)
      const rows = cols[col] ?? 0
      return { col, row: rows > 0 ? Math.min(cur.row, rows - 1) : -1 }
    })
  }, [colsKey])

  const move = useCallback(
    (dCol: number, dRow: number) => setCursor((cur) => moveMiller(cur, dCol, dRow, ref.current.columns)),
    [],
  )
  const activate = useCallback(() => {
    const { cursor: c, columns: cols, onActivate: cb } = ref.current
    if (cb && c.row >= 0 && c.col < cols.length && c.row < (cols[c.col] ?? 0)) cb(c)
  }, [])

  const onKeyDown = useCallback(
    (e: { key: string; preventDefault: () => void }) => {
      switch (e.key) {
        case 'ArrowRight':
          e.preventDefault()
          move(1, 0)
          break
        case 'ArrowLeft':
          e.preventDefault()
          move(-1, 0)
          break
        case 'ArrowDown':
          e.preventDefault()
          move(0, 1)
          break
        case 'ArrowUp':
          e.preventDefault()
          move(0, -1)
          break
        case 'Enter':
          e.preventDefault()
          activate()
          break
      }
    },
    [move, activate],
  )

  return { cursor, setCursor, activate, onKeyDown }
}
