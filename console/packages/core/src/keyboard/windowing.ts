// Pure virtualization math (APO-780). Given a scroll offset and fixed row
// height, compute the slice of rows to render plus the top/bottom spacer heights
// that keep the scrollbar honest. No DOM, no React — just arithmetic, so it is
// exhaustively unit-testable and the same helper backs the table and the
// palette list.

export interface WindowInput {
  /** Current scroll offset of the viewport, in px. */
  scrollTop: number
  /** Visible height of the viewport, in px. */
  viewportHeight: number
  /** Fixed height of one row, in px. */
  itemHeight: number
  /** Total number of rows. */
  count: number
  /** Extra rows rendered above/below the viewport to avoid blank flashes. */
  overscan?: number
}

export interface WindowResult {
  /** First rendered index (inclusive). */
  start: number
  /** Last rendered index (exclusive). */
  end: number
  /** Spacer height above the rendered slice, in px. */
  paddingTop: number
  /** Spacer height below the rendered slice, in px. */
  paddingBottom: number
  /** Total scrollable height, in px. */
  totalHeight: number
}

/**
 * The rows to render for a fixed-height list. Degrades safely: a non-positive
 * `itemHeight` (unmeasured) renders everything, and all bounds are clamped to
 * `[0, count]` so a wild `scrollTop` can never produce a negative slice.
 */
export function computeWindow(input: WindowInput): WindowResult {
  const { scrollTop, viewportHeight, itemHeight, count } = input
  const overscan = Math.max(0, input.overscan ?? 4)

  if (count <= 0) {
    return { start: 0, end: 0, paddingTop: 0, paddingBottom: 0, totalHeight: 0 }
  }
  const totalHeight = itemHeight > 0 ? count * itemHeight : 0

  // Unmeasured row height ⇒ can't window; render all rows.
  if (itemHeight <= 0) {
    return { start: 0, end: count, paddingTop: 0, paddingBottom: 0, totalHeight }
  }

  const safeTop = Math.max(0, scrollTop)
  const firstVisible = Math.floor(safeTop / itemHeight)
  const visibleCount = Math.max(1, Math.ceil(Math.max(0, viewportHeight) / itemHeight))

  const start = clamp(firstVisible - overscan, 0, count)
  const end = clamp(firstVisible + visibleCount + overscan, start, count)

  return {
    start,
    end,
    paddingTop: start * itemHeight,
    paddingBottom: (count - end) * itemHeight,
    totalHeight,
  }
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n))
}
