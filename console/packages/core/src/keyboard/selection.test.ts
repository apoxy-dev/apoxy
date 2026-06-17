import { describe, expect, it } from 'vitest'
import { moveMiller, nextIndex } from './selection'

describe('nextIndex (1-D)', () => {
  it('clamps at the ends without loop', () => {
    expect(nextIndex(0, -1, 5, false)).toBe(0)
    expect(nextIndex(4, 1, 5, false)).toBe(4)
    expect(nextIndex(2, 1, 5, false)).toBe(3)
  })
  it('wraps when looping', () => {
    expect(nextIndex(0, -1, 5, true)).toBe(4)
    expect(nextIndex(4, 1, 5, true)).toBe(0)
  })
  it('selects an end when nothing is selected yet', () => {
    expect(nextIndex(-1, 1, 5, false)).toBe(0)
    expect(nextIndex(-1, -1, 5, false)).toBe(4)
  })
  it('returns -1 for an empty list', () => {
    expect(nextIndex(0, 1, 0, false)).toBe(-1)
  })
})

describe('moveMiller (2-D)', () => {
  const cols = [3, 1, 2] // column 0 has 3 rows, column 1 has 1, column 2 has 2

  it('moves within a column', () => {
    expect(moveMiller({ col: 0, row: 0 }, 0, 1, cols)).toEqual({ col: 0, row: 1 })
    expect(moveMiller({ col: 0, row: 0 }, 0, -1, cols)).toEqual({ col: 0, row: 0 })
    expect(moveMiller({ col: 0, row: 2 }, 0, 1, cols)).toEqual({ col: 0, row: 2 })
  })

  it('clamps the row when entering a shorter column', () => {
    // row 2 in col 0 → col 1 has only 1 row → clamp to row 0
    expect(moveMiller({ col: 0, row: 2 }, 1, 0, cols)).toEqual({ col: 1, row: 0 })
  })

  it('keeps the row when the destination column is tall enough', () => {
    expect(moveMiller({ col: 2, row: 1 }, -1, 0, cols)).toEqual({ col: 1, row: 0 })
    expect(moveMiller({ col: 1, row: 0 }, 1, 0, cols)).toEqual({ col: 2, row: 0 })
  })

  it('stops at the edges', () => {
    expect(moveMiller({ col: 0, row: 0 }, -1, 0, cols)).toEqual({ col: 0, row: 0 })
    expect(moveMiller({ col: 2, row: 0 }, 1, 0, cols)).toEqual({ col: 2, row: 0 })
  })

  it('skips empty columns horizontally', () => {
    const withGap = [2, 0, 2]
    expect(moveMiller({ col: 0, row: 1 }, 1, 0, withGap)).toEqual({ col: 2, row: 1 })
  })

  it('selects the first/last row from an unset cursor', () => {
    expect(moveMiller({ col: 0, row: -1 }, 0, 1, cols)).toEqual({ col: 0, row: 0 })
    expect(moveMiller({ col: 0, row: -1 }, 0, -1, cols)).toEqual({ col: 0, row: 2 })
  })

  it('handles no columns', () => {
    expect(moveMiller({ col: 0, row: 0 }, 1, 0, [])).toEqual({ col: 0, row: -1 })
  })

  it('stays put when only empty columns lie in the move direction', () => {
    // Trailing empty columns: ArrowRight must not deselect onto an empty column.
    expect(moveMiller({ col: 0, row: 1 }, 1, 0, [2, 0, 0])).toEqual({ col: 0, row: 1 })
    // Leading empty columns: ArrowLeft must not deselect either.
    expect(moveMiller({ col: 2, row: 1 }, -1, 0, [0, 0, 2])).toEqual({ col: 2, row: 1 })
  })
})
