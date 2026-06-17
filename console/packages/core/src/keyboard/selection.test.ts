// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { moveMiller, nextIndex, useListSelection, useMillerSelection } from './selection'

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

describe('useListSelection identity anchoring', () => {
  const setup = (keys: string[]) =>
    renderHook((p: { keys: string[] }) => useListSelection({ count: p.keys.length, keys: p.keys }), {
      initialProps: { keys },
    })

  it('follows the selected item when a row above it is removed', () => {
    const { result, rerender } = setup(['a', 'b', 'c', 'd'])
    act(() => result.current.setIndex(2)) // select 'c'
    expect(result.current.index).toBe(2)
    rerender({ keys: ['b', 'c', 'd'] }) // 'a' deleted above the cursor
    expect(result.current.index).toBe(1) // cursor still on 'c'
  })

  it('follows the selected item across a reorder that keeps the count', () => {
    const { result, rerender } = setup(['a', 'b', 'c'])
    act(() => result.current.setIndex(0)) // select 'a'
    rerender({ keys: ['c', 'b', 'a'] }) // reversed
    expect(result.current.index).toBe(2) // cursor still on 'a'
  })

  it('clamps into range when the selected item itself is removed', () => {
    const { result, rerender } = setup(['a', 'b', 'c'])
    act(() => result.current.setIndex(2)) // select 'c'
    rerender({ keys: ['a', 'b'] }) // 'c' deleted
    expect(result.current.index).toBe(1) // clamped to the last surviving row
  })
})

describe('useMillerSelection (hook)', () => {
  const key = (e: { key: string }) => ({ ...e, preventDefault: () => {} })

  it('drives the 2-D cursor from arrow keys', () => {
    const { result } = renderHook(() => useMillerSelection({ columns: [2, 3, 1] }))
    expect(result.current.cursor).toEqual({ col: 0, row: -1 })
    act(() => result.current.onKeyDown(key({ key: 'ArrowDown' }))) // first row of col 0
    expect(result.current.cursor).toEqual({ col: 0, row: 0 })
    act(() => result.current.onKeyDown(key({ key: 'ArrowRight' }))) // into col 1
    expect(result.current.cursor).toEqual({ col: 1, row: 0 })
    act(() => result.current.onKeyDown(key({ key: 'ArrowDown' })))
    expect(result.current.cursor).toEqual({ col: 1, row: 1 })
  })

  it('activates the cursor only on a real cell', () => {
    const seen: Array<{ col: number; row: number }> = []
    const { result } = renderHook(() => useMillerSelection({ columns: [2], onActivate: (c) => seen.push(c) }))
    act(() => result.current.onKeyDown(key({ key: 'Enter' }))) // row === -1, no-op
    expect(seen).toEqual([])
    act(() => result.current.setCursor({ col: 0, row: 1 }))
    act(() => result.current.onKeyDown(key({ key: 'Enter' })))
    expect(seen).toEqual([{ col: 0, row: 1 }])
  })

  it('re-clamps the cursor when the column shapes shrink', () => {
    const { result, rerender } = renderHook((p: { columns: number[] }) => useMillerSelection(p), {
      initialProps: { columns: [3, 3] },
    })
    act(() => result.current.setCursor({ col: 1, row: 2 }))
    rerender({ columns: [3, 1] }) // col 1 lost rows under the cursor
    expect(result.current.cursor).toEqual({ col: 1, row: 0 })
    rerender({ columns: [2] }) // col 1 disappeared entirely → cursor falls back to col 0
    expect(result.current.cursor).toEqual({ col: 0, row: 0 })
  })
})
