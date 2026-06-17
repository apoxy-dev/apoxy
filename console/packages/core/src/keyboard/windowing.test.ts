import { describe, expect, it } from 'vitest'
import { computeWindow } from './windowing'

describe('computeWindow', () => {
  it('windows a long list around the scroll offset', () => {
    const w = computeWindow({ scrollTop: 1000, viewportHeight: 400, itemHeight: 40, count: 1000, overscan: 2 })
    // firstVisible = 25, visibleCount = 10
    expect(w.start).toBe(23)
    expect(w.end).toBe(37)
    expect(w.paddingTop).toBe(23 * 40)
    expect(w.paddingBottom).toBe((1000 - 37) * 40)
    expect(w.totalHeight).toBe(1000 * 40)
  })

  it('clamps the slice at the top', () => {
    const w = computeWindow({ scrollTop: 0, viewportHeight: 400, itemHeight: 40, count: 1000, overscan: 4 })
    expect(w.start).toBe(0)
    expect(w.paddingTop).toBe(0)
  })

  it('clamps the slice at the bottom', () => {
    const w = computeWindow({ scrollTop: 1_000_000, viewportHeight: 400, itemHeight: 40, count: 1000 })
    expect(w.end).toBe(1000)
    expect(w.start).toBeLessThanOrEqual(1000)
    expect(w.paddingBottom).toBe(0)
  })

  it('renders everything when the row height is unmeasured', () => {
    const w = computeWindow({ scrollTop: 0, viewportHeight: 0, itemHeight: 0, count: 50 })
    expect(w).toEqual({ start: 0, end: 50, paddingTop: 0, paddingBottom: 0, totalHeight: 0 })
  })

  it('handles an empty list', () => {
    expect(computeWindow({ scrollTop: 0, viewportHeight: 400, itemHeight: 40, count: 0 })).toEqual({
      start: 0,
      end: 0,
      paddingTop: 0,
      paddingBottom: 0,
      totalHeight: 0,
    })
  })

  it('never produces a negative slice for a wild scrollTop', () => {
    const w = computeWindow({ scrollTop: -500, viewportHeight: 400, itemHeight: 40, count: 10 })
    expect(w.start).toBeGreaterThanOrEqual(0)
    expect(w.end).toBeGreaterThanOrEqual(w.start)
    expect(w.end).toBeLessThanOrEqual(10)
  })
})
