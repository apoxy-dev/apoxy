// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import { cleanup, fireEvent, render, waitFor } from '@testing-library/react'
import { Sparkline } from './sparkline'
import { TimeSeriesChart, fitTicks, tickDecimals } from './time-series-chart'

const CHART_W = 600
const CHART_H = 240
/** Left margin of the chart, to turn a plot x into a client x. */
const MARGIN_LEFT = 52

// ParentSize measures its container with a ResizeObserver; jsdom has no layout
// engine, so report a fixed box to make the chart mount at a real width.
beforeAll(() => {
  globalThis.ResizeObserver = class {
    constructor(private cb: ResizeObserverCallback) {}
    observe(target: Element) {
      this.cb(
        [
          {
            target,
            contentRect: { width: CHART_W, height: CHART_H, top: 0, left: 0 },
          },
        ] as unknown as ResizeObserverEntry[],
        this as unknown as ResizeObserver,
      )
    }
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
})

afterEach(cleanup)

/** X of the triangle apex, the last point of the `points` attribute. */
function apexX(tri: Element | undefined): number {
  const pts = (tri?.getAttribute('points') ?? '').trim().split(/\s+/)
  return Number((pts[pts.length - 1] ?? '').split(',')[0])
}

/** Plot width, read off a horizontal grid line so the test needs no margins. */
function plotWidth(container: HTMLElement): number {
  const grid = Array.from(container.querySelectorAll('line')).find(
    (l) => l.getAttribute('y1') === l.getAttribute('y2'),
  )
  return Number(grid?.getAttribute('x2'))
}

describe('fitTicks', () => {
  const wide = ['09-06 23:16', '09-08 05:16', '09-09 11:16', '09-10 17:16', '09-11 23:16']

  const cases: Array<{ name: string; labels: string[]; width: number; want: number[] }> = [
    // 11 characters take 77 px, so only four fit in 350 px.
    { name: 'thins wide labels on a narrow plot', labels: wide, width: 350, want: [0, 1, 3, 4] },
    { name: 'keeps every wide label on a wide plot', labels: wide, width: 900, want: [0, 1, 2, 3, 4] },
    // The same plot holds all five once the label is the date alone.
    {
      name: 'keeps every short label where a wide one would not fit',
      labels: ['09-06', '09-08', '09-09', '09-10', '09-11'],
      width: 350,
      want: [0, 1, 2, 3, 4],
    },
    // Never below the two ends.
    { name: 'keeps the two ends however narrow the plot', labels: wide, width: 10, want: [0, 4] },
    { name: 'reports nothing for no labels', labels: [], width: 350, want: [] },
    { name: 'keeps a lone label', labels: ['09-06 23:16'], width: 10, want: [0] },
  ]

  for (const { name, labels, width, want } of cases) {
    it(name, () => {
      expect(fitTicks(labels, width).map((t) => t.index)).toEqual(want)
    })
  }

  it('carries the label of the place it was picked from', () => {
    expect(fitTicks(wide, 10)).toEqual([
      { label: '09-06 23:16', index: 0 },
      { label: '09-11 23:16', index: 4 },
    ])
  })
})

describe('tickDecimals', () => {
  const cases: Array<[number, number]> = [
    [10, 0],
    [1, 0],
    [0.25, 1],
    [0.1, 1],
    [0.05, 2],
    [0, 2],
    [Number.NaN, 0],
  ]
  for (const [step, want] of cases) {
    it(`asks for ${want} decimals at a step of ${step}`, () => {
      expect(tickDecimals(step)).toBe(want)
    })
  }
})

describe('Sparkline', () => {
  it('renders an svg for a multi-point series with a fill', () => {
    const { container } = render(<Sparkline values={[1, 4, 2, 8, 5]} fill />)
    expect(container.querySelector('svg')).not.toBeNull()
  })

  it('renders an empty svg below two points', () => {
    const { container } = render(<Sparkline values={[3]} />)
    expect(container.querySelector('svg')).not.toBeNull()
  })
})

describe('TimeSeriesChart', () => {
  const series = [
    { key: 'invocations', values: [10, 20, 5, 30], color: 'var(--apx-ink)' },
  ]

  it('mounts without throwing for one or two axes', () => {
    expect(() =>
      render(
        <TimeSeriesChart
          series={[
            {
              key: 'invocations',
              values: [10, 20, 5, 30],
              color: 'var(--apx-ink)',
              area: true,
            },
            {
              key: 'errors',
              values: [0, 1, 0, 2],
              color: 'var(--apx-coral)',
              axis: 'secondary',
            },
          ]}
          xTicks={['a', 'b', 'c']}
          formatValue={(n) => String(n)}
          formatPoint={(i) => `bucket ${i}`}
        />,
      ),
    ).not.toThrow()
  })

  it('draws a marker at the bucket x and drops the out-of-range ones', async () => {
    const { container } = render(
      <TimeSeriesChart
        series={series}
        markers={[
          { index: 0, label: 'Envoy exit: a (1)' },
          { index: 3, label: 'Envoy exit: b (2)' },
          { index: 9, label: 'past the last bucket' },
          { index: -1, label: 'before the first bucket' },
        ]}
      />,
    )
    const tris = await waitFor(() => {
      const found = container.querySelectorAll('polygon')
      expect(found).toHaveLength(2)
      return found
    })
    const innerW = plotWidth(container)
    expect(innerW).toBeGreaterThan(0)
    // First and last bucket sit on the two edges of the plot.
    expect(apexX(tris[0])).toBeCloseTo(0)
    expect(apexX(tris[1])).toBeCloseTo(innerW)
    const vertical = Array.from(container.querySelectorAll('line')).filter(
      (l) => l.getAttribute('x1') === l.getAttribute('x2'),
    )
    expect(vertical.map((l) => Number(l.getAttribute('x1')))).toEqual([
      0,
      innerW,
    ])
    expect(
      Array.from(container.querySelectorAll('title')).map((t) => t.textContent),
    ).toEqual(['Envoy exit: a (1)', 'Envoy exit: b (2)'])
  })

  it('dashes only the series that asks for it', async () => {
    const { container } = render(
      <TimeSeriesChart
        series={[
          { key: 'measured', values: [10, 20, 5, 30], color: 'var(--apx-ink)' },
          { key: 'limit', values: [25, 25, 25, 25], color: 'var(--apx-slate)', dash: true },
        ]}
      />,
    )
    const paths = await waitFor(() => {
      const found = container.querySelectorAll('path')
      expect(found).toHaveLength(2)
      return found
    })
    expect(paths[0]?.getAttribute('stroke-dasharray')).toBeNull()
    expect(paths[1]?.getAttribute('stroke-dasharray')).toBe('4 3')
  })

  it('breaks the line over a null bucket', async () => {
    const { container } = render(
      <TimeSeriesChart
        series={[
          { key: 'active', values: [10, null, 30, 20], color: 'var(--apx-ink)' },
        ]}
      />,
    )
    const path = await waitFor(() => {
      const found = container.querySelector('path')
      expect(found).not.toBeNull()
      return found as SVGPathElement
    })
    // Two move commands, so the hole is a break and not a dip to zero.
    const d = path.getAttribute('d') ?? ''
    expect(d.match(/M/g) ?? []).toHaveLength(2)
  })

  it('leaves a null bucket out of the y scale', async () => {
    const { container } = render(
      <TimeSeriesChart
        series={[{ key: 'active', values: [null, 50, null], color: 'var(--apx-ink)' }]}
        formatValue={(n) => String(n)}
      />,
    )
    const ticks = await waitFor(() => {
      const found = Array.from(container.querySelectorAll('text')).map(
        (t) => t.textContent,
      )
      expect(found).toHaveLength(5)
      return found
    })
    // The top tick is the headroom over 50, the only measured value.
    expect(ticks).toEqual(['0', '14', '28', '42', '56'])
  })

  it('gives a sub-percent domain the decimals its ticks need', async () => {
    const { container } = render(
      <TimeSeriesChart series={[{ key: 'heap', values: [0.2, 0.8, 0.5], color: 'var(--apx-ink)' }]} />,
    )
    const ticks = await waitFor(() => {
      const found = Array.from(container.querySelectorAll('text')).map((t) => t.textContent ?? '')
      expect(found).toHaveLength(5)
      return found
    })
    expect(ticks).toEqual(['0.0', '0.3', '0.5', '0.8', '1.0'])
    expect(new Set(ticks).size).toBe(5)
  })

  it('hands the tick decimals to the formatter of the caller', async () => {
    const { container } = render(
      <TimeSeriesChart
        series={[{ key: 'heap', values: [0.2, 0.8, 0.5], color: 'var(--apx-ink)' }]}
        formatValue={(n, d = 0) => `${n.toFixed(d)}%`}
      />,
    )
    const ticks = await waitFor(() => {
      const found = Array.from(container.querySelectorAll('text')).map((t) => t.textContent ?? '')
      expect(found).toHaveLength(5)
      return found
    })
    expect(ticks).toEqual(['0.0%', '0.3%', '0.5%', '0.8%', '1.0%'])
  })

  it('drops the x labels the plot has no room for, keeping both ends', async () => {
    const labels = Array.from({ length: 9 }, (_, i) => `09-0${i + 1} 23:16`)
    const { container } = render(
      <TimeSeriesChart series={series} xTicks={labels} formatValue={(n) => String(n)} />,
    )
    const texts = await waitFor(() => {
      const found = Array.from(container.querySelectorAll('text')).map((t) => t.textContent ?? '')
      expect(found.length).toBeGreaterThan(5)
      return found
    })
    // The y ticks are plain numbers, so a dash marks an x label.
    const shown = texts.filter((t) => t.includes('-'))
    expect(shown.length).toBeLessThan(labels.length)
    expect(shown[0]).toBe(labels[0])
    expect(shown[shown.length - 1]).toBe(labels[labels.length - 1])
  })

  it('shows a dash for a null bucket in the tooltip', async () => {
    const { container } = render(
      <TimeSeriesChart
        series={[{ key: 'active', values: [10, null, 30], color: 'var(--apx-ink)' }]}
        formatValue={(n) => String(n)}
      />,
    )
    const bar = await waitFor(() => {
      const r = container.querySelector('rect')
      expect(r).not.toBeNull()
      return r as SVGRectElement
    })
    const innerW = plotWidth(container)
    // Middle of the plot, which is the null bucket.
    fireEvent.mouseMove(bar, { clientX: MARGIN_LEFT + innerW / 2, clientY: 20 })
    const tip = container.querySelector('svg')?.nextElementSibling
    expect(tip?.textContent).toContain('— active')
    // The dot is dropped as well, so nothing is drawn at zero.
    expect(container.querySelectorAll('circle')).toHaveLength(0)
  })

  it('puts the markers of the hovered bucket in the tooltip header', async () => {
    const { container } = render(
      <TimeSeriesChart
        series={series}
        markers={[
          { index: 0, label: 'Envoy exit: a (1)' },
          { index: 3, label: 'Envoy exit: b (2)' },
        ]}
        formatPoint={(i) => `bucket ${i}`}
      />,
    )
    const bar = await waitFor(() => {
      const r = container.querySelector('rect')
      expect(r).not.toBeNull()
      return r as SVGRectElement
    })
    // Left of the plot, so the hover snaps to bucket 0, which has a marker.
    fireEvent.mouseMove(bar, { clientX: 0, clientY: 20 })
    const tip = container.querySelector('svg')?.nextElementSibling
    expect(tip?.textContent).toContain('bucket 0')
    expect(tip?.textContent).toContain('Envoy exit: a (1)')
    expect(tip?.textContent).not.toContain('Envoy exit: b (2)')
  })

  describe('marker hit target', () => {
    const markers = [
      { index: 0, label: 'Envoy exit: a (1)' },
      { index: 3, label: 'Envoy exit: b (2)' },
    ]

    function renderMarked() {
      return render(
        <TimeSeriesChart
          series={series}
          markers={markers}
          formatValue={(n) => String(n)}
          formatPoint={(i) => `bucket ${i}`}
        />,
      )
    }

    /** The hit target of one marker, found by the label it carries. */
    async function hitOf(container: HTMLElement, label: string) {
      return await waitFor(() => {
        const el = container.querySelector(`rect[aria-label="${label}"]`)
        expect(el).not.toBeNull()
        return el as SVGRectElement
      })
    }

    it('shows the bucket time and the label of the marker under the pointer', async () => {
      const { container } = renderMarked()
      const hit = await hitOf(container, 'Envoy exit: b (2)')

      fireEvent.mouseOver(hit)
      const tip = container.querySelector('svg')?.nextElementSibling
      expect(tip?.textContent).toContain('bucket 3')
      expect(tip?.textContent).toContain('Envoy exit: b (2)')
      // Only the marker of that bucket, the same as a column hover.
      expect(tip?.textContent).not.toContain('Envoy exit: a (1)')
      // The bucket's series rows stay.
      expect(tip?.textContent).toContain('30 invocations')
    })

    it('hides the tooltip again when the pointer leaves the marker', async () => {
      const { container } = renderMarked()
      const hit = await hitOf(container, 'Envoy exit: a (1)')

      fireEvent.mouseOver(hit)
      expect(container.querySelector('svg')?.nextElementSibling).not.toBeNull()
      fireEvent.mouseOut(hit)
      expect(container.querySelector('svg')?.nextElementSibling).toBeNull()
    })

    it('keeps the plot hover in front of a marker the pointer left', async () => {
      const { container } = renderMarked()
      const hit = await hitOf(container, 'Envoy exit: a (1)')
      const bar = container.querySelector('rect') as SVGRectElement
      const innerW = plotWidth(container)

      fireEvent.mouseOver(hit)
      // Into the plot, on the last bucket: the column hover wins.
      fireEvent.mouseMove(bar, { clientX: MARGIN_LEFT + innerW, clientY: 20 })
      const tip = container.querySelector('svg')?.nextElementSibling
      expect(tip?.textContent).toContain('bucket 3')
      expect(tip?.textContent).not.toContain('Envoy exit: a (1)')
    })

    it('gives the triangle a focusable target of at least 14 by 14', async () => {
      const { container } = renderMarked()
      const hit = await hitOf(container, 'Envoy exit: a (1)')
      const tri = container.querySelector('polygon')

      expect(Number(hit.getAttribute('width'))).toBeGreaterThanOrEqual(14)
      expect(Number(hit.getAttribute('height'))).toBeGreaterThanOrEqual(14)
      expect(hit.getAttribute('tabindex')).toBe('0')
      expect(hit.getAttribute('pointer-events')).toBe('all')
      // Centered on the triangle apex.
      const mid = Number(hit.getAttribute('x')) + Number(hit.getAttribute('width')) / 2
      expect(mid).toBeCloseTo(apexX(tri ?? undefined))
    })
  })
})
