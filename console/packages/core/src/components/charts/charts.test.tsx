// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import { cleanup, render } from '@testing-library/react'
import { Sparkline } from './sparkline'
import { TimeSeriesChart } from './time-series-chart'

// ParentSize observes its container; jsdom has no layout engine, so polyfill a
// no-op ResizeObserver to let the measured chart mount without throwing.
beforeAll(() => {
  if (typeof globalThis.ResizeObserver === 'undefined') {
    globalThis.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    } as unknown as typeof ResizeObserver
  }
})

afterEach(cleanup)

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
})
