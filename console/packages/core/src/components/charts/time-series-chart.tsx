import { useState } from 'react'
import type { MouseEvent as RMouseEvent, TouchEvent as RTouchEvent } from 'react'
import { Group } from '@visx/group'
import { ParentSize } from '@visx/responsive'
import { scaleLinear } from '@visx/scale'
import { AreaClosed, Bar, Line, LinePath } from '@visx/shape'
import { cn } from '../../lib/cn'

export interface ChartSeries {
  /** Stable key, also the tooltip row label. */
  key: string
  /** Dense values, one per bucket (index is the x position). */
  values: number[]
  /** Line/area color; any CSS color (e.g. a token var). */
  color: string
  /** Fill a faint area under the line. */
  area?: boolean
  /**
   * Y-scale group. Series on different axes are scaled independently so a small
   * series stays legible next to a large one; the `primary` group drives the
   * left-axis labels. Defaults to `primary`.
   */
  axis?: 'primary' | 'secondary'
}

export interface TimeSeriesChartProps {
  /** One or more dense series; the longest sets the bucket count. */
  series: ChartSeries[]
  height?: number
  /** Sparse labels spread evenly across the x-axis. */
  xTicks?: string[]
  /** Format the left-axis ticks and the tooltip values. */
  formatValue?: (n: number) => string
  /** Tooltip header for a hovered bucket index (e.g. its timestamp). */
  formatPoint?: (index: number) => string
  className?: string
}

const MARGIN = { top: 16, right: 16, bottom: 28, left: 52 }
// Headroom above the tallest point so peaks don't touch the top edge. The
// secondary axis gets more, as it's usually a sparse, spiky series (errors).
const PRIMARY_HEADROOM = 1.12
const SECONDARY_HEADROOM = 1.4
// Gap between the cursor and the tooltip box, in chart (user) units.
const TOOLTIP_GAP = 12

function defaultFormat(n: number): string {
  const abs = Math.abs(n)
  if (abs >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (abs >= 1_000) return (n / 1_000).toFixed(1) + 'k'
  return String(Math.round(n))
}

/**
 * A measured (ParentSize, real-pixel) line/area chart with an optional second
 * y-axis and a hover crosshair + tooltip. Deliberately not a scaled viewBox, so
 * axis text and strokes stay crisp at any width or page zoom. Colors come from
 * the caller (pass token vars) so it themes with the surrounding surface.
 */
export function TimeSeriesChart({
  height = 240,
  className,
  ...rest
}: TimeSeriesChartProps) {
  return (
    <div className={cn('relative', className)} style={{ height }}>
      <ParentSize
        parentSizeStyles={{ position: 'relative', width: '100%', height: '100%' }}
      >
        {({ width }) =>
          width > 0 ? <Chart width={width} height={height} {...rest} /> : null
        }
      </ParentSize>
    </div>
  )
}

interface HoverMarker {
  key: string
  color: string
  value: number
  y: number
}
interface HoverState {
  index: number
  /** Crosshair x, in inner-group user units. */
  x: number
  /** Pointer y, in svg-root user units (clamped to the plot area). */
  pointerY: number
  markers: HoverMarker[]
}

function Chart({
  width,
  height,
  series,
  xTicks = [],
  formatValue = defaultFormat,
  formatPoint,
}: Omit<TimeSeriesChartProps, 'height' | 'className'> & {
  width: number
  height: number
}) {
  const m = MARGIN
  const innerW = Math.max(0, width - m.left - m.right)
  const innerH = Math.max(0, height - m.top - m.bottom)
  const n = Math.max(...series.map((s) => s.values.length), 2)

  const groupMax = (group: 'primary' | 'secondary', headroom: number) => {
    let mx = 0
    for (const s of series) {
      if ((s.axis ?? 'primary') !== group) continue
      for (const v of s.values) if (v > mx) mx = v
    }
    return Math.max(mx * headroom, 1)
  }
  const maxPrimary = groupMax('primary', PRIMARY_HEADROOM)
  const maxSecondary = groupMax('secondary', SECONDARY_HEADROOM)

  const xScale = scaleLinear({ domain: [0, n - 1], range: [0, innerW] })
  const yPrimary = scaleLinear({ domain: [0, maxPrimary], range: [innerH, 0] })
  const ySecondary = scaleLinear({ domain: [0, maxSecondary], range: [innerH, 0] })
  const yScaleOf = (s: ChartSeries) =>
    (s.axis ?? 'primary') === 'secondary' ? ySecondary : yPrimary
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * maxPrimary)

  const [hover, setHover] = useState<HoverState | null>(null)

  // Map the pointer to a bucket using the svg's screen CTM, which folds in any
  // ancestor transform OR CSS `zoom` (a real case here: an app-root `zoom` makes
  // getBoundingClientRect disagree with the layout box). createSVGPoint +
  // matrixTransform(inverse) lands us in the svg's own user units regardless.
  const onMove = (
    e: RMouseEvent<SVGRectElement> | RTouchEvent<SVGRectElement>,
  ) => {
    const svg = e.currentTarget.ownerSVGElement
    const ctm = svg?.getScreenCTM()
    if (!svg || !ctm) return
    const touch = 'touches' in e ? e.touches[0] : undefined
    const pt = svg.createSVGPoint()
    pt.x = touch ? touch.clientX : (e as RMouseEvent).clientX
    pt.y = touch ? touch.clientY : (e as RMouseEvent).clientY
    const loc = pt.matrixTransform(ctm.inverse())
    // `loc` is in svg-root units; the plot is offset by the margin (the Group).
    let idx = Math.round(xScale.invert(loc.x - m.left))
    if (idx < 0) idx = 0
    else if (idx > n - 1) idx = n - 1
    const markers: HoverMarker[] = series.map((s) => {
      const value = s.values[idx] ?? 0
      return { key: s.key, color: s.color, value, y: yScaleOf(s)(value) }
    })
    const pointerY = Math.min(Math.max(loc.y, m.top), m.top + innerH)
    setHover({ index: idx, x: xScale(idx), pointerY, markers })
  }
  const onLeave = () => setHover(null)

  // Tooltip box position + flip. It lives inside the ParentSize wrapper (same
  // user-unit space as the svg, no portal, no zoom-boundary crossing), so its
  // left/top are just the crosshair x and pointer y. Flip it to whichever side
  // of the cursor has room so a high or right-edge point can't clip it.
  const anchorLeft = m.left + (hover?.x ?? 0)
  const anchorTop = hover?.pointerY ?? 0
  const flipLeft = (hover?.x ?? 0) > innerW / 2
  const flipUp = (hover ? hover.pointerY - m.top : 0) > innerH / 2
  const tx = flipLeft ? `calc(-100% - ${TOOLTIP_GAP}px)` : `${TOOLTIP_GAP}px`
  const ty = flipUp ? `calc(-100% - ${TOOLTIP_GAP}px)` : `${TOOLTIP_GAP}px`

  return (
    <>
      <svg width={width} height={height}>
        <Group left={m.left} top={m.top}>
          {yTicks.map((t, i) => (
            <Group key={i}>
              <Line
                from={{ x: 0, y: yPrimary(t) }}
                to={{ x: innerW, y: yPrimary(t) }}
                stroke="var(--border-subtle)"
              />
              <text
                x={-8}
                y={yPrimary(t) + 4}
                fontSize={11}
                textAnchor="end"
                fontFamily="var(--font-mono)"
                fill="var(--text-muted)"
              >
                {formatValue(Math.round(t))}
              </text>
            </Group>
          ))}
          <Line
            from={{ x: 0, y: innerH }}
            to={{ x: innerW, y: innerH }}
            stroke="var(--border-default)"
          />
          {series.map((s) =>
            s.area ? (
              <AreaClosed
                key={s.key + '-area'}
                data={s.values}
                x={(_v, i) => xScale(i)}
                y={(v) => yScaleOf(s)(v)}
                yScale={yScaleOf(s)}
                fill={s.color}
                opacity={0.06}
                stroke="none"
              />
            ) : null,
          )}
          {series.map((s) => (
            <LinePath
              key={s.key + '-line'}
              data={s.values}
              x={(_v, i) => xScale(i)}
              y={(v) => yScaleOf(s)(v)}
              stroke={s.color}
              strokeWidth={1.8}
              strokeLinejoin="round"
            />
          ))}
          {xTicks.map((lab, i) => (
            <text
              key={i}
              x={(i / (Math.max(xTicks.length, 2) - 1)) * innerW}
              y={innerH + 20}
              fontSize={11}
              fontFamily="var(--font-mono)"
              fill="var(--text-muted)"
              textAnchor={
                i === 0 ? 'start' : i === xTicks.length - 1 ? 'end' : 'middle'
              }
            >
              {lab}
            </text>
          ))}
          {hover && (
            <Group>
              <Line
                from={{ x: hover.x, y: 0 }}
                to={{ x: hover.x, y: innerH }}
                stroke="var(--text-muted)"
                strokeWidth={1}
                strokeDasharray="3,3"
                pointerEvents="none"
              />
              {hover.markers.map((mk, i) =>
                i === 0 || mk.value > 0 ? (
                  <circle
                    key={mk.key}
                    cx={hover.x}
                    cy={mk.y}
                    r={3}
                    fill={mk.color}
                    pointerEvents="none"
                  />
                ) : null,
              )}
            </Group>
          )}
          <Bar
            x={0}
            y={0}
            width={innerW}
            height={innerH}
            fill="transparent"
            onMouseMove={onMove}
            onTouchMove={onMove}
            onMouseLeave={onLeave}
            onTouchEnd={onLeave}
          />
        </Group>
      </svg>
      {hover && (
        <div
          className="pointer-events-none absolute z-10 whitespace-nowrap rounded-none border border-[color:var(--border-default)] bg-[var(--apx-white)] px-[10px] py-[8px] text-[11px] leading-[1.6] text-[color:var(--text-primary)] shadow-[0_6px_18px_rgba(0,0,0,0.12)] [font-family:var(--font-mono)]"
          style={{
            left: anchorLeft,
            top: anchorTop,
            transform: `translate(${tx}, ${ty})`,
          }}
        >
          {formatPoint && (
            <div className="mb-[4px] text-[color:var(--text-muted)]">
              {formatPoint(hover.index)}
            </div>
          )}
          {hover.markers.map((mk) => (
            <div key={mk.key} className="flex items-center gap-[7px]">
              <span
                className="h-[9px] w-[9px] flex-none rounded-none"
                style={{ background: mk.color }}
              />
              {formatValue(mk.value)} {mk.key}
            </div>
          ))}
        </div>
      )}
    </>
  )
}
