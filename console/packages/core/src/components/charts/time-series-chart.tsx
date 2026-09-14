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
  /** Dense values, one per bucket (index is the x position). A `null` is a
   *  bucket with no measurement: the line breaks over it and the tooltip
   *  shows a dash. */
  values: (number | null)[]
  /** Line/area color; any CSS color (e.g. a token var). */
  color: string
  /** Fill a faint area under the line. */
  area?: boolean
  /** Draw the line dashed, e.g. for a limit or a derived series. */
  dash?: boolean
  /**
   * Y-scale group. Series on different axes are scaled independently so a small
   * series stays legible next to a large one; the `primary` group drives the
   * left-axis labels. Defaults to `primary`.
   */
  axis?: 'primary' | 'secondary'
}

export interface ChartMarker {
  /** Bucket index the marker sits on. */
  index: number
  /** Text shown in the marker's `<title>` and in the tooltip header. */
  label: string
  /** Line and triangle color; defaults to coral. */
  color?: string
}

export interface TimeSeriesChartProps {
  /** One or more dense series; the longest sets the bucket count. */
  series: ChartSeries[]
  height?: number
  /** Sparse labels spread evenly across the x-axis. The chart drops as many as
   *  the plot width needs, so a caller may pass more than fit. */
  xTicks?: string[]
  /** Format the left-axis ticks and the tooltip values. `decimals` is the
   *  precision an axis tick needs to differ from its neighbour; it is absent
   *  for a tooltip value. */
  formatValue?: (n: number, decimals?: number) => string
  /** Tooltip header for a hovered bucket index (e.g. its timestamp). */
  formatPoint?: (index: number) => string
  /** Event markers on single buckets; markers outside the buckets are dropped. */
  markers?: ChartMarker[]
  className?: string
}

const MARGIN = { top: 16, right: 16, bottom: 28, left: 52 }
// Headroom above the tallest point so peaks don't touch the top edge. The
// secondary axis gets more, as it's usually a sparse, spiky series (errors).
const PRIMARY_HEADROOM = 1.12
const SECONDARY_HEADROOM = 1.4
// Gap between the cursor and the tooltip box, in chart (user) units.
const TOOLTIP_GAP = 12
// Stroke pattern of a `dash` series.
const DASH_PATTERN = '4 3'
// Tooltip row of a bucket with no measurement.
const NO_VALUE = '—'
// Marker triangle, in the top margin: svg y 4 (base) to 12 (apex).
const MARKER_TOP = 4
const MARKER_SIZE = 8
// Square hit target centered on the triangle, so the pointer finds an 8px
// glyph.
const MARKER_HIT = 16
// Width one character of an x-axis label takes, at the 11px monospace face.
// Rounded up from the real advance, which leaves a space between two labels.
const TICK_CHAR_PX = 7

function defaultFormat(n: number, decimals = 0): string {
  const abs = Math.abs(n)
  if (abs >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (abs >= 1_000) return (n / 1_000).toFixed(1) + 'k'
  return n.toFixed(decimals)
}

/**
 * Decimals a y-axis tick needs so that no two ticks read the same: none at a
 * step of 1 or more, one at 0.1 or more, two below that. A "heap pressure"
 * chart whose peak is under one percent otherwise prints "1% 1% 1% 0% 0%".
 */
export function tickDecimals(step: number): number {
  if (!Number.isFinite(step) || step >= 1) return 0
  return step >= 0.1 ? 1 : 2
}

/** One x-axis label, with its place in the list it was picked from. */
export interface FittedTick {
  label: string
  /** Index in the original list, which sets the x of the label. */
  index: number
}

/**
 * The labels that fit `width`, an even subset of the ones given, always with
 * the first and the last. The count comes from the longest label, so a wide
 * label ("09-06 23:16") thins the axis further than a short one ("09-06").
 */
export function fitTicks(labels: string[], width: number): FittedTick[] {
  const n = labels.length
  if (n === 0) return []
  const all = labels.map((label, index) => ({ label, index }))
  if (n === 1) return all
  const chars = Math.max(...labels.map((l) => l.length), 1)
  const fit = Math.max(2, Math.floor(width / (chars * TICK_CHAR_PX)))
  if (fit >= n) return all
  const out: FittedTick[] = []
  const seen = new Set<number>()
  for (let k = 0; k < fit; k++) {
    const index = Math.round((k * (n - 1)) / (fit - 1))
    if (seen.has(index)) continue
    seen.add(index)
    out.push({ label: labels[index]!, index })
  }
  return out
}

/**
 * Cumulative CSS `zoom` from `el` up to the document root. getComputedStyle
 * reports each element's OWN specified zoom (not the inherited/cumulative value)
 * in both Blink and WebKit, so the product over the ancestor chain is the true
 * effective zoom. We need this to undo CSS `zoom` when mapping a pointer into the
 * chart's user coordinates (see onMove).
 */
function cumulativeZoom(el: Element | null): number {
  let z = 1
  for (let n: Element | null = el; n; n = n.parentElement) {
    const cz = parseFloat(getComputedStyle(n).getPropertyValue('zoom'))
    if (cz && !Number.isNaN(cz)) z *= cz
  }
  return z
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
  /** `null` when the bucket holds no measurement. */
  value: number | null
  y: number
}
interface HoverState {
  /** Nearest bucket index — drives the dots and the tooltip values. */
  index: number
  /**
   * Crosshair line x, in inner-group user units: the EXACT cursor position, not
   * the snapped bucket. The line must sit under the cursor (snapping it to the
   * bucket center is what read as "doesn't align with the cursor"); only the
   * dots + tooltip snap to the nearest data point.
   */
  lineX: number
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
  markers = [],
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
      for (const v of s.values) if (v != null && v > mx) mx = v
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
  const yDecimals = tickDecimals(maxPrimary / 4)
  const xLabels = fitTicks(xTicks, innerW)
  const xSpan = Math.max(xTicks.length, 2) - 1

  const [hover, setHover] = useState<HoverState | null>(null)
  // Bucket of the marker the pointer (or the keyboard focus) is on. The plot
  // hover wins while it is set, so crossing the plot never leaves a marker
  // tooltip behind.
  const [markerAt, setMarkerAt] = useState<number | null>(null)

  const shownMarkers = markers.filter((mk) => mk.index >= 0 && mk.index <= n - 1)

  /** Series values of one bucket, for the tooltip rows and the dots. */
  const markersAt = (idx: number): HoverMarker[] =>
    series.map((s) => {
      const value = s.values[idx] ?? null
      return { key: s.key, color: s.color, value, y: yScaleOf(s)(value ?? 0) }
    })

  // A hovered marker reads like a hover of its own bucket, pinned to the
  // marker x and to the top of the plot.
  const markerHover: HoverState | null =
    markerAt == null
      ? null
      : {
          index: markerAt,
          lineX: xScale(markerAt),
          pointerY: m.top,
          markers: markersAt(markerAt),
        }
  const active = hover ?? markerHover
  const activeLabels = active
    ? shownMarkers.filter((mk) => mk.index === active.index).map((mk) => mk.label)
    : []

  // Map the pointer to the chart's user coordinates. We deliberately do NOT use
  // svg.getScreenCTM(): under an ancestor CSS `zoom` (the app shell uses
  // `zoom: 0.9`) the engines disagree and getScreenCTM is wrong in WebKit. In
  // Blink, getScreenCTM and getBoundingClientRect both fold the zoom in (painted
  // space); in WebKit, getScreenCTM.a stays 1 and getBoundingClientRect returns
  // the UNZOOMED layout box -- yet mouse clientX is always painted viewport px.
  // Mapping through getScreenCTM therefore lands the crosshair ~zoom% left of the
  // cursor in Safari, worsening with x. Instead map purely from painted geometry:
  // the svg has no viewBox, so 1 user unit == 1 layout px and the painted scale is
  // exactly the cumulative CSS zoom Z (zoom origin is the viewport, since the shell
  // pins #root to inset:0). Recover the svg's painted top-left from its bounding
  // rect -- already painted in Blink; scale by Z in WebKit, detected by whether the
  // rect width still carries the zoom -- then invert: user = (client - painted) / Z.
  const onMove = (
    e: RMouseEvent<SVGRectElement> | RTouchEvent<SVGRectElement>,
  ) => {
    const svg = e.currentTarget.ownerSVGElement
    if (!svg) return
    const touch = 'touches' in e ? e.touches[0] : undefined
    const clientX = touch ? touch.clientX : (e as RMouseEvent).clientX
    const clientY = touch ? touch.clientY : (e as RMouseEvent).clientY
    const rect = svg.getBoundingClientRect()
    const z = cumulativeZoom(svg) || 1
    // Is the bounding rect already in painted space (Blink) or the unzoomed layout
    // box (WebKit)? The rect width is either width*z (painted) or width (unzoomed).
    const rectIsPainted =
      Math.abs(rect.width - width * z) <= Math.abs(rect.width - width)
    const paintedLeft = rectIsPainted ? rect.left : rect.left * z
    const paintedTop = rectIsPainted ? rect.top : rect.top * z
    const userX = (clientX - paintedLeft) / z
    const userY = (clientY - paintedTop) / z
    // `userX/userY` are in svg-root units; the plot is offset by the margin (the
    // Group). The crosshair LINE follows the exact cursor x (continuous), clamped
    // to the plot; the dots + tooltip snap to the nearest bucket `idx`.
    const localX = userX - m.left
    const lineX = Math.min(Math.max(localX, 0), innerW)
    let idx = Math.round(xScale.invert(localX))
    if (idx < 0) idx = 0
    else if (idx > n - 1) idx = n - 1
    const pointerY = Math.min(Math.max(userY, m.top), m.top + innerH)
    setHover({ index: idx, lineX, pointerY, markers: markersAt(idx) })
  }
  // Both are cleared: the pointer can only leave the plot for a marker, and the
  // marker's own enter runs after this leave.
  const onLeave = () => {
    setHover(null)
    setMarkerAt(null)
  }

  // Tooltip box position + flip. It lives inside the ParentSize wrapper (same
  // user-unit space as the svg, no portal, no zoom-boundary crossing), so its
  // left/top are just the cursor x and pointer y. Flip it to whichever side of
  // the cursor has room so a high or right-edge point can't clip it.
  const anchorLeft = m.left + (active?.lineX ?? 0)
  const anchorTop = active?.pointerY ?? 0
  const flipLeft = (active?.lineX ?? 0) > innerW / 2
  const flipUp = (active ? active.pointerY - m.top : 0) > innerH / 2
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
                {formatValue(Number(t.toFixed(yDecimals)), yDecimals)}
              </text>
            </Group>
          ))}
          <Line
            from={{ x: 0, y: innerH }}
            to={{ x: innerW, y: innerH }}
            stroke="var(--border-default)"
          />
          {/* `defined` breaks the line and the fill over a null bucket, so a
              bucket with no measurement is a hole, not a dip to zero. The y
              accessor is never called for a null. */}
          {series.map((s) =>
            s.area ? (
              <AreaClosed
                key={s.key + '-area'}
                data={s.values}
                x={(_v, i) => xScale(i)}
                y={(v) => yScaleOf(s)(v ?? 0)}
                yScale={yScaleOf(s)}
                defined={(v) => v != null}
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
              y={(v) => yScaleOf(s)(v ?? 0)}
              defined={(v) => v != null}
              stroke={s.color}
              strokeWidth={1.8}
              strokeLinejoin="round"
              strokeDasharray={s.dash ? DASH_PATTERN : undefined}
            />
          ))}
          {/* Each label keeps the x of its place in the full list, so dropping
              one never moves the rest. */}
          {xLabels.map(({ label, index }) => (
            <text
              key={index}
              x={(index / xSpan) * innerW}
              y={innerH + 20}
              fontSize={11}
              fontFamily="var(--font-mono)"
              fill="var(--text-muted)"
              textAnchor={
                index === 0
                  ? 'start'
                  : index === xTicks.length - 1
                    ? 'end'
                    : 'middle'
              }
            >
              {label}
            </text>
          ))}
          {shownMarkers.map((mk, i) => {
            const x = xScale(mk.index)
            const color = mk.color ?? 'var(--apx-coral)'
            // The triangle sits in the top margin (svg y 4..12), so it needs
            // negative y in this margin-shifted group.
            const top = MARKER_TOP - m.top
            return (
              <Group key={`${mk.index}-${i}`}>
                <Line
                  from={{ x, y: 0 }}
                  to={{ x, y: innerH }}
                  stroke={color}
                  strokeWidth={1}
                  strokeDasharray="4,3"
                  opacity={0.8}
                  pointerEvents="none"
                />
                <polygon
                  points={`${x - 4},${top} ${x + 4},${top} ${x},${top + MARKER_SIZE}`}
                  fill={color}
                >
                  <title>{mk.label}</title>
                </polygon>
              </Group>
            )
          })}
          {active && (
            <Group>
              {/* The crosshair follows the pointer only. A hovered marker
                  already draws its own line at the same x. */}
              {hover && (
                <Line
                  from={{ x: hover.lineX, y: 0 }}
                  to={{ x: hover.lineX, y: innerH }}
                  stroke="var(--text-muted)"
                  strokeWidth={1}
                  strokeDasharray="3,3"
                  pointerEvents="none"
                />
              )}
              {active.markers.map((mk, i) =>
                mk.value != null && (i === 0 || mk.value > 0) ? (
                  <circle
                    key={mk.key}
                    cx={xScale(active.index)}
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
          {/* Hit targets of the marker triangles, after the plot rect so the
              pointer reaches them. They sit in the top margin, clear of the
              plot, so the two hover sources never fight. */}
          {shownMarkers.map((mk, i) => {
            const x = xScale(mk.index)
            const top = MARKER_TOP - m.top
            const clear = () => setMarkerAt((at) => (at === mk.index ? null : at))
            return (
              <rect
                key={`hit-${mk.index}-${i}`}
                x={x - MARKER_HIT / 2}
                y={top - (MARKER_HIT - MARKER_SIZE) / 2}
                width={MARKER_HIT}
                height={MARKER_HIT}
                fill="transparent"
                pointerEvents="all"
                style={{ cursor: 'default' }}
                tabIndex={0}
                role="img"
                aria-label={mk.label}
                onMouseEnter={() => setMarkerAt(mk.index)}
                onMouseLeave={clear}
                onFocus={() => setMarkerAt(mk.index)}
                onBlur={clear}
              />
            )
          })}
        </Group>
      </svg>
      {active && (
        <div
          className="pointer-events-none absolute z-10 whitespace-nowrap rounded-none border border-[color:var(--border-default)] bg-[var(--apx-white)] px-[10px] py-[8px] text-[11px] leading-[1.6] text-[color:var(--text-primary)] shadow-[0_6px_18px_rgba(0,0,0,0.12)] [font-family:var(--font-mono)]"
          style={{
            left: anchorLeft,
            top: anchorTop,
            transform: `translate(${tx}, ${ty})`,
          }}
        >
          {(formatPoint || activeLabels.length > 0) && (
            <div className="mb-[4px] text-[color:var(--text-muted)]">
              {formatPoint && <div>{formatPoint(active.index)}</div>}
              {activeLabels.map((lab) => (
                <div key={lab}>{lab}</div>
              ))}
            </div>
          )}
          {active.markers.map((mk) => (
            <div key={mk.key} className="flex items-center gap-[7px]">
              <span
                className="h-[9px] w-[9px] flex-none rounded-none"
                style={{ background: mk.color }}
              />
              {mk.value == null ? NO_VALUE : formatValue(mk.value)} {mk.key}
            </div>
          ))}
        </div>
      )}
    </>
  )
}
