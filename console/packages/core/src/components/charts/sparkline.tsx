import { scaleLinear } from '@visx/scale'
import { AreaClosed, LinePath } from '@visx/shape'
import { cn } from '../../lib/cn'

export interface SparklineProps {
  /** The series to plot; needs >= 2 points to draw anything. */
  values: number[]
  /** Stroke (and area) color; any CSS color, e.g. a token var. */
  color?: string
  /** Fill a faint area under the line. */
  fill?: boolean
  width?: number
  height?: number
  className?: string
}

interface Pt {
  i: number
  v: number
}

/**
 * A compact, fixed-size trend line. Drawn to real pixels (never a scaled
 * viewBox), so the stroke stays crisp at any layout size or page zoom. The
 * y-domain is min/max normalized so small variations stay legible.
 */
export function Sparkline({
  values,
  color = 'var(--apx-graphite)',
  fill = false,
  width = 76,
  height = 26,
  className,
}: SparklineProps) {
  const pad = 2
  if (values.length < 2)
    return (
      <svg className={cn('block', className)} width={width} height={height} />
    )
  const min = Math.min(...values)
  const max = Math.max(...values)
  const xScale = scaleLinear({
    domain: [0, values.length - 1],
    range: [pad, width - pad],
  })
  const yScale = scaleLinear({
    domain: [min, max === min ? min + 1 : max],
    range: [height - pad, pad],
  })
  const data: Pt[] = values.map((v, i) => ({ i, v }))
  const x = (d: Pt) => xScale(d.i)
  const y = (d: Pt) => yScale(d.v)
  return (
    <svg className={cn('block', className)} width={width} height={height}>
      {fill && (
        <AreaClosed
          data={data}
          x={x}
          y={y}
          yScale={yScale}
          fill={color}
          opacity={0.1}
          stroke="none"
        />
      )}
      <LinePath
        data={data}
        x={x}
        y={y}
        stroke={color}
        strokeWidth={1.4}
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  )
}
