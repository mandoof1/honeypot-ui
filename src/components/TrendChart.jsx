import { useState } from 'react'
import { CATEGORY_COLOR, CATEGORY_LABEL } from '../lib/severity'
import { formatUtcDay } from '../lib/time'
import { TREND_CATEGORIES, axisTop, trendSummary } from '../lib/trends'

/*
 * Sessions per day, stacked by category.
 *
 * Stacked columns rather than lines: a day's sessions are a whole made of
 * parts, and the question the chart answers is "how much, and how much of it
 * was serious". The stack runs cool to hot from the baseline, in the order
 * the category ramp has everywhere else.
 *
 * Colour is never the only channel. Segments are separated by a gap in the
 * surface colour, the legend names each one, hovering a day lists every
 * figure, and the sentence and table underneath carry the same numbers
 * without the chart at all.
 */

const HEIGHT = 168
const WIDTH = 720
const GAP = 2
const MAX_BAR = 24

const SERIES = [...TREND_CATEGORIES, 'unknown']

function valueOf(point, series) {
  return series === 'unknown' ? point.unclassified : point.counts[series]
}

export default function TrendChart({ trend, days }) {
  const [hover, setHover] = useState(null)
  const { points } = trend
  const top = axisTop(trend.max)
  const column = WIDTH / Math.max(points.length, 1)
  const bar = Math.max(1, Math.min(MAX_BAR, column - GAP))
  const shown = SERIES.filter((series) => series !== 'unknown' || trend.unclassified > 0)
  const hovered = hover === null ? null : points[hover]
  const labels = points.length <= 1
    ? points.map((_, i) => i)
    : [0, Math.floor((points.length - 1) / 2), points.length - 1]

  return (
    <figure className="m-0" data-testid="trend-chart">
      <div className="flex gap-2">
        {/* Axis labels are HTML beside the plot, so they are not stretched
            with it and stay the same size as the rest of the text. */}
        <div className="readout flex w-9 shrink-0 flex-col justify-between text-right text-[12px] text-paper-3" style={{ height: HEIGHT }} aria-hidden="true">
          <span>{top.toLocaleString()}</span>
          <span>{(top / 2).toLocaleString()}</span>
          <span>0</span>
        </div>

        <div className="relative min-w-0 flex-1">
          <svg
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            preserveAspectRatio="none"
            className="block w-full"
            style={{ height: HEIGHT }}
            role="img"
            aria-label={trendSummary(trend, days)}
          >
            {[0, 0.5, 1].map((fraction) => (
              <line
                key={fraction}
                x1="0" x2={WIDTH}
                y1={Math.min(HEIGHT - 0.5, Math.max(0.5, HEIGHT * fraction))}
                y2={Math.min(HEIGHT - 0.5, Math.max(0.5, HEIGHT * fraction))}
                stroke="var(--color-line)" strokeWidth="1" vectorEffect="non-scaling-stroke"
              />
            ))}

            {points.map((point, i) => {
              let base = HEIGHT
              const x = i * column + (column - bar) / 2
              return (
                <g key={point.t} opacity={hover === null || hover === i ? 1 : 0.45}>
                  {shown.map((series) => {
                    const value = valueOf(point, series)
                    if (!value) return null
                    const full = (value / top) * HEIGHT
                    // The gap between segments is taken out of each one, in
                    // the surface colour, so adjacent fills never touch.
                    const height = Math.max(1, full - GAP)
                    base -= full
                    return (
                      <rect
                        key={series}
                        x={x}
                        y={base + GAP}
                        width={bar}
                        height={height}
                        fill={CATEGORY_COLOR[series]}
                      />
                    )
                  })}
                </g>
              )
            })}

            {points.map((point, i) => (
              <rect
                key={`hit-${point.t}`}
                x={i * column}
                y="0"
                width={column}
                height={HEIGHT}
                fill="transparent"
                onMouseEnter={() => setHover(i)}
                onMouseLeave={() => setHover(null)}
              />
            ))}
          </svg>

          {hovered && (
            <div
              className="pointer-events-none absolute top-0 z-10 w-44 -translate-x-1/2 rounded-[3px] border border-line-2 bg-ink-2 px-2.5 py-2 shadow-lg"
              style={{ left: `${Math.min(88, Math.max(12, ((hover + 0.5) / points.length) * 100))}%` }}
            >
              <p className="readout text-[12px] text-paper-2">{formatUtcDay(hovered.t)} UTC</p>
              <p className="readout mt-0.5 text-[13px] font-semibold text-paper">
                {hovered.total.toLocaleString()} session{hovered.total === 1 ? '' : 's'}
              </p>
              <ul className="mt-1 space-y-0.5">
                {[...shown].reverse().map((series) => (
                  <li key={series} className="flex items-center gap-2 text-[12px]">
                    <span className="h-[2px] w-3 shrink-0" style={{ background: CATEGORY_COLOR[series] }} aria-hidden="true" />
                    <span className="readout text-paper">{valueOf(hovered, series).toLocaleString()}</span>
                    <span className="truncate text-paper-3">{CATEGORY_LABEL[series]}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="readout relative mt-1.5 h-4 text-[12px] text-paper-3" aria-hidden="true">
            {labels.map((index, position) => (
              <span
                key={index}
                className="absolute whitespace-nowrap"
                style={
                  position === 0 ? { left: 0 }
                    : position === labels.length - 1 ? { right: 0 }
                      : { left: '50%', transform: 'translateX(-50%)' }
                }
              >
                {formatUtcDay(points[index].t)}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Legend: always present, in stack order from the top down. */}
      <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1" aria-label="Categories">
        {[...shown].reverse().map((series) => (
          <li key={series} className="flex items-center gap-1.5 text-[12px] text-paper-2">
            <span className="h-2 w-2 shrink-0 rounded-[1px]" style={{ background: CATEGORY_COLOR[series] }} aria-hidden="true" />
            {CATEGORY_LABEL[series]}
          </li>
        ))}
      </ul>

      <figcaption className="mt-2.5 text-[13px] leading-relaxed text-paper-2" data-testid="trend-summary">
        {trendSummary(trend, days)}
      </figcaption>

      <details className="mt-2">
        <summary className="cursor-pointer text-[12px] font-medium text-paper-2 hover:text-paper">
          Daily figures as a table
        </summary>
        <div className="mt-2 max-h-64 overflow-auto">
          <table className="w-full border-collapse text-left text-[12px]">
            <thead className="sticky top-0 bg-ink-1">
              <tr className="border-b border-line">
                <th scope="col" className="eyebrow px-2 py-1 font-normal">Day (UTC)</th>
                <th scope="col" className="eyebrow px-2 py-1 text-right font-normal">Total</th>
                {shown.map((series) => (
                  <th key={series} scope="col" className="eyebrow px-2 py-1 text-right font-normal">
                    {CATEGORY_LABEL[series]}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {points.map((point) => (
                <tr key={point.t} className="border-b border-line last:border-b-0">
                  <th scope="row" className="readout px-2 py-1 font-normal text-paper-2">{point.t.slice(0, 10)}</th>
                  <td className="readout px-2 py-1 text-right text-paper">{point.total.toLocaleString()}</td>
                  {shown.map((series) => (
                    <td key={series} className="readout px-2 py-1 text-right text-paper-2">
                      {valueOf(point, series).toLocaleString()}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  )
}
