import { useId, useState } from 'react'
import { Link } from 'react-router-dom'
import { usePreferences } from '../context/usePreferences'
import { CATEGORY_COLOR, CATEGORY_LABEL, CATEGORY_ORDER } from '../lib/severity'
import { hourOfDay, localOffsetMinutes, offsetLabel, shiftHourBuckets } from '../lib/time'

/*
 * Charts for the console.
 *
 * All three are achromatic. Colour in this interface means threat level, so a
 * chart that measures volume — when attacks arrive, which countries send the
 * most — draws in ivory. Only the composition bar, which measures threat
 * directly, is allowed the ramp.
 */

const HOURS = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0'))

/**
 * Arrivals by hour of day.
 *
 * A honeypot's diurnal histogram is its signature reading: automated sweeps
 * run flat around the clock, while a person at a keyboard clusters in their
 * own working hours. This is the one view that separates the two at a glance,
 * and the API has been returning it since the beginning without anything
 * drawing it.
 */
export function HourTrace({ byHour = {}, height = 132, bucketZone = 'UTC' }) {
  const [hover, setHover] = useState(null)
  const clipId = useId()
  const { zone } = usePreferences()

  // The API counts by UTC hour. The buckets are re-keyed to the zone the
  // reader chose, and the hour that is highlighted is the current hour in
  // that same zone. Before, the bars were UTC and the highlight was the
  // browser's local hour, so the chart pointed at the wrong bar for anyone
  // not on UTC, and said nothing about which zone it was drawn in.
  const convertible = bucketZone === 'UTC'
  const local = convertible && zone === 'local'
  const offset = local ? localOffsetMinutes() : 0
  const { values, exact } = shiftHourBuckets(byHour, offset)
  const zoneName = !convertible ? bucketZone : local ? offsetLabel(offset) : 'UTC'
  const peak = Math.max(...values, 1)
  const total = values.reduce((a, b) => a + b, 0)
  const currentHour = convertible ? hourOfDay(local ? 'local' : 'utc') : -1
  const peakHour = values.indexOf(Math.max(...values))

  // A fixed viewBox with a 24-column grid; the SVG scales to its container.
  const COLS = 24
  const GAP = 2
  const W = 480
  const colWidth = W / COLS
  const barWidth = colWidth - GAP

  return (
    <figure className="m-0">
      <div className="relative">
        <svg
          viewBox={`0 0 ${W} ${height}`}
          preserveAspectRatio="none"
          className="block w-full"
          style={{ height }}
          role="img"
          aria-label={total === 0
            ? `Sessions by hour of day, ${zoneName}. None recorded.`
            : `Sessions by hour of day, ${zoneName}. Peak ${values[peakHour]} at ${HOURS[peakHour]}:00. ${total} in total.`}
        >
          <defs>
            <clipPath id={clipId}>
              <rect x="0" y="0" width={W} height={height} />
            </clipPath>
          </defs>

          {/* Recessive baseline. The only rule the chart needs. */}
          <line
            x1="0" y1={height - 0.5} x2={W} y2={height - 0.5}
            stroke="var(--color-line)" strokeWidth="1" vectorEffect="non-scaling-stroke"
          />

          <g clipPath={`url(#${clipId})`}>
            {values.map((value, i) => {
              // Every bar keeps a visible stub so an empty hour reads as
              // measured-and-zero rather than missing.
              const barHeight = value === 0 ? 1.5 : Math.max(3, (value / peak) * (height - 10))
              const isNow = i === currentHour
              const isHover = hover === i
              return (
                <rect
                  key={i}
                  x={i * colWidth + GAP / 2}
                  y={height - barHeight}
                  width={barWidth}
                  height={barHeight}
                  rx="1.5"
                  fill={
                    isHover ? 'var(--color-paper)'
                      : isNow ? 'var(--color-paper)'
                        : value === 0 ? 'var(--color-line)' : 'var(--color-paper-2)'
                  }
                  opacity={isHover || isNow ? 1 : 0.55}
                />
              )
            })}
          </g>

          {/* Generous invisible hit targets — the bars themselves are too
              thin to be a comfortable pointer target. */}
          {values.map((_, i) => (
            <rect
              key={`hit-${i}`}
              x={i * colWidth}
              y="0"
              width={colWidth}
              height={height}
              fill="transparent"
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(null)}
            />
          ))}
        </svg>

        {hover !== null && (
          <div
            className="pointer-events-none absolute -top-1 z-10 -translate-x-1/2 -translate-y-full whitespace-nowrap rounded-[3px] border border-line-2 bg-ink-2 px-2 py-1 shadow-lg"
            style={{ left: `${((hover + 0.5) / COLS) * 100}%` }}
          >
            <span className="readout text-xs text-paper">
              {HOURS[hover]}:00 · {values[hover].toLocaleString()}
            </span>
          </div>
        )}
      </div>

      {/* Ticks at the quarters only; 24 labels would be noise. */}
      <div className="mt-1.5 flex justify-between" aria-hidden="true">
        {['00:00', '06:00', '12:00', '18:00', '23:00'].map((t) => (
          <span key={t} className="readout text-[12px] text-paper-3">{t}</span>
        ))}
      </div>

      <figcaption className="mt-2 text-[12px] leading-relaxed text-paper-3" data-testid="hour-zone">
        Hours in <span className="text-paper-2">{zoneName}</span>
        {local && ', converted from the server’s UTC counts'}
        {local && !exact && '; the offset is not a whole hour, so each bar is shifted to the nearest one'}
        {total > 0 && <>. Busiest hour {HOURS[peakHour]}:00 with {values[peakHour].toLocaleString()}</>}
        {currentHour >= 0 && <>; the bright bar is the current hour</>}.
      </figcaption>

      {/* The same numbers without the pointer: values used to be reachable
          only by hovering a bar. */}
      <details className="mt-1.5">
        <summary className="cursor-pointer text-[12px] font-medium text-paper-2 hover:text-paper">
          Sessions by hour as a table
        </summary>
        <table className="mt-2 w-full border-collapse text-left text-[12px]" data-testid="hour-table">
          <caption className="sr-only">Sessions by hour of day, {zoneName}</caption>
          <tbody className="grid grid-cols-4 gap-x-4 sm:grid-cols-6">
            {values.map((value, hour) => (
              <tr key={hour} className="flex items-baseline justify-between border-b border-line py-0.5">
                <th scope="row" className="readout font-normal text-paper-3">{HOURS[hour]}:00</th>
                <td className="readout text-paper">{value.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  )
}

/**
 * Categories as one whole. A stacked proportion bar rather than separate
 * tracks, which invited reading each percentage against its own scale.
 * Segments carry a 2px surface gap so adjacent fills stay distinguishable
 * without relying on hue alone.
 */
export function CompositionBar({ distribution = {} }) {
  const total = Object.values(distribution).reduce((a, b) => a + b, 0)

  const segments = CATEGORY_ORDER
    .map((category) => ({
      category,
      count: distribution[category] ?? 0,
      color: CATEGORY_COLOR[category],
      label: CATEGORY_LABEL[category] || category,
    }))
    .filter((s) => s.count > 0)

  if (total === 0) return null

  return (
    <div>
      <div className="flex h-2.5 w-full gap-[2px] overflow-hidden">
        {segments.map(({ category, count, color, label }) => (
          <div
            key={category}
            className="rounded-[1px] first:rounded-l-[2px] last:rounded-r-[2px]"
            style={{ width: `${(count / total) * 100}%`, background: color }}
            title={`${label}: ${count.toLocaleString()}`}
          />
        ))}
      </div>

      {/* Legend is always present: identity must never be colour alone. */}
      <dl className="mt-3 space-y-1.5">
        {segments.map(({ category, count, color, label }) => (
          <div key={category} className="flex items-baseline gap-2.5">
            <span
              className="h-2 w-2 shrink-0 translate-y-px rounded-[1px]"
              style={{ background: color }}
              aria-hidden="true"
            />
            <dt className="flex-1 truncate text-[13px] text-paper-2">{label}</dt>
            <dd className="readout text-[13px] text-paper">
              {count.toLocaleString()}
              <span className="ml-2 text-paper-3">
                {Math.round((count / total) * 100)}%
              </span>
            </dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

/**
 * Ranked magnitude list — top countries, tools, repeat addresses. The bar is
 * a track behind the label rather than beside it, so the name stays readable
 * at any width and the row count fits without a scrollbar.
 */
export function RankList({ items, emptyHint, mono = false }) {
  if (!items || items.length === 0) {
    return <p className="px-4 py-6 text-[13px] text-paper-3">{emptyHint}</p>
  }

  const peak = Math.max(...items.map((i) => i.value), 1)

  return (
    <ul className="px-4 pb-3.5">
      {items.map(({ key, label, sub, value, href }) => (
        <li key={key} className="py-[3px]">
          <div className="flex items-baseline gap-2">
            {href ? (
              <Link
                to={href}
                className={`min-w-0 flex-1 truncate text-[13px] text-paper hover:underline ${mono ? 'readout' : ''}`}
              >
                {label}
              </Link>
            ) : (
              <span
                className={`min-w-0 flex-1 truncate text-[13px] text-paper ${mono ? 'readout' : ''}`}
              >
                {label}
              </span>
            )}
            {sub && <span className="readout shrink-0 text-[12px] text-paper-3">{sub}</span>}
            <span className="readout shrink-0 text-[13px] text-paper-2">
              {value.toLocaleString()}
            </span>
          </div>
          {/*
            A thin rule under the label rather than a filled block behind it.
            At full row height the bar read as an alternating row background
            and fought the text it was supposed to be measuring.
          */}
          <div className="mt-1 h-[2px] w-full rounded-full bg-line" aria-hidden="true">
            <div
              className="h-full rounded-full bg-paper-2"
              style={{ width: `${(value / peak) * 100}%` }}
            />
          </div>
        </li>
      ))}
    </ul>
  )
}
