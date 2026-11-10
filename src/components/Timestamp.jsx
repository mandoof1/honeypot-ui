import { usePreferences } from '../context/usePreferences'
import { formatTimestamp } from '../lib/time'

/**
 * A moment in time, in the display zone the reader chose, with the zone
 * named. Hovering gives the same moment in the other zone, so a UTC reader
 * and a local-time reader can agree on what they are looking at.
 *
 * `value` is an ISO string, a Date, or epoch milliseconds.
 */
export default function Timestamp({ value, style = 'full', withZone = true, className = '' }) {
  const { zone } = usePreferences()
  const text = formatTimestamp(value, { zone, style, withZone })
  if (text === '—') return <span className={className}>—</span>

  const date = value instanceof Date ? value : new Date(value)
  const other = formatTimestamp(date, { zone: zone === 'utc' ? 'local' : 'utc', style: 'full' })
  return (
    <time dateTime={date.toISOString()} title={other} className={className}>
      {text}
    </time>
  )
}
