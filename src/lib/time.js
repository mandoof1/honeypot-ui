/*
 * Time zones.
 *
 * The API stores and buckets everything in UTC. The console used to print
 * timestamps with toLocaleString() and no zone, while the hour-of-day chart
 * drew the server's UTC buckets and highlighted the browser's local hour, so
 * two readings on one screen disagreed by the viewer's offset and neither
 * said which it was.
 *
 * Every timestamp now goes through here: one display zone (UTC or the
 * browser's own), chosen once and labelled wherever a time is shown.
 *
 * Pure, so it is unit-tested under node. "local" always means the zone of the
 * runtime; functions that need the offset take it as an argument so tests do
 * not depend on the machine they run on.
 */

export const ZONES = ['local', 'utc']

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

const pad = (n) => String(n).padStart(2, '0')

function toDate(value) {
  if (value === null || value === undefined || value === '') return null
  const date = value instanceof Date ? value : new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

/** Minutes east of UTC for the runtime's zone at the given moment. */
export function localOffsetMinutes(date = new Date()) {
  return -date.getTimezoneOffset()
}

/** "UTC", "UTC+4", "UTC−3", "UTC+5:30": an offset written the way people say it. */
export function offsetLabel(offsetMinutes) {
  if (!offsetMinutes) return 'UTC'
  const sign = offsetMinutes > 0 ? '+' : '−'
  const absolute = Math.abs(offsetMinutes)
  const hours = Math.floor(absolute / 60)
  const minutes = absolute % 60
  return `UTC${sign}${hours}${minutes ? `:${pad(minutes)}` : ''}`
}

/** The label to print beside a time shown in `zone`. */
export function zoneLabel(zone, date = new Date()) {
  return zone === 'utc' ? 'UTC' : offsetLabel(localOffsetMinutes(date))
}

/** "UTC" or "local time (UTC+4)": the long form, for headings and field labels. */
export function zoneDescription(zone, date = new Date()) {
  return zone === 'utc' ? 'UTC' : `local time (${offsetLabel(localOffsetMinutes(date))})`
}

function parts(date, zone) {
  if (zone === 'utc') {
    return {
      year: date.getUTCFullYear(), month: date.getUTCMonth(), day: date.getUTCDate(),
      hour: date.getUTCHours(), minute: date.getUTCMinutes(), second: date.getUTCSeconds(),
    }
  }
  return {
    year: date.getFullYear(), month: date.getMonth(), day: date.getDate(),
    hour: date.getHours(), minute: date.getMinutes(), second: date.getSeconds(),
  }
}

/**
 * A timestamp in the display zone, with the zone named.
 *
 *   full    2026-01-01 14:00:05 UTC+4
 *   minute  2026-01-01 14:00 UTC+4
 *   short   Jan 1, 14:00 UTC+4      (dense rows; the year is in the tooltip)
 *   date    2026-01-01
 *   time    14:00:05 UTC+4
 *
 * Returns "—" for a missing or unparseable value rather than "Invalid Date".
 */
export function formatTimestamp(value, { zone = 'local', style = 'full', withZone = true } = {}) {
  const date = toDate(value)
  if (!date) return '—'
  const p = parts(date, zone)
  const ymd = `${p.year}-${pad(p.month + 1)}-${pad(p.day)}`
  const hm = `${pad(p.hour)}:${pad(p.minute)}`
  const label = withZone ? ` ${zoneLabel(zone, date)}` : ''
  if (style === 'date') return ymd
  if (style === 'time') return `${hm}:${pad(p.second)}${label}`
  if (style === 'short') return `${MONTHS[p.month]} ${p.day}, ${hm}${label}`
  if (style === 'minute') return `${ymd} ${hm}${label}`
  return `${ymd} ${hm}:${pad(p.second)}${label}`
}

/** "Jan 1": a UTC day bucket from the trends endpoint. */
export function formatUtcDay(value) {
  const date = toDate(value)
  if (!date) return '—'
  return `${MONTHS[date.getUTCMonth()]} ${date.getUTCDate()}`
}

/** The value a datetime-local input needs to show `iso` in the display zone. */
export function toInputValue(iso, zone = 'local') {
  const date = toDate(iso)
  if (!date) return ''
  const p = parts(date, zone)
  return `${p.year}-${pad(p.month + 1)}-${pad(p.day)}T${pad(p.hour)}:${pad(p.minute)}`
}

/** A datetime-local input's value, read in the display zone, as an ISO instant. */
export function fromInputValue(value, zone = 'local') {
  if (!value) return ''
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?/.exec(value)
  if (!match) return ''
  const [year, month, day, hour, minute, second] = match.slice(1).map((part) => Number(part || 0))
  const date = zone === 'utc'
    ? new Date(Date.UTC(year, month - 1, day, hour, minute, second))
    : new Date(year, month - 1, day, hour, minute, second)
  return Number.isNaN(date.getTime()) ? '' : date.toISOString()
}

/** Hour of day (0–23) of `date` in the display zone. */
export function hourOfDay(zone, date = new Date()) {
  return zone === 'utc' ? date.getUTCHours() : date.getHours()
}

/**
 * Re-key the API's UTC hour-of-day buckets ({"00": n, …, "23": n}) to another
 * offset. Returns 24 counts indexed by hour in that zone.
 *
 * An hour bucket cannot be split, so an offset that is not a whole number of
 * hours (India, Nepal, parts of Australia) is rounded to the nearest hour and
 * `exact` is false, which the chart says out loud.
 */
export function shiftHourBuckets(byHour = {}, offsetMinutes = 0) {
  const shift = Math.round(offsetMinutes / 60)
  const values = new Array(24).fill(0)
  for (let utcHour = 0; utcHour < 24; utcHour += 1) {
    const count = Number(byHour?.[pad(utcHour)] ?? byHour?.[utcHour] ?? 0) || 0
    const target = (((utcHour + shift) % 24) + 24) % 24
    values[target] += count
  }
  return { values, shiftHours: shift, exact: offsetMinutes % 60 === 0 }
}
