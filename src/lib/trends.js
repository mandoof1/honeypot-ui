/*
 * The trend series, made ready to draw and to describe.
 *
 * /dashboard/trends answers with one point per UTC day: a total and a count
 * for each category. A chart is one reading of that; the summary sentence
 * and the table are the others, and all three are built from the same
 * normalised points so they cannot disagree.
 */

import { formatUtcDay } from './time.js'

export const TREND_WINDOWS = [7, 30, 90]

/** Stack order, bottom to top: cool to hot, as everywhere else in the console. */
export const TREND_CATEGORIES = ['benign', 'reconnaissance', 'exploitation', 'exfiltration']

const count = (value) => Math.max(0, Math.round(Number(value) || 0))

/**
 * @returns {{points: Array, max: number, total: number, totals: object,
 *            busiest: object|null, timezone: string, bucket: string}}
 * Each point: `{t, total, counts: {benign, …}, unclassified}`. `unclassified`
 * is whatever part of the day's total no category accounts for.
 */
export function normaliseTrend(payload) {
  const points = (payload?.series || [])
    .filter((point) => point && point.t)
    .map((point) => {
      const counts = Object.fromEntries(TREND_CATEGORIES.map((category) => [category, count(point[category])]))
      const classified = TREND_CATEGORIES.reduce((sum, category) => sum + counts[category], 0)
      const total = Math.max(count(point.total), classified)
      return { t: String(point.t), total, counts, unclassified: total - classified }
    })
    .sort((a, b) => a.t.localeCompare(b.t))

  const totals = Object.fromEntries(TREND_CATEGORIES.map((category) => [
    category,
    points.reduce((sum, point) => sum + point.counts[category], 0),
  ]))
  const total = points.reduce((sum, point) => sum + point.total, 0)
  const busiest = points.reduce((best, point) => (best === null || point.total > best.total ? point : best), null)

  return {
    points,
    max: busiest ? busiest.total : 0,
    total,
    totals,
    unclassified: points.reduce((sum, point) => sum + point.unclassified, 0),
    busiest: busiest && busiest.total > 0 ? busiest : null,
    timezone: payload?.timezone ? String(payload.timezone) : 'UTC',
    bucket: payload?.bucket ? String(payload.bucket) : 'day',
  }
}

/** A round number at or above `max` for the top of the axis, and its midpoint. */
export function axisTop(max) {
  if (max <= 4) return 4
  const magnitude = 10 ** Math.floor(Math.log10(max))
  for (const step of [1, 2, 4, 5, 10]) {
    if (step * magnitude >= max) return step * magnitude
  }
  return 10 * magnitude
}

/** The series in one sentence: the text a chart cannot be for some readers. */
export function trendSummary(trend, days) {
  if (!trend.points.length) return `No daily figures were returned for the last ${days} days.`
  if (trend.total === 0) return `No sessions were captured in the last ${days} days (${trend.timezone} days).`
  const share = (value) => `${Math.round((value / trend.total) * 100)}%`
  const parts = TREND_CATEGORIES
    .filter((category) => trend.totals[category] > 0)
    .sort((a, b) => trend.totals[b] - trend.totals[a])
    .map((category) => `${category} ${trend.totals[category].toLocaleString()} (${share(trend.totals[category])})`)
  const busiest = trend.busiest
    ? ` The busiest day was ${formatUtcDay(trend.busiest.t)} with ${trend.busiest.total.toLocaleString()}.`
    : ''
  return `${trend.total.toLocaleString()} session${trend.total === 1 ? '' : 's'} in the last ${days} days `
    + `(${trend.timezone} days): ${parts.join(', ')}.${busiest}`
}
