import { useState } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import EmptyState from '../components/EmptyState'
import { LoadFailure, StaleNotice } from '../components/LoadState'
import { SkeletonBlock } from '../components/Loading'
import PageHeader from '../components/PageHeader'
import TrendChart from '../components/TrendChart'
import { CompositionBar, HourTrace, RankList } from '../components/charts'
import { SeverityRail } from '../components/Severity'
import { useNow } from '../hooks/useNow'
import { usePolledResource } from '../hooks/usePolledResource'
import { compactAge, updatedAgo } from '../lib/format'
import { networkLabel } from '../lib/origin'
import { cleanLine } from '../lib/text'
import { TREND_WINDOWS, normaliseTrend } from '../lib/trends'
import {
  CATEGORY_COLOR, CATEGORY_LABEL, HANDS_ON_PROFILES,
  PROFILE_LABEL_SHORT,
} from '../lib/severity'

const REFRESH_MS = 15000
const TREND_REFRESH_MS = 5 * 60 * 1000

function LoadingSkeleton() {
  return (
    <div className="space-y-3" role="status" aria-label="Loading the overview">
      <SkeletonBlock className="h-52" />
      <div className="grid gap-3 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <SkeletonBlock className="h-[30rem]" />
        <SkeletonBlock className="h-[30rem]" />
      </div>
    </div>
  )
}

/**
 * The hero.
 *
 * Standing readings on the left, the day's rhythm drawn on the right. The
 * hour trace is the reading that actually separates automated sweeps from a
 * person at a keyboard, which is the judgement a tier-1 analyst is here to
 * make — so it gets the largest surface on the page rather than a row of
 * interchangeable stat cards.
 */
function Header({ stats }) {
  const needsReview = stats.high_severity_alerts ?? 0
  const today = stats.sessions_today ?? 0
  const active = stats.active_sessions ?? 0

  return (
    <section className="panel grid gap-6 p-5 lg:grid-cols-[minmax(0,auto)_minmax(0,1fr)] lg:gap-10">
      <div className="flex gap-8 lg:flex-col lg:justify-between lg:gap-5">
        <div>
          <p className="eyebrow">Needs review</p>
          <p
            className="figure mt-2 text-[64px]"
            style={{ color: needsReview > 0 ? 'var(--color-s4)' : 'var(--color-paper-3)' }}
            data-testid="needs-review"
          >
            {needsReview}
          </p>
          <p className="mt-2 max-w-[16rem] text-[13px] leading-snug text-paper-2">
            {needsReview === 0
              ? 'No unacknowledged high-severity alerts.'
              : `Unacknowledged high-severity ${needsReview === 1 ? 'alert' : 'alerts'}.`}
          </p>
        </div>

        <dl className="flex gap-8 lg:gap-6">
          <div>
            <dt className="eyebrow">Today</dt>
            <dd className="figure mt-1.5 text-[26px] text-paper">
              {today.toLocaleString()}
            </dd>
          </div>
          <div>
            <dt className="eyebrow">In progress</dt>
            <dd className="figure mt-1.5 text-[26px] text-paper">{active}</dd>
          </div>
        </dl>
      </div>

      <div className="min-w-0">
        <div className="flex items-baseline justify-between gap-3">
          <h2 className="font-display text-[17px] font-semibold text-paper">
            When they come
          </h2>
          <p className="text-[13px] text-paper-3">Sessions by hour of day, all time</p>
        </div>
        <div className="mt-4">
          <HourTrace byHour={stats.sessions_by_hour} bucketZone={stats.timezone || 'UTC'} />
        </div>
      </div>
    </section>
  )
}

/** One catch in the live feed. Dense, but every field earns its place. */
function FeedRow({ event, now }) {
  const handsOn = HANDS_ON_PROFILES.has(event.attacker_profile)
  const color = CATEGORY_COLOR[event.attack_category] || CATEGORY_COLOR.unknown

  return (
    <li className="flex items-center gap-3 border-t border-line px-4 py-2.5 first:border-t-0">
      <span
        className="h-6 w-[3px] shrink-0 rounded-[1px]"
        style={{ background: color }}
        aria-hidden="true"
      />

      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <Link
            to={`/attackers/${encodeURIComponent(event.attacker_ip)}`}
            className="readout truncate text-[13px] text-paper hover:underline"
            title="Everything this address has done"
          >
            {cleanLine(event.attacker_ip)}
          </Link>
          <Link
            to={`/sessions?session=${event.session_id}`}
            className="shrink-0 text-[12px] text-paper-3 hover:text-paper"
            title="Open this session"
          >
            open
          </Link>
          <span className="readout shrink-0 text-[12px] uppercase text-paper-3">
            {event.protocol || '—'}
          </span>
        </div>
        <div className="mt-0.5 flex items-baseline gap-1.5 text-[12px] text-paper-3">
          <span className="truncate">
            {CATEGORY_LABEL[event.attack_category] || CATEGORY_LABEL.unknown}
          </span>
          <span aria-hidden="true">·</span>
          <span className="truncate">
            {cleanLine(event.geo_country_name || event.geo_country) || networkLabel(event.attacker_ip) || 'Unknown origin'}
          </span>
        </div>
      </div>

      {/* Hands-on-keyboard is the distinction worth surfacing in the feed: a
          bot sweep and a person exploring get triaged very differently. */}
      {handsOn && (
        <span className="tag hidden shrink-0 sm:inline-flex" style={{ color: 'var(--color-s4)' }}>
          {PROFILE_LABEL_SHORT[event.attacker_profile]}
        </span>
      )}

      <SeverityRail level={event.severity} showLabel={false} />

      <span className="readout w-8 shrink-0 text-right text-[12px] text-paper-3" title="Time since it started">
        {compactAge(event.timestamp, now)}
      </span>
    </li>
  )
}

function Panel({ title, note, action, children }) {
  return (
    <section className="panel overflow-hidden">
      <div className="panel-head">
        <h2 className="font-display text-[15px] font-semibold text-paper">{title}</h2>
        {action || (note && <span className="text-[12px] text-paper-3">{note}</span>)}
      </div>
      {children}
    </section>
  )
}

/** Sessions per day over a chosen window. Its own request, so a slow or failing trend never holds up the rest. */
function TrendsPanel() {
  const [days, setDays] = useState(30)
  const trends = usePolledResource(
    ({ signal }) => api.dashboard.trends(days, { signal }),
    { key: `trends:${days}`, intervalMs: TREND_REFRESH_MS },
  )
  const trend = trends.data ? normaliseTrend(trends.data) : null

  return (
    <Panel
      title="Sessions per day"
      action={
        <div className="inline-flex overflow-hidden rounded-[3px] border border-line" role="group" aria-label="Trend window">
          {TREND_WINDOWS.map((window) => (
            <button
              key={window}
              type="button"
              aria-pressed={days === window}
              onClick={() => setDays(window)}
              className={`px-2.5 py-1 text-[12px] font-medium transition-colors ${
                days === window ? 'bg-paper text-ink-0' : 'bg-ink-2 text-paper-2 hover:text-paper'
              }`}
            >
              {window} days
            </button>
          ))}
        </div>
      }
    >
      <div className="px-4 pb-4" data-testid="trends-panel">
        {trends.loading ? (
          <SkeletonBlock className="h-56" />
        ) : trends.failed ? (
          <LoadFailure what="the daily trend" error={trends.error} onRetry={trends.reload} className="py-8" />
        ) : (
          <>
            {trends.stale && (
              <StaleNotice what="The daily trend" error={trends.error} loadedAt={trends.loadedAt} onRetry={trends.reload} className="mb-3" />
            )}
            {trend.total === 0 ? (
              <p className="py-6 text-[13px] text-paper-3" data-testid="trend-summary">
                No sessions were captured in the last {days} days.
              </p>
            ) : (
              <div className={trends.stale ? 'is-stale' : undefined}>
                <TrendChart trend={trend} days={days} />
              </div>
            )}
          </>
        )}
      </div>
    </Panel>
  )
}

export default function Dashboard() {
  const now = useNow(1000)
  // Statistics and the feed are one reading and are loaded as one. The
  // engine's status is asked for alongside but cannot fail the reading: it
  // is `null` when the question itself went unanswered.
  const overview = usePolledResource(
    async ({ signal }) => {
      const [stats, events, engine] = await Promise.allSettled([
        api.dashboard.stats({ signal }),
        api.dashboard.liveEvents(40, { signal }),
        api.honeypot.status({ signal }),
      ])
      if (stats.status === 'rejected') throw stats.reason
      if (events.status === 'rejected') throw events.reason
      return {
        stats: stats.value,
        events: Array.isArray(events.value) ? events.value : [],
        engine: engine.status === 'fulfilled' ? engine.value : null,
      }
    },
    { key: 'overview', intervalMs: REFRESH_MS },
  )

  const header = (
    <PageHeader
      eyebrow="Honeypot console"
      title="Overview"
      description="What the decoys have caught, what needs a decision, and when it arrives."
    >
      <span className="readout text-[12px] text-paper-3" aria-live="off" data-testid="updated-ago">
        {overview.loading ? 'loading' : updatedAgo(overview.loadedAt, now)}
      </span>
      <button
        type="button"
        className="control"
        onClick={overview.reload}
        disabled={overview.loading || overview.refreshing}
      >
        <RefreshCw className={`h-3.5 w-3.5 ${overview.refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
        Refresh
      </button>
    </PageHeader>
  )

  if (overview.loading) {
    return (
      <div className="mx-auto max-w-[1600px] space-y-3">
        {header}
        <LoadingSkeleton />
      </div>
    )
  }

  // Never loaded: say so. Drawing the page from nothing would put a zero
  // under "Needs review", which reads as "no alerts" when the truth is that
  // the count is not known.
  if (overview.failed) {
    return (
      <div className="mx-auto max-w-[1600px] space-y-3">
        {header}
        <section className="panel">
          <LoadFailure what="the overview" error={overview.error} onRetry={overview.reload} />
        </section>
      </div>
    )
  }

  const { stats, events: liveEvents, engine } = overview.data

  const countries = Object.entries(
    liveEvents.reduce((acc, e) => {
      const name = e.geo_country_name || e.geo_country || networkLabel(e.attacker_ip)
      if (name) acc[name] = (acc[name] || 0) + 1
      return acc
    }, {}),
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, count]) => ({ key: name, label: cleanLine(name), value: count }))

  const tools = (stats.top_tools_detected || []).slice(0, 6).map((t) => ({
    key: t.tool,
    label: cleanLine(String(t.tool).replace(/_/g, ' ')),
    value: t.count,
  }))

  // "Repeat" means more than one session. The list used to show the top
  // addresses whatever their count, so one-off visitors appeared under it.
  const repeats = (stats.top_attacker_ips || [])
    .filter((a) => a.count > 1)
    .slice(0, 6)
    .map((a) => ({
      key: a.ip,
      label: cleanLine(a.ip),
      href: `/attackers/${encodeURIComponent(a.ip)}`,
      sub: a.country || networkLabel(a.ip) || undefined,
      value: a.count,
    }))

  return (
    <div className="mx-auto max-w-[1600px] space-y-3">
      {header}

      {overview.stale && (
        <StaleNotice what="This overview" error={overview.error} loadedAt={overview.loadedAt} onRetry={overview.reload} />
      )}

      {engine && !engine.reachable && (
        <div
          role="status"
          className="flex items-start gap-2.5 rounded-[4px] border border-s3/40 bg-ink-1 px-4 py-3"
        >
          <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-s3" aria-hidden="true" />
          <p className="text-[13px] text-paper-2">
            <span className="font-medium text-paper">Engine unreachable.</span>{' '}
            {engine.detail || 'The backend could not contact the honeypot engine.'}{' '}
            Live emulation status and isolation checks are unavailable. Captured
            sessions are unaffected.
          </p>
        </div>
      )}

      <div className={`space-y-3 ${overview.stale ? 'is-stale' : ''}`}>
        <Header stats={stats} />

        {/* Asymmetric on purpose: the feed is the working surface, the ranked
            panels are reference. An even split would imply equal weight. */}
        <div className="grid items-start gap-3 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
          <div className="space-y-3">
            <TrendsPanel />

            <Panel
              title="Latest catches"
              action={
                <Link
                  to="/sessions"
                  className="text-[13px] font-medium text-paper-2 transition-colors hover:text-paper"
                >
                  All sessions
                </Link>
              }
            >
              {liveEvents.length === 0 ? (
                <EmptyState
                  title="Nothing caught yet"
                  hint="Sessions appear the moment the engine records its first connection."
                />
              ) : (
                <ul className="max-h-[38rem] overflow-y-auto">
                  {liveEvents.map((event) => (
                    <FeedRow key={event.session_uuid} event={event} now={now} />
                  ))}
                </ul>
              )}
            </Panel>
          </div>

          <div className="space-y-3">
            <Panel
              title="Composition"
              note={`${(stats.total_sessions ?? 0).toLocaleString()} classified`}
            >
              <div className="px-4 pb-4">
                {Object.keys(stats.attack_distribution || {}).length === 0 ? (
                  <p className="py-4 text-[13px] text-paper-3">
                    Categories appear once the engine analyses its first session.
                  </p>
                ) : (
                  <CompositionBar distribution={stats.attack_distribution} />
                )}
              </div>
            </Panel>

            <Panel title="Where from" note="Recent sessions">
              <RankList items={countries} emptyHint="No located sessions yet." />
            </Panel>

            <Panel title="What they brought" note="Tools seen">
              <RankList items={tools} emptyHint="No offensive tooling detected yet." />
            </Panel>

            <Panel title="Repeat visitors" note="More than one session">
              <RankList
                items={repeats}
                mono
                emptyHint="No address has connected more than once."
              />
            </Panel>
          </div>
        </div>
      </div>
    </div>
  )
}
