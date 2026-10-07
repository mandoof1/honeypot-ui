import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../services/api'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import { SkeletonBlock } from '../components/Loading'
import { CompositionBar, HourTrace, RankList } from '../components/charts'
import { SeverityRail } from '../components/Severity'
import { useVisiblePoll } from '../hooks/useVisiblePoll'
import { networkLabel } from '../lib/origin'
import { clean } from '../lib/text'
import {
  CATEGORY_COLOR, CATEGORY_LABEL, HANDS_ON_PROFILES,
  PROFILE_LABEL_SHORT, timeAgo,
} from '../lib/severity'

const REFRESH_MS = 15000

function LoadingSkeleton() {
  return (
    <div className="space-y-3">
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
  const needsReview = stats?.high_severity_alerts ?? 0
  const today = stats?.sessions_today ?? 0
  const active = stats?.active_sessions ?? 0

  return (
    <section className="panel grid gap-6 p-5 lg:grid-cols-[minmax(0,auto)_minmax(0,1fr)] lg:gap-10">
      <div className="flex gap-8 lg:flex-col lg:justify-between lg:gap-5">
        <div>
          <p className="eyebrow">Needs review</p>
          <p
            className="figure mt-2 text-[64px]"
            style={{ color: needsReview > 0 ? 'var(--color-s4)' : 'var(--color-paper-3)' }}
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
          <p className="text-[13px] text-paper-3">Sessions by hour, all time</p>
        </div>
        <div className="mt-4">
          <HourTrace byHour={stats?.sessions_by_hour} />
        </div>
      </div>
    </section>
  )
}

/** One catch in the live feed. Dense, but every field earns its place. */
function FeedRow({ event }) {
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
            {clean(event.attacker_ip)}
          </Link>
          <Link
            to={`/sessions?session=${event.session_id}`}
            className="shrink-0 text-[11px] text-paper-3 hover:text-paper"
            title="Open this session"
          >
            open
          </Link>
          <span className="readout shrink-0 text-[11px] uppercase text-paper-3">
            {event.protocol || '—'}
          </span>
        </div>
        <div className="mt-0.5 flex items-baseline gap-1.5 text-[12px] text-paper-3">
          <span className="truncate">
            {CATEGORY_LABEL[event.attack_category] || CATEGORY_LABEL.unknown}
          </span>
          <span aria-hidden="true">·</span>
          <span className="truncate">
            {event.geo_country_name || event.geo_country || networkLabel(event.attacker_ip) || 'Unknown origin'}
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

      <span className="readout w-8 shrink-0 text-right text-[12px] text-paper-3">
        {timeAgo(event.timestamp)}
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

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [liveEvents, setLiveEvents] = useState([])
  const [engine, setEngine] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const fetchData = useCallback(async () => {
    try {
      const [statsData, eventsData, engineStatus] = await Promise.all([
        api.dashboard.stats(),
        api.dashboard.liveEvents(40),
        api.honeypot.status().catch(() => null),
      ])
      setStats(statsData)
      setLiveEvents(eventsData || [])
      setEngine(engineStatus)
      setError(null)
    } catch (err) {
      // Surface failures instead of only writing them to the console, which
      // left the dashboard silently frozen on stale numbers.
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    const timer = setTimeout(fetchData, 0)
    return () => clearTimeout(timer)
  }, [fetchData])
  // Polls only while the tab is visible and never overlaps itself.
  useVisiblePoll(fetchData, REFRESH_MS)

  if (loading) return <LoadingSkeleton />

  const countries = Object.entries(
    liveEvents.reduce((acc, e) => {
      const name = e.geo_country_name || e.geo_country || networkLabel(e.attacker_ip)
      if (name) acc[name] = (acc[name] || 0) + 1
      return acc
    }, {}),
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, count]) => ({ key: name, label: name, value: count }))

  const tools = (stats?.top_tools_detected || []).slice(0, 6).map((t) => ({
    key: t.tool,
    label: t.tool.replace(/_/g, ' '),
    value: t.count,
  }))

  const repeats = (stats?.top_attacker_ips || []).slice(0, 6).map((a) => ({
    key: a.ip,
    label: clean(a.ip),
    href: `/attackers/${encodeURIComponent(a.ip)}`,
    sub: a.country || networkLabel(a.ip) || undefined,
    value: a.count,
  }))

  return (
    <div className="mx-auto max-w-[1600px] space-y-3">
      {error && <ErrorBanner message={error} onRetry={fetchData} />}

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

      <Header stats={stats} />

      {/* Asymmetric on purpose: the feed is the working surface, the ranked
          panels are reference. An even split would imply equal weight. */}
      <div className="grid items-start gap-3 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
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
                <FeedRow key={event.session_uuid} event={event} />
              ))}
            </ul>
          )}
        </Panel>

        <div className="space-y-3">
          <Panel
            title="Composition"
            note={`${(stats?.total_sessions ?? 0).toLocaleString()} classified`}
          >
            <div className="px-4 pb-4">
              {Object.keys(stats?.attack_distribution || {}).length === 0 ? (
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

          <Panel title="Repeat visitors" note="By session count">
            <RankList
              items={repeats}
              mono
              emptyHint="No address has connected more than once."
            />
          </Panel>
        </div>
      </div>
    </div>
  )
}
