import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, ExternalLink, RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import { BlockAddressControl } from '../components/BlockControls'
import CopyButton from '../components/CopyButton'
import EmptyState from '../components/EmptyState'
import { LoadFailure, StaleNotice } from '../components/LoadState'
import { LoadingRegion } from '../components/Loading'
import { CategoryTag } from '../components/Severity'
import { SignalBadges } from '../components/SessionSignals'
import Timestamp from '../components/Timestamp'
import { RankList } from '../components/charts'
import { usePolledResource } from '../hooks/usePolledResource'
import { techniqueUrl } from '../lib/attack'
import { diversionOf } from '../lib/diversion'
import { networkLabel } from '../lib/origin'
import { clean, cleanLine } from '../lib/text'
import { plural } from '../lib/format'
import {
  aggregateFingerprints, aggregateSignals, anomalyReading, isRefusal,
} from '../lib/verdict'
import {
  CATEGORY_COLOR, CATEGORY_LABEL, CATEGORY_ORDER, HANDS_ON_PROFILES, PROFILE_LABEL_SHORT,
} from '../lib/severity'

/*
 * One source address, everything it did.
 *
 * The session list answers "what happened at 03:12"; this answers "who is
 * 203.0.113.7". A returning address is the most common shape of a campaign
 * against a honeypot — the same bot, the same credential list, the same
 * dropper, across weeks — and until now the only way to see it was to type
 * the address into the search box and read the rows one by one.
 */

const REFRESH_MS = 30000

function Stat({ label, children, mono = true }) {
  return (
    <div className="min-w-0">
      <dt className="eyebrow">{label}</dt>
      <dd className={`mt-1 break-words text-[13px] text-paper ${mono ? 'readout' : ''}`}>{children}</dd>
    </div>
  )
}

function Panel({ title, note, children }) {
  return (
    <section className="panel overflow-hidden">
      <div className="panel-head">
        <h2 className="font-display text-[15px] font-semibold text-paper">{title}</h2>
        {note && <span className="text-[12px] text-paper-3">{note}</span>}
      </div>
      {children}
    </section>
  )
}

function SessionRow({ session }) {
  const color = CATEGORY_COLOR[session.attack_category] || CATEGORY_COLOR.unknown
  const handsOn = HANDS_ON_PROFILES.has(session.attacker_profile)
  const refused = isRefusal(session)
  const anomaly = anomalyReading(session)
  return (
    <li>
      <Link
        to={`/sessions?session=${session.id}`}
        className="flex items-center gap-3 border-t border-line px-4 py-2.5 transition-colors first:border-t-0 hover:bg-ink-2/60"
      >
        <span
          className="h-6 w-[3px] shrink-0 rounded-[1px]"
          style={{ background: refused ? 'var(--color-line-2)' : color }}
          aria-hidden="true"
        />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="readout shrink-0 text-[12px] uppercase text-paper-3">{session.protocol || '—'}</span>
            <span className="truncate text-[13px] text-paper">
              {refused ? 'Refused connection' : (CATEGORY_LABEL[session.attack_category] || CATEGORY_LABEL.unknown)}
            </span>
            {handsOn && (
              <span className="tag shrink-0" style={{ color: 'var(--color-s4)' }}>
                {PROFILE_LABEL_SHORT[session.attacker_profile]}
              </span>
            )}
            {diversionOf(session) && (
              <span className="tag shrink-0" style={{ color: 'var(--color-s3)' }}>decoy</span>
            )}
            <SignalBadges session={session} compact />
          </span>
          <span className="mt-0.5 flex flex-wrap items-baseline gap-x-1.5 text-[12px] text-paper-3">
            <Timestamp value={session.started_at} style="minute" className="readout" />
            <span aria-hidden="true">·</span>
            <span>{plural(session.command_count, 'command')}</span>
            {anomaly.state === 'flagged' && (
              <>
                <span aria-hidden="true">·</span>
                <span style={{ color: 'var(--color-s4)' }}>anomalous</span>
              </>
            )}
          </span>
        </span>
        <ExternalLink className="h-3 w-3 shrink-0 text-paper-3" strokeWidth={2} aria-hidden="true" />
      </Link>
    </li>
  )
}

/** Client fingerprints and tripwire signals across the sessions the API returned. */
function ToolingPanel({ sessions }) {
  const fingerprints = aggregateFingerprints(sessions)
  const signals = aggregateSignals(sessions)
  const anySignal = signals.likelyAgent + signals.possibleAgent + signals.honeytoken > 0
  if (fingerprints.length === 0 && !anySignal) return null

  return (
    <Panel title="Client fingerprints and signals" note={`from the latest ${sessions.length} sessions`}>
      <div className="space-y-3 px-4 pb-3.5" data-testid="profile-tooling">
        {anySignal && (
          <ul className="space-y-1 text-[13px] text-paper-2">
            {signals.likelyAgent > 0 && (
              <li>
                <span className="font-medium text-paper">Likely automated AI agent</span>
                {' '}in {plural(signals.likelyAgent, 'session')}: the engine&rsquo;s canary was triggered.
              </li>
            )}
            {signals.possibleAgent > 0 && (
              <li>
                Possibly automated in {plural(signals.possibleAgent, 'session')}, on timing alone.
              </li>
            )}
            {signals.honeytoken > 0 && (
              <li>
                <span className="font-medium text-paper">Honeytoken used</span>
                {' '}in {plural(signals.honeytoken, 'session')}.
              </li>
            )}
          </ul>
        )}
        {fingerprints.length > 0 && (
          <dl className="space-y-1.5">
            {fingerprints.map((row) => (
              <div key={`${row.key}:${row.value}`} className="flex items-center gap-2">
                <dt className="eyebrow w-24 shrink-0" title={row.hint}>{row.label}</dt>
                <dd className="readout min-w-0 flex-1 break-all text-[12px] text-paper">{cleanLine(row.value)}</dd>
                <span className="readout shrink-0 text-[12px] text-paper-3" title="Sessions carrying this value">
                  ×{row.count}
                </span>
                <CopyButton value={row.value} label={`Copy ${row.label}`} />
              </div>
            ))}
          </dl>
        )}
      </div>
    </Panel>
  )
}

export default function AttackerProfile() {
  const { ip } = useParams()
  const resource = usePolledResource(
    async ({ signal }) => {
      try {
        return await api.sessions.attacker(ip, { signal })
      } catch (err) {
        // "Nothing from this address" is an answer, not a failure.
        if (err?.status === 404) return { notFound: true }
        throw err
      }
    },
    { key: `attacker:${ip}`, intervalMs: REFRESH_MS },
  )
  const profile = resource.data && !resource.data.notFound ? resource.data : null
  const notFound = Boolean(resource.data?.notFound)

  const label = networkLabel(ip)
  const origin = cleanLine(profile?.geo?.country_name || profile?.geo?.country) || label || 'Unknown origin'

  const categories = CATEGORY_ORDER
    .filter((c) => profile?.categories?.[c])
    .map((c) => ({ key: c, label: CATEGORY_LABEL[c], value: profile.categories[c] }))
  const protocols = Object.entries(profile?.protocols || {})
    .sort((a, b) => b[1] - a[1])
    .map(([p, n]) => ({ key: p, label: cleanLine(p).toUpperCase(), value: n }))
  const tools = (profile?.tools || []).slice(0, 8).map((t) => ({
    key: t.name, label: cleanLine(String(t.name)).replace(/_/g, ' '), value: t.count,
  }))
  const intents = (profile?.intents || []).slice(0, 8).map((t) => ({
    key: t.name, label: cleanLine(String(t.name)).replace(/_/g, ' '), value: t.count,
  }))
  const usernames = (profile?.top_usernames || []).slice(0, 8).map((u) => ({
    key: u.username, label: cleanLine(u.username), value: u.count,
  }))
  const techniques = profile?.techniques || []
  const sessions = profile?.sessions || []

  return (
    <div className="mx-auto max-w-[1400px] space-y-3">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <Link to="/sessions" className="inline-flex items-center gap-1 text-[12px] text-paper-3 hover:text-paper">
            <ArrowLeft className="h-3 w-3" strokeWidth={2} />
            Sessions
          </Link>
          <h1 className="readout mt-1 truncate text-2xl">{cleanLine(ip)}</h1>
          <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-paper-2">
            <span>{origin}</span>
            {profile?.geo?.city && <span className="text-paper-3">· {cleanLine(profile.geo.city)}</span>}
            {profile?.scanner_operator && (
              <span
                className="tag"
                style={{ color: 'var(--color-paper-2)' }}
                title="This address belongs to a public research scanner. Its sessions are real, but they are not attacks."
              >
                {cleanLine(profile.scanner_operator)} scanner
              </span>
            )}
            {profile?.diverted && (
              <span className="tag" style={{ color: 'var(--color-s3)' }} title="Answered by the decoy copy of the website">
                diverted to decoy
              </span>
            )}
          </p>
        </div>
        <div className="flex flex-wrap items-start gap-2">
          <Link to={`/sessions?search=${encodeURIComponent(ip)}`} className="control">
            Filter sessions
          </Link>
          <button type="button" className="control" onClick={resource.reload} disabled={resource.loading || resource.refreshing}>
            <RefreshCw className={`h-3.5 w-3.5 ${resource.refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <BlockAddressControl ip={ip} />
        </div>
      </header>

      {resource.stale && (
        <StaleNotice what="This profile" error={resource.error} loadedAt={resource.loadedAt} onRetry={resource.reload} />
      )}

      {resource.loading ? (
        <LoadingRegion label="Loading address" />
      ) : resource.failed ? (
        <section className="panel">
          <LoadFailure what="this address" error={resource.error} onRetry={resource.reload} />
        </section>
      ) : notFound || profile.session_count === 0 ? (
        <section className="panel" data-testid="profile-empty">
          <EmptyState
            title="No sessions from this address"
            hint="It has not connected to a decoy. If it is listed under Indicators, it was named in a command or reached for by a payload, which is not the same as attacking."
            action={
              <Link to={`/sessions?search=${encodeURIComponent(ip)}`} className="control">
                Search sessions that mention it
              </Link>
            }
          />
        </section>
      ) : (
        <div className={`space-y-3 ${resource.stale ? 'is-stale' : ''}`}>
          <section className="panel p-4">
            {/* Four to a row at most. Eight across truncated every value on a
                1366-pixel screen. */}
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3.5 md:grid-cols-4">
              <Stat label="Sessions">{profile.session_count.toLocaleString()}</Stat>
              <Stat label="First seen">
                <Timestamp value={profile.first_seen} style="minute" />
              </Stat>
              <Stat label="Last seen">
                <Timestamp value={profile.last_seen} style="minute" />
              </Stat>
              <Stat label="Alerts">
                {profile.alert_count ?? 0}
                {profile.open_alert_count > 0 && (
                  <span style={{ color: 'var(--color-s4)' }}> · {profile.open_alert_count} open</span>
                )}
              </Stat>
              <Stat label="Logins tried">{(profile.credential_attempts ?? 0).toLocaleString()}</Stat>
              <Stat label="Files uploaded">{(profile.upload_count ?? 0).toLocaleString()}</Stat>
              <Stat label="Engines" mono={false}>
                {profile.nodes?.length ? profile.nodes.map(cleanLine).join(', ') : '—'}
              </Stat>
              <Stat label="Worst category" mono={false}>
                {categories.length ? <CategoryTag category={categories[0].key} /> : '—'}
              </Stat>
            </dl>
            {typeof profile.aggregated_sessions === 'number' && profile.aggregated_sessions < profile.session_count && (
              <p className="mt-3 text-[12px] text-paper-3">
                The breakdowns below are computed from the latest {profile.aggregated_sessions.toLocaleString()} of
                its {profile.session_count.toLocaleString()} sessions.
              </p>
            )}
          </section>

          <div className="grid items-start gap-3 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
            <Panel title="Sessions" note={`latest ${sessions.length} of ${profile.session_count}`}>
              {sessions.length ? (
                <ul className="max-h-[40rem] overflow-y-auto">
                  {sessions.map((s) => <SessionRow key={s.id} session={s} />)}
                </ul>
              ) : (
                <p className="px-4 py-6 text-[13px] text-paper-3">No sessions returned.</p>
              )}
              {profile.session_count > sessions.length && (
                <div className="border-t border-line px-4 py-2 text-[12px]">
                  <Link to={`/sessions?search=${encodeURIComponent(ip)}`} className="text-paper-2 hover:text-paper">
                    See all {profile.session_count.toLocaleString()} sessions
                  </Link>
                </div>
              )}
            </Panel>

            <div className="space-y-3">
              <ToolingPanel sessions={sessions} />
              <Panel title="What it did" note="By session">
                <RankList items={categories} emptyHint="No classified sessions." />
              </Panel>
              <Panel title="Protocols">
                <RankList items={protocols} mono emptyHint="—" />
              </Panel>
              <Panel title="Tools seen">
                <RankList items={tools} emptyHint="No offensive tooling detected." />
              </Panel>
              <Panel title="Intents">
                <RankList items={intents} emptyHint="No intents inferred." />
              </Panel>
              <Panel title="Usernames tried" note={profile.credential_attempts ? `${profile.credential_attempts} attempts` : undefined}>
                <RankList items={usernames} mono emptyHint="No logins attempted." />
              </Panel>
              {techniques.length > 0 && (
                <Panel title="MITRE ATT&CK" note={`${techniques.length} technique${techniques.length === 1 ? '' : 's'}`}>
                  <ul className="space-y-1 px-4 pb-3.5">
                    {techniques.slice(0, 20).map((t) => {
                      const url = techniqueUrl(t)
                      const body = (
                        <>
                          <span className="readout shrink-0 text-[12px] text-paper-2">{cleanLine(String(t.id))}</span>
                          <span className="min-w-0 flex-1 truncate text-[13px] text-paper">{clean(t.name)}</span>
                          {!url && <span className="tag shrink-0" style={{ color: 'var(--color-s2)' }}>unverified</span>}
                          <span className="readout shrink-0 text-[12px] text-paper-3">{t.count}</span>
                        </>
                      )
                      return (
                        <li key={t.id}>
                          {url ? (
                            <a
                              href={url}
                              target="_blank"
                              rel="noreferrer noopener"
                              className="flex items-baseline gap-2 rounded-[3px] px-1.5 py-1 -mx-1.5 transition-colors hover:bg-ink-2"
                            >
                              {body}
                            </a>
                          ) : (
                            <div className="flex items-baseline gap-2 px-1.5 py-1 -mx-1.5">{body}</div>
                          )}
                        </li>
                      )
                    })}
                  </ul>
                </Panel>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
