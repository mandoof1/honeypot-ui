import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, ExternalLink, RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import { LoadingRegion } from '../components/Loading'
import { CategoryTag } from '../components/Severity'
import { RankList } from '../components/charts'
import { diversionOf } from '../lib/diversion'
import { networkLabel } from '../lib/origin'
import { clean } from '../lib/text'
import { useVisiblePoll } from '../hooks/useVisiblePoll'
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
      <dd className={`mt-1 truncate text-[13px] text-paper ${mono ? 'readout' : ''}`}>{children}</dd>
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
  return (
    <li>
      <Link
        to={`/sessions?session=${session.id}`}
        className="flex items-center gap-3 border-t border-line px-4 py-2.5 transition-colors first:border-t-0 hover:bg-ink-2/60"
      >
        <span className="h-6 w-[3px] shrink-0 rounded-[1px]" style={{ background: color }} aria-hidden="true" />
        <span className="min-w-0 flex-1">
          <span className="flex items-baseline gap-2">
            <span className="readout shrink-0 text-[11px] uppercase text-paper-3">{session.protocol || '—'}</span>
            <span className="truncate text-[13px] text-paper">
              {CATEGORY_LABEL[session.attack_category] || CATEGORY_LABEL.unknown}
            </span>
            {handsOn && (
              <span className="tag shrink-0" style={{ color: 'var(--color-s4)' }}>
                {PROFILE_LABEL_SHORT[session.attacker_profile]}
              </span>
            )}
            {diversionOf(session) && (
              <span className="tag shrink-0" style={{ color: 'var(--color-s3)' }}>decoy</span>
            )}
          </span>
          <span className="mt-0.5 flex items-baseline gap-1.5 text-[12px] text-paper-3">
            <span className="readout">{new Date(session.started_at).toLocaleString()}</span>
            <span aria-hidden="true">·</span>
            <span>{session.command_count ?? 0} commands</span>
            {session.is_anomalous && (
              <>
                <span aria-hidden="true">·</span>
                <span style={{ color: 'var(--color-s4)' }}>anomalous</span>
              </>
            )}
          </span>
        </span>
        <ExternalLink className="h-3 w-3 shrink-0 text-paper-3" strokeWidth={2} />
      </Link>
    </li>
  )
}

export default function AttackerProfile() {
  const { ip } = useParams()
  const [profile, setProfile] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true)
    try {
      setProfile(await api.sessions.attacker(ip))
      setError(null)
    } catch (err) {
      setError(err.message || 'Could not load this address')
    } finally {
      if (!silent) setLoading(false)
    }
  }, [ip])

  useEffect(() => {
    const timer = setTimeout(load, 0)
    return () => clearTimeout(timer)
  }, [load])
  useVisiblePoll(() => load({ silent: true }), REFRESH_MS, [load])

  const label = networkLabel(ip)
  const origin = profile?.geo?.country_name || profile?.geo?.country || label || 'Unknown origin'

  const categories = CATEGORY_ORDER
    .filter((c) => profile?.categories?.[c])
    .map((c) => ({ key: c, label: CATEGORY_LABEL[c], value: profile.categories[c] }))
  const protocols = Object.entries(profile?.protocols || {})
    .sort((a, b) => b[1] - a[1])
    .map(([p, n]) => ({ key: p, label: p.toUpperCase(), value: n }))
  const tools = (profile?.tools || []).slice(0, 8).map((t) => ({
    key: t.name, label: clean(t.name).replace(/_/g, ' '), value: t.count,
  }))
  const intents = (profile?.intents || []).slice(0, 8).map((t) => ({
    key: t.name, label: clean(t.name).replace(/_/g, ' '), value: t.count,
  }))
  const usernames = (profile?.top_usernames || []).slice(0, 8).map((u) => ({
    key: u.username, label: clean(u.username), value: u.count,
  }))
  const techniques = profile?.techniques || []

  return (
    <div className="mx-auto max-w-[1400px] space-y-3">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <Link to="/sessions" className="inline-flex items-center gap-1 text-[12px] text-paper-3 hover:text-paper">
            <ArrowLeft className="h-3 w-3" strokeWidth={2} />
            Sessions
          </Link>
          <h1 className="readout mt-1 truncate text-2xl">{clean(ip)}</h1>
          <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-paper-2">
            <span>{origin}</span>
            {profile?.geo?.city && <span className="text-paper-3">· {clean(profile.geo.city)}</span>}
            {profile?.scanner_operator && (
              <span
                className="tag"
                style={{ color: 'var(--color-paper-2)' }}
                title="This address belongs to a public research scanner. Its sessions are real, but they are not attacks."
              >
                {clean(profile.scanner_operator)} scanner
              </span>
            )}
            {profile?.diverted && (
              <span className="tag" style={{ color: 'var(--color-s3)' }} title="Answered by the decoy copy of the website">
                diverted to decoy
              </span>
            )}
          </p>
        </div>
        <div className="flex gap-2">
          <Link to={`/sessions?search=${encodeURIComponent(ip)}`} className="control">
            Filter sessions
          </Link>
          <button type="button" className="control" onClick={() => load()} disabled={loading}>
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </button>
        </div>
      </header>

      {error && <ErrorBanner message={error} onRetry={() => load()} />}

      {loading ? (
        <LoadingRegion label="Loading address" />
      ) : !profile ? null : profile.session_count === 0 ? (
        <EmptyState
          title="No sessions from this address"
          hint="Nothing has been captured from it yet. It will appear here the first time it connects."
        />
      ) : (
        <>
          <section className="panel p-4">
            <dl className="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-4 lg:grid-cols-8">
              <Stat label="Sessions">{profile.session_count.toLocaleString()}</Stat>
              <Stat label="First seen">
                {profile.first_seen ? new Date(profile.first_seen).toLocaleString() : '—'}
              </Stat>
              <Stat label="Last seen">
                {profile.last_seen ? new Date(profile.last_seen).toLocaleString() : '—'}
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
                {profile.nodes?.length ? profile.nodes.map(clean).join(', ') : '—'}
              </Stat>
              <Stat label="Worst category" mono={false}>
                {categories.length ? <CategoryTag category={categories[0].key} /> : '—'}
              </Stat>
            </dl>
          </section>

          <div className="grid items-start gap-3 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
            <Panel title="Sessions" note={`latest ${profile.sessions?.length || 0} of ${profile.session_count}`}>
              {profile.sessions?.length ? (
                <ul className="max-h-[40rem] overflow-y-auto">
                  {profile.sessions.map((s) => <SessionRow key={s.id} session={s} />)}
                </ul>
              ) : (
                <p className="px-4 py-6 text-[13px] text-paper-3">No sessions returned.</p>
              )}
              {profile.session_count > (profile.sessions?.length || 0) && (
                <div className="border-t border-line px-4 py-2 text-[12px]">
                  <Link to={`/sessions?search=${encodeURIComponent(ip)}`} className="text-paper-2 hover:text-paper">
                    See all {profile.session_count.toLocaleString()} sessions
                  </Link>
                </div>
              )}
            </Panel>

            <div className="space-y-3">
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
                    {techniques.slice(0, 20).map((t) => (
                      <li key={t.id}>
                        <a
                          href={`https://attack.mitre.org/techniques/${String(t.id).replace('.', '/')}/`}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="group flex items-baseline gap-2 rounded-[3px] px-1.5 py-1 -mx-1.5 transition-colors hover:bg-ink-2"
                        >
                          <span className="readout shrink-0 text-[12px] text-paper-2">{t.id}</span>
                          <span className="min-w-0 flex-1 truncate text-[13px] text-paper">{clean(t.name)}</span>
                          <span className="readout shrink-0 text-[12px] text-paper-3">{t.count}</span>
                        </a>
                      </li>
                    ))}
                  </ul>
                </Panel>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
