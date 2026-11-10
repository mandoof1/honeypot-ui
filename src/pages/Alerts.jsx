import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Check, CircleSlash, ExternalLink, RefreshCw, Server, UserMinus, UserPlus } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { usePreferences } from '../context/usePreferences'
import { usePolledResource } from '../hooks/usePolledResource'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import { LoadFailure, StaleNotice } from '../components/LoadState'
import { LoadingRegion } from '../components/Loading'
import PageHeader from '../components/PageHeader'
import SavedSearches, { ShareLink } from '../components/SavedSearches'
import { SEVERITY_COLOR, SEVERITY_ORDER } from '../lib/severity'
import { clean, cleanLine } from '../lib/text'
import { fromInputValue, toInputValue } from '../lib/time'

/*
 * Alerts.
 *
 * The work of a queue is triage, so the page is built around the actions that
 * empty it — acknowledge, resolve, dismiss — rather than around reading. It
 * refreshes itself in the background without disturbing the filters or the
 * reader's place, because an alert queue that only updates on reload is a
 * queue nobody trusts.
 *
 * Two kinds of alert share the list. Session alerts come from a detection and
 * link to the evidence. System alerts come from the platform watching itself:
 * an engine that stopped reporting, a capture disk filling up. Those have no
 * session and are drawn with a different mark so they are never mistaken for
 * an attack.
 */

const PAGE_SIZE = 25
const REFRESH_MS = 30000

const STATUS_LABEL = {
  new: 'New',
  acknowledged: 'Acknowledged',
  resolved: 'Resolved',
  false_positive: 'False positive',
}

/* Ordered by what an analyst does next, not alphabetically. */
const STATUS_FILTERS = ['new', 'acknowledged', 'resolved', 'false_positive']

function timeAgo(iso) {
  const seconds = (Date.now() - new Date(iso).getTime()) / 1000
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

function isOpen(alert) {
  return alert.status === 'new' || alert.status === 'acknowledged'
}

function NotesEditor({ alert, onSave, canAct }) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(alert.notes || '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const save = async () => {
    setSaving(true)
    setError(null)
    try {
      await onSave(alert.id, { notes: draft })
      setEditing(false)
    } catch (err) {
      setError(err.message || 'Could not save the note')
    } finally {
      setSaving(false)
    }
  }

  if (editing) {
    return (
      <div className="mt-2.5 space-y-1.5">
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={3}
          maxLength={2000}
          aria-label={`Notes for alert ${alert.id}`}
          placeholder="What was checked, what was decided, who was told."
          className="field w-full resize-y text-[13px]"
        />
        {error && <p className="text-[12px]" style={{ color: 'var(--color-s4)' }}>{error}</p>}
        <div className="flex items-center gap-2">
          <button type="button" className="control control-primary" onClick={save} disabled={saving}>
            {saving ? 'Saving…' : 'Save note'}
          </button>
          <button
            type="button"
            className="text-[13px] font-medium text-paper-2 hover:text-paper"
            onClick={() => { setDraft(alert.notes || ''); setEditing(false) }}
            disabled={saving}
          >
            Cancel
          </button>
        </div>
      </div>
    )
  }

  if (!alert.notes && !canAct) return null

  return (
    <div className="mt-2 flex items-start gap-2">
      {alert.notes ? (
        <p className="min-w-0 flex-1 whitespace-pre-line rounded-[3px] bg-ink-2 px-2.5 py-1.5 text-[12px] leading-relaxed text-paper-2">
          {clean(alert.notes)}
        </p>
      ) : null}
      {canAct && (
        <button
          type="button"
          onClick={() => { setDraft(alert.notes || ''); setEditing(true) }}
          className="shrink-0 text-[12px] font-medium text-paper-3 transition-colors hover:text-paper"
        >
          {alert.notes ? 'Edit note' : 'Add note'}
        </button>
      )}
    </div>
  )
}

function AlertRow({ alert, busy, onUpdate, onPatch, canAct, selected, onSelect, me }) {
  const { formatTime } = usePreferences()
  // Every session folded into this alert; session_id is the most serious.
  const sessionIds = Array.isArray(alert.session_ids) && alert.session_ids.length > 0
    ? alert.session_ids
    : (alert.session_id != null ? [alert.session_id] : [])
  const color = SEVERITY_COLOR[alert.severity] || 'var(--color-paper-3)'
  const open = isOpen(alert)
  const system = alert.kind === 'system' || alert.session_id == null
  const occurrences = alert.occurrences || 1

  return (
    <li className="border-t border-line first:border-t-0">
      <article className="flex gap-3 px-3.5 py-3">
        {canAct && (
          <input
            type="checkbox"
            checked={selected}
            onChange={(e) => onSelect(alert.id, e.target.checked)}
            aria-label={`Select alert ${alert.id}`}
            className="mt-1 h-3.5 w-3.5 shrink-0 accent-paper"
          />
        )}
        <span
          className="mt-[3px] h-full w-[3px] shrink-0 rounded-[1px]"
          style={{ background: color }}
          aria-hidden="true"
        />

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            {system && (
              <Server
                className="h-3.5 w-3.5 shrink-0 self-center text-paper-3"
                strokeWidth={1.75}
                aria-label="System alert"
              />
            )}
            <h3 className="min-w-0 flex-1 text-[13px] font-medium text-paper">
              {clean(alert.title)}
            </h3>
            {occurrences > 1 && (
              <span
                className="readout shrink-0 text-[12px] text-paper-2"
                title={`Seen ${occurrences} times; last ${alert.last_seen_at ? timeAgo(alert.last_seen_at) : 'recently'}`}
              >
                ×{occurrences}
              </span>
            )}
            <span className="tag shrink-0" style={{ color }}>
              {alert.severity}
            </span>
            {!open && (
              <span className="tag shrink-0" style={{ color: 'var(--color-paper-3)' }}>
                {STATUS_LABEL[alert.status]}
              </span>
            )}
          </div>

          {alert.description && (
            <p className="mt-1 text-[12px] leading-relaxed text-paper-2">
              {clean(alert.description)}
            </p>
          )}

          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-paper-3">
            <span className="readout" title={formatTime(alert.created_at)}>
              {timeAgo(alert.created_at)}
            </span>
            {alert.last_seen_at && occurrences > 1 && (
              <span className="readout">last {timeAgo(alert.last_seen_at)}</span>
            )}
            {!system && sessionIds.length > 0 && (
              <span className="inline-flex flex-wrap items-center gap-x-1.5 gap-y-0.5" data-testid="alert-sessions">
                {sessionIds.length === 1 ? 'Session' : `${sessionIds.length} sessions:`}
                {sessionIds.slice(0, 12).map((id) => (
                  <Link
                    key={id}
                    to={`/sessions?session=${id}`}
                    aria-label={`Session ${id}`}
                    className="readout inline-flex items-center gap-0.5 transition-colors hover:text-paper"
                  >
                    {id}
                    {id === alert.session_id && sessionIds.length === 1 && (
                      <ExternalLink className="h-3 w-3" strokeWidth={2} aria-hidden="true" />
                    )}
                  </Link>
                ))}
                {sessionIds.length > 12 && <span>and {sessionIds.length - 12} more</span>}
              </span>
            )}
            {alert.attacker_ip && (
              <Link
                to={`/attackers/${encodeURIComponent(alert.attacker_ip)}`}
                className="readout transition-colors hover:text-paper"
                title="Everything this address has done"
              >
                {cleanLine(alert.attacker_ip)}
              </Link>
            )}
            {alert.mitre_techniques?.length > 0 && (
              <span className="readout">
                {alert.mitre_techniques.map((t) => cleanLine(t.id)).join(' · ')}
              </span>
            )}
            {alert.assigned_to_id != null && (
              <span className="inline-flex items-center gap-1">
                <UserPlus className="h-3 w-3" strokeWidth={2} />
                {alert.assigned_to_id === me?.id ? 'you' : clean(alert.assigned_to_name) || `user ${alert.assigned_to_id}`}
              </span>
            )}
            {alert.acknowledged_at && (
              <span title={formatTime(alert.acknowledged_at)}>
                acknowledged {timeAgo(alert.acknowledged_at)}
              </span>
            )}
            {alert.resolved_at && (
              <span title={formatTime(alert.resolved_at)}>
                closed {timeAgo(alert.resolved_at)}
              </span>
            )}
          </div>

          <NotesEditor alert={alert} onSave={onPatch} canAct={canAct} />

          {canAct && open && (
            <div className="mt-2.5 flex flex-wrap gap-1.5">
              {alert.status === 'new' && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => onUpdate(alert.id, 'acknowledged')}
                  className="control gap-1.5"
                >
                  <Check className="h-3.5 w-3.5" strokeWidth={2} />
                  Acknowledge
                </button>
              )}
              <button
                type="button"
                disabled={busy}
                onClick={() => onUpdate(alert.id, 'resolved')}
                className="control gap-1.5"
              >
                Resolve
              </button>
              {!system && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => onUpdate(alert.id, 'false_positive')}
                  className="control gap-1.5"
                  title="Mark as a false positive — this is the signal that the detection rule needs adjusting"
                >
                  <CircleSlash className="h-3.5 w-3.5" strokeWidth={2} />
                  False positive
                </button>
              )}
              {me?.id != null && alert.assigned_to_id !== me.id && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => onPatch(alert.id, { assigned_to_id: me.id })}
                  className="control gap-1.5"
                >
                  <UserPlus className="h-3.5 w-3.5" strokeWidth={2} />
                  Take
                </button>
              )}
              {alert.assigned_to_id != null && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => onPatch(alert.id, { unassign: true })}
                  className="control gap-1.5"
                  title="Remove the assignee"
                >
                  <UserMinus className="h-3.5 w-3.5" strokeWidth={2} />
                  Unassign
                </button>
              )}
            </div>
          )}
        </div>
      </article>
    </li>
  )
}

const FILTER_DEFAULTS = { status: 'new', severity: '', kind: '', ip: '', mine: '', since: '' }
const NO_SELECTION = new Set()

export default function Alerts() {
  const { hasRole, user } = useAuth()
  const { zone, zoneLabel } = usePreferences()
  const canAct = hasRole('analyst')
  const [searchParams, setSearchParams] = useSearchParams()
  const [busyId, setBusyId] = useState(null)
  const [actionError, setActionError] = useState(null)
  const [bulkBusy, setBulkBusy] = useState(false)

  // The filters are the URL. They used to be component state, so a link to
  // "resolved alerts" opened the default queue and a reload lost the view.
  // No `status` parameter means the working default, new alerts; "any" is
  // spelled out as status=all.
  const statusParam = searchParams.get('status')
  const status = statusParam === null ? 'new' : (statusParam === 'all' ? '' : statusParam)
  const severity = searchParams.get('severity') || ''
  const kind = searchParams.get('kind') || ''
  const ip = searchParams.get('ip') || ''
  const mine = searchParams.get('mine') === '1'
  const since = searchParams.get('since') || ''
  const page = Math.max(1, Math.floor(Number(searchParams.get('page'))) || 1)
  const userId = user?.id

  const setParams = (changes, replace = false) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current)
      Object.entries(changes).forEach(([key, value]) => {
        if (value === '' || value == null) next.delete(key)
        else next.set(key, value)
      })
      return next
    }, { replace })
  }
  const setFilter = (key, value, replace = false) => setParams({ [key]: value, page: '' }, replace)
  const setStatus = (value) => setFilter('status', value === 'new' ? '' : (value === '' ? 'all' : value))

  const params = { page, page_size: PAGE_SIZE }
  if (status) params.status = status
  if (severity) params.severity = severity
  if (kind) params.kind = kind
  if (ip.trim()) params.attacker_ip = ip.trim()
  if (mine && userId != null) params.assigned_to_id = userId
  if (since) params.since = since
  const requestKey = JSON.stringify(params)

  // The list is what the page is for; the counts are a convenience. A
  // failure to count must not hide a list that loaded.
  const queue = usePolledResource(
    async ({ signal }) => {
      const [list, summary] = await Promise.allSettled([
        api.alerts.list(params, { signal }),
        api.alerts.stats({ signal }),
      ])
      if (list.status === 'rejected') throw list.reason
      return {
        alerts: list.value.alerts || [],
        total: list.value.total || 0,
        stats: summary.status === 'fulfilled' ? summary.value : null,
      }
    },
    { key: requestKey, intervalMs: REFRESH_MS },
  )
  const alerts = queue.data?.alerts ?? []
  const total = queue.data?.total ?? 0
  const stats = queue.data?.stats ?? null
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  // Resolving the last alert on the last page used to leave the reader on a
  // page that no longer exists, looking at "No alerts match".
  const beyondLastPage = queue.data !== null && alerts.length === 0 && total > 0 && page > pages
  useEffect(() => {
    if (!beyondLastPage) return
    setSearchParams((current) => {
      const next = new URLSearchParams(current)
      if (pages > 1) next.set('page', pages)
      else next.delete('page')
      return next
    }, { replace: true })
  }, [beyondLastPage, pages, setSearchParams])

  // A selection belongs to the page and filters it was made under. Keyed to
  // them, it is empty the moment either changes, so a bulk action can only
  // ever reach alerts that are on screen.
  const [selection, setSelection] = useState({ key: null, ids: NO_SELECTION })
  const visibleIds = new Set(alerts.map((alert) => alert.id))
  const selected = selection.key === requestKey
    ? new Set([...selection.ids].filter((id) => visibleIds.has(id)))
    : NO_SELECTION

  const toggleSelected = (id, on) => {
    const next = new Set(selected)
    if (on) next.add(id)
    else next.delete(id)
    setSelection({ key: requestKey, ids: next })
  }
  const selectAllOpen = () => {
    setSelection({ key: requestKey, ids: new Set(alerts.filter(isOpen).map((a) => a.id)) })
  }
  const clearSelection = () => setSelection({ key: null, ids: NO_SELECTION })

  const patch = async (id, data) => {
    setBusyId(id)
    setActionError(null)
    try {
      await api.alerts.update(id, data)
      await queue.refresh()
    } catch (err) {
      setActionError(err.message || 'Could not update the alert')
      throw err
    } finally {
      setBusyId(null)
    }
  }

  const update = (id, nextStatus) => patch(id, { status: nextStatus }).catch(() => {})

  const bulk = async (nextStatus) => {
    const ids = [...selected]
    if (!ids.length) return
    setBulkBusy(true)
    setActionError(null)
    try {
      await api.alerts.bulk(ids, nextStatus)
      clearSelection()
      await queue.refresh()
    } catch (err) {
      setActionError(err.message || 'Could not update the selected alerts')
    } finally {
      setBulkBusy(false)
    }
  }

  const anyFilter = status !== 'new' || severity || kind || ip || mine || since
  const resetFilters = () => setParams(
    { ...Object.fromEntries(Object.keys(FILTER_DEFAULTS).map((key) => [key, ''])), page: '' },
  )

  return (
    <div className="mx-auto flex h-full max-w-[1100px] flex-col gap-3">
      <PageHeader
        eyebrow="Triage queue"
        title="Alerts"
        description="Detections and platform warnings waiting for a decision."
      >
        <SavedSearches scope="alerts" />
        <ShareLink />
        <button type="button" className="control" onClick={queue.reload} disabled={queue.loading || queue.refreshing}>
          <RefreshCw className={`h-3.5 w-3.5 ${queue.refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
          Refresh
        </button>
      </PageHeader>

      {actionError && <ErrorBanner title="The change was not applied" message={actionError} />}
      {queue.stale && <StaleNotice what="The alert queue" error={queue.error} loadedAt={queue.loadedAt} onRetry={queue.reload} />}

      {/* The counts are the queue's shape: how much is waiting, how much has
          been touched, how much is done. */}
      {stats && (
        <div className="panel grid grid-cols-3 divide-x divide-line">
          {[
            ['Waiting', stats.new, 'var(--color-s4)'],
            ['Acknowledged', stats.acknowledged, 'var(--color-s2)'],
            ['Closed', stats.resolved, 'var(--color-paper-3)'],
          ].map(([label, value, color]) => (
            <div key={label} className="px-4 py-3">
              <p className="eyebrow">{label}</p>
              <p
                className="readout mt-1 text-[22px] font-semibold tabular-nums"
                style={{ color }}
              >
                {value ?? 0}
              </p>
            </div>
          ))}
        </div>
      )}
      {queue.data !== null && !stats && (
        <p className="text-[13px] text-paper-3" role="alert">
          The queue totals could not be loaded. The list below is unaffected.
        </p>
      )}

      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Status</span>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="control"
          >
            <option value="">Any</option>
            {STATUS_FILTERS.map((s) => (
              <option key={s} value={s}>{STATUS_LABEL[s]}</option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="eyebrow">Severity</span>
          <select
            value={severity}
            onChange={(e) => setFilter('severity', e.target.value)}
            className="control capitalize"
          >
            <option value="">Any</option>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="eyebrow">Kind</span>
          <select
            value={kind}
            onChange={(e) => setFilter('kind', e.target.value)}
            className="control"
          >
            <option value="">Any</option>
            <option value="session">Detections</option>
            <option value="system">System</option>
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="eyebrow">Address</span>
          <input
            type="search"
            value={ip}
            placeholder="203.0.113.7"
            onChange={(e) => setFilter('ip', e.target.value, true)}
            className="field readout w-40"
          />
        </label>

        <label className="flex flex-col gap-1">
          <span className="eyebrow">Since ({zoneLabel()})</span>
          <input
            type="datetime-local"
            value={toInputValue(since, zone)}
            onChange={(e) => setFilter('since', fromInputValue(e.target.value, zone))}
            className="field"
          />
        </label>

        <label className="flex cursor-pointer items-center gap-2 pb-2">
          <input
            type="checkbox"
            checked={mine}
            onChange={(e) => setFilter('mine', e.target.checked ? '1' : '')}
            className="h-3.5 w-3.5 accent-paper"
          />
          <span className="text-[13px] font-medium text-paper-2">Assigned to me</span>
        </label>

        {anyFilter && (
          <button
            type="button"
            onClick={resetFilters}
            className="pb-2 text-[13px] font-medium text-paper-2 transition-colors hover:text-paper"
          >
            Reset
          </button>
        )}

        {total > 0 && (
          <p className="ml-auto pb-2 text-[12px] text-paper-3">
            {total} alert{total === 1 ? '' : 's'}
          </p>
        )}
      </div>

      {canAct && alerts.some(isOpen) && (
        <div className="flex flex-wrap items-center gap-2 text-[12px] text-paper-3">
          <button type="button" className="control" onClick={selectAllOpen}>
            Select open on this page
          </button>
          {selected.size > 0 && (
            <>
              <span className="readout">{selected.size} selected</span>
              <button type="button" className="control" disabled={bulkBusy} onClick={() => bulk('acknowledged')}>
                Acknowledge selected
              </button>
              <button type="button" className="control" disabled={bulkBusy} onClick={() => bulk('resolved')}>
                Resolve selected
              </button>
              <button
                type="button"
                className="text-[13px] font-medium text-paper-2 hover:text-paper"
                onClick={clearSelection}
              >
                Clear
              </button>
            </>
          )}
        </div>
      )}

      <section className="panel flex min-h-0 flex-1 flex-col overflow-hidden" aria-label="Alerts">
        {queue.loading ? (
          <LoadingRegion label="Loading alerts" />
        ) : queue.failed ? (
          <LoadFailure what="alerts" error={queue.error} onRetry={queue.reload} />
        ) : alerts.length === 0 ? (
          <EmptyState
            title={status === 'new' && !anyFilter ? 'Nothing waiting' : 'No alerts match'}
            hint={
              status === 'new' && !anyFilter
                ? 'Alerts appear here when a session matches a configured threshold, or when the platform notices a problem with itself. Thresholds are set under Settings.'
                : 'Try a different status, severity or filter.'
            }
          />
        ) : (
          <ul className={`min-h-0 flex-1 overflow-y-auto ${queue.stale ? 'is-stale' : ''}`}>
            {alerts.map((alert) => (
              <AlertRow
                key={alert.id}
                alert={alert}
                busy={busyId === alert.id || bulkBusy}
                onUpdate={update}
                onPatch={patch}
                canAct={canAct}
                selected={selected.has(alert.id)}
                onSelect={toggleSelected}
                me={user}
              />
            ))}
          </ul>
        )}

        {pages > 1 && !queue.loading && !queue.failed && (
          <div className="flex items-center justify-between border-t border-line px-3 py-2">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setParams({ page: page - 1 > 1 ? page - 1 : '' })}
              className="control"
            >
              Previous
            </button>
            <span className="readout text-[12px] text-paper-3">
              {Math.min(page, pages)} / {pages}
            </span>
            <button
              type="button"
              disabled={page >= pages}
              onClick={() => setParams({ page: page + 1 })}
              className="control"
            >
              Next
            </button>
          </div>
        )}
      </section>
    </div>
  )
}
