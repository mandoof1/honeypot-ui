import { useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Link } from 'react-router-dom'
import { ChevronLeft, ChevronRight, Download, Search, SlidersHorizontal, RefreshCw, Link as LinkIcon } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { useDebounced } from '../hooks/useDebounced'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import SessionDetail from '../components/SessionDetail'
import { diversionOf } from '../lib/diversion'
import { networkLabel } from '../lib/origin'
import Dialog from '../components/Dialog'
import { LoadingRegion } from '../components/Loading'
import { useVisiblePoll } from '../hooks/useVisiblePoll'
import { clean } from '../lib/text'

import {
  CATEGORY_COLOR, CATEGORY_LABEL, HANDS_ON_PROFILES,
  PROFILE_LABEL_SHORT,
} from '../lib/severity'

function toApiDate(value) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toISOString()
}

function toLocalDate(value) {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000)
  return local.toISOString().slice(0, 16)
}

const PAGE_SIZE = 25
//: How often the list silently refreshes with newly captured sessions.
const REFRESH_MS = 15000

const CATEGORIES = ['benign', 'reconnaissance', 'exploitation', 'exfiltration']
const STATUSES = ['active', 'completed', 'terminated']

const EXPORT_FORMATS = [
  { id: 'csv', label: 'CSV', hint: 'Spreadsheet summary of matching sessions' },
  { id: 'json', label: 'JSON', hint: 'Full session records' },
  { id: 'cef', label: 'CEF', hint: 'ArcSight and syslog collectors' },
  { id: 'stix', label: 'STIX', hint: 'Threat intelligence platforms' },
]

/** Typed into character by character, so they must not each push history. */
const TEXT_FILTERS = new Set(['search', 'country'])

const EMPTY_FILTERS = {
  search: '',
  status: '',
  attack_category: '',
  country: '',
  protocol: '',
  date_from: '',
  date_to: '',
  is_anomalous: '',
  // Off by default: hiding traffic silently would misrepresent what the
  // honeypot saw. It is offered because scanner probes otherwise dominate
  // every count.
  exclude_scanners: '',
}

/** One row in the list. Compact — the detail panel carries the depth. */
function SessionRow({ session, selected, onSelect }) {
  const color = CATEGORY_COLOR[session.attack_category] || CATEGORY_COLOR.unknown
  const handsOn = HANDS_ON_PROFILES.has(session.attacker_profile)

  return (
    <li>
      <button
        type="button"
        onClick={() => onSelect(session)}
        aria-current={selected ? 'true' : undefined}
        className={`flex w-full items-center gap-3 border-l-2 px-3 py-[7px] text-left transition-colors ${
          selected
            ? 'border-l-paper bg-ink-2'
            : 'border-l-transparent hover:bg-ink-2/60'
        }`}
      >
        <span
          className="h-6 w-[3px] shrink-0 rounded-[1px]"
          style={{ background: color }}
          aria-hidden="true"
        />

        <span className="min-w-0 flex-1">
          <span className="flex items-baseline gap-2">
            <span className="readout truncate text-[13px] text-paper">
              {clean(session.attacker_ip)}
            </span>
            <span className="readout shrink-0 text-[11px] uppercase text-paper-3">
              {session.protocol || '—'}
            </span>
            <Link
              to={`/attackers/${encodeURIComponent(session.attacker_ip)}`}
              onClick={(e) => e.stopPropagation()}
              className="shrink-0 text-[11px] text-paper-3 hover:text-paper"
              title="Everything this address has done"
            >
              profile
            </Link>
            {handsOn && (
              <span className="tag shrink-0" style={{ color: 'var(--color-s4)' }}>
                {PROFILE_LABEL_SHORT[session.attacker_profile]}
              </span>
            )}
            {diversionOf(session) && (
              <span
                className="tag shrink-0"
                style={{ color: 'var(--color-s3)' }}
                title="Answered by the decoy copy of the website"
              >
                decoy
              </span>
            )}
          </span>
          <span className="mt-0.5 flex items-baseline gap-1.5 text-[12px] text-paper-3">
            <span className="truncate">
              {CATEGORY_LABEL[session.attack_category] || CATEGORY_LABEL.unknown}
            </span>
            <span aria-hidden="true">·</span>
            <span className="shrink-0">{session.geo?.country || networkLabel(session.attacker_ip) || '—'}</span>
            <span aria-hidden="true">·</span>
            <span className="readout shrink-0">
              {new Date(session.started_at).toLocaleString(undefined, {
                month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
              })}
            </span>
          </span>
        </span>

        {session.is_anomalous && (
          <span
            className="h-1.5 w-1.5 shrink-0 rounded-full bg-s4"
            title="Flagged as anomalous"
          />
        )}
      </button>
    </li>
  )
}

export default function SessionLogs() {
  const { hasRole } = useAuth()
  const [sessions, setSessions] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [exporting, setExporting] = useState(null)
  const [selected, setSelected] = useState(null)
  const [detailError, setDetailError] = useState(null)
  const [searchParams, setSearchParams] = useSearchParams()
  // Selection is URL state, but must not change the list request's identity.
  const filterKey = JSON.stringify(Object.fromEntries(
    Object.keys(EMPTY_FILTERS).map((key) => [key, searchParams.get(key) || '']),
  ))
  const filters = useMemo(() => JSON.parse(filterKey), [filterKey])
  const requested = Number(searchParams.get('session')) || null
  const page = Math.max(1, Math.min(1000000, Math.floor(Number(searchParams.get('page'))) || 1))
  const [showFilters, setShowFilters] = useState(() => [...searchParams.keys()].some((key) => key in EMPTY_FILTERS && key !== 'search'))
  const [mobileOpen, setMobileOpen] = useState(() => Boolean(searchParams.get('session')) && window.matchMedia('(max-width: 1023px)').matches)
  const [notice, setNotice] = useState('')
  const [reload, setReload] = useState(0)

  const debouncedSearch = useDebounced(filters.search)
  const canExport = hasRole('analyst')

  // Keyed on the *debounced* search, not the raw input. Keying this on
  // `filters` gave it a new identity per keystroke, so the fetch effect refired
  // on each one — carrying the stale search value — and the debounce only chose
  // what was sent, never whether to send at all. Typing four characters issued
  // five list requests, four of them for a search term the user had moved past.
  const queryKey = useMemo(() => {
    const base = JSON.parse(filterKey)
    return JSON.stringify({
      ...base,
      search: debouncedSearch,
      date_from: base.date_from ? toApiDate(base.date_from) : '',
      date_to: base.date_to ? toApiDate(base.date_to) : '',
    })
  }, [filterKey, debouncedSearch])
  const query = useMemo(() => JSON.parse(queryKey), [queryKey])

  const activeFilterCount = useMemo(
    () =>
      Object.entries(filters).filter(([k, v]) => k !== 'search' && v !== '').length,
    [filters],
  )

  const fetchSessions = useCallback(() => setReload((value) => value + 1), [])

  useEffect(() => {
    const controller = new AbortController()
    const options = { signal: controller.signal }
    const load = async () => {
      setLoading(true)
      try {
        const data = await api.sessions.list({ page, page_size: PAGE_SIZE, ...query }, options)
        if (controller.signal.aborted) return
        const rows = data.sessions || []
        setSessions(rows)
        setTotal(data.total || 0)
        setError(null)
      } catch (err) {
        if (controller.signal.aborted) return
        setError(err.message)
        setSessions([])
        setSelected(null)
        setTotal(0)
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }
    const timer = setTimeout(load, 0)
    return () => { controller.abort(); clearTimeout(timer) }
  }, [page, query, reload])

  // Auto-refresh so new captures appear without a manual reload. This is a
  // silent background refresh: it replaces the current page in place and never
  // toggles the loading state, so the list doesn't flash or lose the reader's
  // place. User actions (paging, filtering, selecting) still go through the
  // effect above.
  // Polls only while the tab is visible, never overlaps itself, and keeps the
  // last good list on failure; the next tick or a manual reload retries.
  useVisiblePoll(async () => {
    try {
      const data = await api.sessions.list({ page, page_size: PAGE_SIZE, ...query })
      setSessions(data.sessions || [])
      setTotal(data.total || 0)
      setError(null)
    } catch {
      // keep the last good list
    }
  }, REFRESH_MS, [page, query])

  // Missing or slow deep-link details must not hide a successful list result.
  //
  // Keyed on the requested id and the page's *row ids*, not on the rows
  // themselves: the background refresh replaces the array every 15 s, and
  // re-running this on each one cleared the open panel for a session that
  // lives on another page — exactly the kind an alert links to — then
  // fetched it again, collapsing the transcript and re-logging every
  // credential reveal.
  const rowIds = sessions.map((item) => item.id).join(',')
  useEffect(() => {
    if (loading) return
    const controller = new AbortController()
    const loadDetail = async () => {
      setDetailError(null)
      const row = sessions.find((item) => item.id === requested)
      if (!requested || row) {
        // Refreshed rows carry newer analysis (category, enrichment); adopt
        // them, but keep the panel open on whatever is already selected.
        setSelected((current) => {
          if (row) return current?.id === row.id ? { ...current, ...row } : row
          if (current && !requested) return current
          return sessions[0] || null
        })
        return
      }
      setSelected((current) => (current?.id === requested ? current : null))
      try {
        const detail = await api.sessions.get(requested, { signal: controller.signal })
        if (!controller.signal.aborted) setSelected(detail)
      } catch (err) {
        if (!controller.signal.aborted) {
          setDetailError(`Unable to open the linked session: ${err.message}. You can still browse the matching sessions.`)
        }
      }
    }
    const timer = setTimeout(loadDetail, 0)
    return () => { controller.abort(); clearTimeout(timer) }
    // `sessions` is read through rowIds on purpose; see above.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requested, rowIds, loading])

  useEffect(() => {
    const desktop = window.matchMedia('(min-width: 1024px)')
    const closeOnDesktop = () => { if (desktop.matches) setMobileOpen(false) }
    desktop.addEventListener('change', closeOnDesktop)
    return () => desktop.removeEventListener('change', closeOnDesktop)
  }, [])

  // No explicit abort here: the fetch effect's cleanup already aborts whenever
  // the request identity changes. Aborting on any parameter change instead left
  // `loading` stuck true whenever the URL moved without the request following
  // it — which, now that typing no longer refetches, is every keystroke.
  const changeParams = (changes, replace = false) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current)
      Object.entries(changes).forEach(([key, value]) => {
        if (value === '' || value == null) next.delete(key)
        else next.set(key, value)
      })
      return next
    }, { replace })
  }
  const selectSession = (session) => {
    setSelected(session)
    setMobileOpen(window.matchMedia('(max-width: 1023px)').matches)
    changeParams({ session: session.id }, true)
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  // Free-text filters replace rather than push: a select is one decision and
  // earns a history entry, but a text field would otherwise leave one entry per
  // character, so Back walked "AE" back to "A" instead of clearing the filter.
  const updateFilter = (key, value) => changeParams({ [key]: key.startsWith('date_') && value ? toApiDate(value) : value, page: '', session: '' }, TEXT_FILTERS.has(key))
  const clearFilters = () => changeParams({ ...EMPTY_FILTERS, page: '', session: '' })
  const shareView = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href)
      setNotice('Investigation link copied. Teammates must sign in to view it.')
    } catch {
      setNotice('Copy the address from your browser to share this investigation.')
    }
  }

  const handleExport = async (format) => {
    setExporting(format)
    try {
      // The API returns the real file with its own Content-Disposition name;
      // an earlier version re-encoded every format as JSON and always saved
      // it with a .json extension.
      const { blob, filename, count, truncated } = await api.export.sessions({ ...query, format })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
      const matches = `${count.toLocaleString()} matching session${count === 1 ? '' : 's'}`
      setNotice(truncated ? `Exported the newest ${matches}. Narrow the filters to include the remaining records.` : `Exported ${matches}.`)
      setError(null)
    } catch (err) {
      setError(`Export failed: ${err.message}`)
    } finally {
      setExporting(null)
    }
  }

  return (
    <div className="mx-auto flex min-h-full max-w-[1600px] lg:h-full flex-col gap-3">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="eyebrow mb-1">Investigation workspace</p>
          <h1 className="text-2xl">Sessions</h1>
          <p className="mt-1 text-sm text-paper-2">Explore captured activity, inspect evidence, and share your findings.</p>
        </div>
        <div className="flex gap-2">
          <button className="control" onClick={shareView}><LinkIcon className="h-3.5 w-3.5" />Copy link</button>
          <button className="control" onClick={fetchSessions} disabled={loading}><RefreshCw className="h-3.5 w-3.5" />Refresh</button>
        </div>
      </header>
      {notice && <div role="status" className="panel flex items-center justify-between gap-3 p-3 text-sm text-paper-2">{notice}<button className="control" onClick={() => setNotice('')} aria-label="Dismiss notification">Dismiss</button></div>}
      {error && <ErrorBanner message={error} onRetry={fetchSessions} />}
      {detailError && <div role="status" className="panel p-3 text-sm text-paper-2">{detailError}</div>}

      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <div className="relative min-w-0">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-paper-3"
              strokeWidth={1.75}
            />
            <input
              type="search"
              aria-label="Search sessions by address or session ID"
              placeholder="Address or session ID"
              value={filters.search}
              onChange={(e) => updateFilter('search', e.target.value)}
              className="field w-60 pl-8"
            />
          </div>
          <button
            type="button"
            aria-expanded={showFilters}
            onClick={() => setShowFilters((open) => !open)}
            className="control"
            style={showFilters ? { borderColor: 'var(--color-paper-2)' } : undefined}
          >
            <SlidersHorizontal className="h-3.5 w-3.5" strokeWidth={2} />
            Filters
            {activeFilterCount > 0 && (
              <span className="readout rounded-full bg-paper px-1.5 text-[11px] font-semibold text-ink-0">
                {activeFilterCount}
              </span>
            )}
          </button>
        </div>

        {canExport && (
          <div className="flex items-center gap-1.5">
            <span className="mr-1 hidden text-[12px] text-paper-3 sm:inline">Export matches</span>
            {EXPORT_FORMATS.map(({ id, label, hint }) => (
              <button
                key={id}
                type="button"
                disabled={exporting !== null || loading || total === 0}
                onClick={() => handleExport(id)}
                title={hint}
                className="control"
              >
                <Download className="h-3.5 w-3.5" strokeWidth={2} />
                {exporting === id ? 'Preparing…' : label}
              </button>
            ))}
          </div>
        )}
      </div>

      {showFilters && (
        <div className="panel flex flex-wrap items-end gap-3 p-3">
          <label className="flex flex-col gap-1">
            <span className="eyebrow">Protocol</span>
            <select className="control" value={filters.protocol} onChange={(e) => updateFilter('protocol', e.target.value)}>
              <option value="">All protocols</option>
              {['ssh', 'ftp', 'telnet', 'http', 'https'].map((value) => <option key={value} value={value}>{value.toUpperCase()}</option>)}
            </select>
          </label>
          {['date_from', 'date_to'].map((key) => <label key={key} className="flex flex-col gap-1">
            <span className="eyebrow">{key === 'date_from' ? 'From' : 'Until'} (local time)</span>
            <input type="datetime-local" className="field" value={toLocalDate(filters[key])} onChange={(e) => updateFilter(key, e.target.value)} />
          </label>)}
          <label className="flex flex-col gap-1">
            <span className="eyebrow">Status</span>
            <select
              value={filters.status}
              onChange={(e) => updateFilter('status', e.target.value)}
              className="control capitalize"
            >
              <option value="">Any</option>
              {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>

          <label className="flex flex-col gap-1">
            <span className="eyebrow">Category</span>
            <select
              value={filters.attack_category}
              onChange={(e) => updateFilter('attack_category', e.target.value)}
              className="control capitalize"
            >
              <option value="">Any</option>
              {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </label>

          <label className="flex flex-col gap-1">
            <span className="eyebrow">Country</span>
            <input
              type="text"
              placeholder="NL"
              maxLength={2}
              value={filters.country}
              onChange={(e) => updateFilter('country', e.target.value.toUpperCase())}
              className="field w-20"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="eyebrow">Research scanners</span>
            <select
              value={filters.exclude_scanners}
              onChange={(e) => updateFilter('exclude_scanners', e.target.value)}
              className="control"
              title="Censys, Shodan and Shadowserver scan every public address continuously. They are always recorded; this decides whether they are shown."
            >
              <option value="">Include</option>
              <option value="true">Exclude</option>
            </select>
          </label>

          <label className="flex flex-col gap-1">
            <span className="eyebrow">Anomaly</span>
            <select
              value={filters.is_anomalous}
              onChange={(e) => updateFilter('is_anomalous', e.target.value)}
              className="control"
            >
              <option value="">Any</option>
              <option value="true">Flagged only</option>
              <option value="false">Not flagged</option>
            </select>
          </label>

          {activeFilterCount > 0 && (
            <button
              type="button"
              onClick={clearFilters}
              className="ml-auto text-[13px] font-medium text-paper-2 transition-colors hover:text-paper"
            >
              Clear filters
            </button>
          )}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 text-xs text-paper-2" aria-live="polite">
        <span className="readout">{loading ? 'Searching…' : `${total.toLocaleString()} matching session${total === 1 ? '' : 's'}`}</span>
        {Object.entries(filters).filter(([, value]) => value).map(([key, value]) => (
          <button key={key} className="control text-xs" onClick={() => updateFilter(key, '')} aria-label={`Remove ${key.replaceAll('_', ' ')} filter`}>
            {key.replaceAll('_', ' ')}: {value} ×
          </button>
        ))}
        {Object.values(filters).some(Boolean) && <button className="control" onClick={clearFilters}>Reset all</button>}
      </div>
      {/*
        Master–detail rather than a modal: an analyst comparing sessions can
        step down the list and watch the right-hand panel change, instead of
        opening and dismissing a dialog for each one.
      */}
      <div className="grid min-h-[24rem] flex-1 gap-3 lg:min-h-0 lg:grid-cols-[minmax(0,1fr)_minmax(0,26rem)]">
        <section className="panel flex min-h-0 flex-col overflow-hidden">
          {loading ? (
            <LoadingRegion label="Loading sessions" />
          ) : sessions.length === 0 ? (
            <EmptyState
              title="No sessions match"
              hint={
                activeFilterCount > 0
                  ? 'Try widening or clearing the filters.'
                  : 'Sessions appear here as the honeypot engine captures traffic.'
              }
            />
          ) : (
            <ul className="min-h-0 flex-1 overflow-y-auto">
              {sessions.map((session) => (
                <SessionRow
                  key={session.id}
                  session={session}
                  selected={selected?.id === session.id}
                  onSelect={selectSession}
                />
              ))}
            </ul>
          )}

          {total > PAGE_SIZE && (
            <div className="flex shrink-0 items-center justify-between border-t border-line px-3 py-2">
              <p className="readout text-[12px] text-paper-3">
                {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, total)} of{' '}
                {total.toLocaleString()}
              </p>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => changeParams({ page: Math.max(1, page - 1), session: '' })}
                  disabled={page === 1}
                  aria-label="Previous page"
                  className="control px-1.5"
                >
                  <ChevronLeft className="h-4 w-4" strokeWidth={2} />
                </button>
                <span className="readout px-1.5 text-[12px] text-paper-2">
                  {page} / {totalPages}
                </span>
                <button
                  type="button"
                  onClick={() => changeParams({ page: Math.min(totalPages, page + 1), session: '' })}
                  disabled={page >= totalPages}
                  aria-label="Next page"
                  className="control px-1.5"
                >
                  <ChevronRight className="h-4 w-4" strokeWidth={2} />
                </button>
              </div>
            </div>
          )}
        </section>

        {/* Desktop: a standing panel. Narrow: a sheet, only once something
            is selected, because there is no room for both. */}
        <aside className="panel hidden min-h-0 lg:block">
          <SessionDetail session={selected} />
        </aside>

        {selected && mobileOpen && (
          <Dialog label={`Session ${selected.session_uuid}`} onClose={() => setMobileOpen(false)} className="lg:hidden">
            <SessionDetail session={selected} onClose={() => setMobileOpen(false)} />
          </Dialog>
        )}
      </div>
    </div>
  )
}
