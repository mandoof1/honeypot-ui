import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ChevronLeft, ChevronRight, Download, FileText, Search, SlidersHorizontal, RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { usePreferences } from '../context/usePreferences'
import { useDebounced } from '../hooks/useDebounced'
import { usePolledResource } from '../hooks/usePolledResource'
import { useReportJobs } from '../hooks/useReportJobs'
import Dialog from '../components/Dialog'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import { LoadFailure, StaleNotice } from '../components/LoadState'
import { LoadingRegion } from '../components/Loading'
import ReportTray from '../components/ReportTray'
import SavedSearches, { ShareLink } from '../components/SavedSearches'
import SessionDetail from '../components/SessionDetail'
import { SignalBadges } from '../components/SessionSignals'
import Timestamp from '../components/Timestamp'
import { diversionOf } from '../lib/diversion'
import { saveBlob } from '../lib/download'
import { networkLabel } from '../lib/origin'
import { cleanLine } from '../lib/text'
import { fromInputValue, toInputValue } from '../lib/time'
import { anomalyReading } from '../lib/verdict'

import {
  CATEGORY_COLOR, CATEGORY_LABEL, HANDS_ON_PROFILES,
  PROFILE_LABEL_SHORT,
} from '../lib/severity'

const PAGE_SIZE = 25
//: How often the list silently refreshes with newly captured sessions.
const REFRESH_MS = 15000
//: How often the open session is re-read while it is still changing.
const DETAIL_REFRESH_MS = 5000

const CATEGORIES = ['benign', 'reconnaissance', 'exploitation', 'exfiltration']
const STATUSES = ['active', 'completed', 'terminated']

const QUICK_FORMATS = [
  { id: 'csv', label: 'CSV', hint: 'Spreadsheet summary of matching sessions' },
  { id: 'json', label: 'JSON', hint: 'Full session records' },
  { id: 'cef', label: 'CEF', hint: 'ArcSight and syslog collectors' },
  { id: 'stix', label: 'STIX', hint: 'Threat intelligence platforms' },
]

const REPORT_FORMATS = [
  { id: 'docx', label: 'Word report', hint: 'An investigation written by the local language model, as an editable Word file (up to 100 sessions)' },
  { id: 'pdf', label: 'PDF report', hint: 'An investigation written by the local language model, as a PDF (up to 100 sessions)' },
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
  // Set by the ATT&CK matrix when a technique cell is opened.
  technique: '',
}

const EMPTY_ROWS = []

function toApiDate(value) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toISOString()
}

/** True while the server is still expected to change this session by itself. */
function stillChanging(session) {
  if (!session) return false
  return session.status === 'active'
    || ['pending', 'running', 'triage'].includes(session.enrichment_status)
    || ['pending', 'running'].includes(session.triage_status)
}

/** One row in the list. Compact — the detail panel carries the depth. */
function SessionRow({ session, selected, onSelect }) {
  const color = CATEGORY_COLOR[session.attack_category] || CATEGORY_COLOR.unknown
  const handsOn = HANDS_ON_PROFILES.has(session.attacker_profile)
  const anomaly = anomalyReading(session)
  const address = cleanLine(session.attacker_ip)

  // The row button and the profile link are siblings. The link used to sit
  // inside the button, which is invalid markup: assistive technology
  // announced one control and keyboard focus could not reach the other.
  return (
    <li
      className={`flex items-stretch border-l-2 transition-colors ${
        selected ? 'border-l-paper bg-ink-2' : 'border-l-transparent hover:bg-ink-2/60'
      }`}
    >
      <button
        type="button"
        onClick={() => onSelect(session)}
        aria-current={selected ? 'true' : undefined}
        className="flex min-w-0 flex-1 items-center gap-3 py-[7px] pl-3 pr-2 text-left"
      >
        <span
          className="h-6 w-[3px] shrink-0 rounded-[1px]"
          style={{ background: color }}
          aria-hidden="true"
        />

        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="readout truncate text-[13px] text-paper">{address}</span>
            <span className="readout shrink-0 text-[12px] uppercase text-paper-3">
              {session.protocol || '—'}
            </span>
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
            <SignalBadges session={session} compact />
            {anomaly.state === 'flagged' && (
              <span className="tag shrink-0" style={{ color: 'var(--color-s4)' }}>
                anomalous
              </span>
            )}
            {anomaly.state === 'not_calibrated' && session.is_anomalous && (
              <span
                className="shrink-0 text-[12px] text-paper-3"
                title="The anomaly detector has no calibrated threshold yet, so its flag is not shown"
              >
                anomaly not calibrated
              </span>
            )}
          </span>
          <span className="mt-0.5 flex items-baseline gap-1.5 text-[12px] text-paper-3">
            <span className="truncate">
              {CATEGORY_LABEL[session.attack_category] || CATEGORY_LABEL.unknown}
            </span>
            <span aria-hidden="true">·</span>
            <span className="shrink-0">{cleanLine(session.geo?.country) || networkLabel(session.attacker_ip) || '—'}</span>
            <span aria-hidden="true">·</span>
            <Timestamp value={session.started_at} style="short" className="readout shrink-0" />
          </span>
        </span>
      </button>
      <Link
        to={`/attackers/${encodeURIComponent(session.attacker_ip)}`}
        aria-label={`Profile of ${address}`}
        title="Everything this address has done"
        className="flex shrink-0 items-center px-3 text-[12px] text-paper-3 transition-colors hover:text-paper"
      >
        profile
      </Link>
    </li>
  )
}

export default function SessionLogs() {
  const { hasRole } = useAuth()
  const { zone, zoneLabel, formatTime } = usePreferences()
  const [searchParams, setSearchParams] = useSearchParams()
  const [exporting, setExporting] = useState(null)
  const [exportError, setExportError] = useState(null)
  const [notice, setNotice] = useState('')
  const [reportSensitive, setReportSensitive] = useState(false)
  const reports = useReportJobs()

  // Selection is URL state, but must not change the list request's identity.
  const filterKey = JSON.stringify(Object.fromEntries(
    Object.keys(EMPTY_FILTERS).map((key) => [key, searchParams.get(key) || '']),
  ))
  const filters = useMemo(() => JSON.parse(filterKey), [filterKey])
  const requested = Number(searchParams.get('session')) || null
  const page = Math.max(1, Math.min(1000000, Math.floor(Number(searchParams.get('page'))) || 1))
  const [showFilters, setShowFilters] = useState(() => [...searchParams.keys()].some((key) => key in EMPTY_FILTERS && key !== 'search'))
  const [narrow, setNarrow] = useState(() => window.matchMedia('(max-width: 1023px)').matches)
  const [mobileOpen, setMobileOpen] = useState(() => Boolean(searchParams.get('session')) && window.matchMedia('(max-width: 1023px)').matches)

  const debouncedSearch = useDebounced(filters.search)
  const canExport = hasRole('analyst')
  const isAdmin = hasRole('admin')

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

  // The list. `requestKey` is the identity of what is being asked for: a
  // response is committed only while it is still the current question, so a
  // poll that started before a page or filter change can no longer leave the
  // old rows under the new pager. A failed refresh keeps the last good rows
  // on screen, marked stale; a view that never loaded says so instead of
  // claiming there are no sessions.
  const requestKey = `${page}|${queryKey}`
  const list = usePolledResource(
    async ({ signal }) => {
      const data = await api.sessions.list({ page, page_size: PAGE_SIZE, ...query }, { signal })
      return { rows: data.sessions || [], total: data.total || 0 }
    },
    { key: requestKey, intervalMs: REFRESH_MS },
  )
  const rows = list.data?.rows ?? EMPTY_ROWS
  const total = list.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  // Which session the panel shows. The URL names it; when the URL names none,
  // the first row of the list is shown and remembered, so a background
  // refresh that brings in newer sessions does not change what is being read.
  const [pinned, setPinned] = useState({ key: null, id: null })
  if (!requested && rows.length > 0 && pinned.key !== requestKey) {
    setPinned({ key: requestKey, id: rows[0].id })
  }
  const implicitId = pinned.key === requestKey ? pinned.id : (rows[0]?.id ?? null)
  const activeId = requested ?? implicitId
  const row = activeId === null ? null : rows.find((item) => item.id === activeId) || null

  // The open session is read on its own when the list cannot keep it current:
  // it lives on another page (an alert links to one), it is still changing,
  // or the reader has just asked for something to be done to it. Before
  // this, the panel copied a row once and showed that copy until another row
  // was clicked, so status, duration and a queued analysis never moved.
  const [watchedId, setWatchedId] = useState(null)
  const readsOwnDetail = activeId !== null && !list.loading
    && (!row || stillChanging(row) || watchedId === activeId)
  const detail = usePolledResource(
    ({ signal }) => api.sessions.get(activeId, { signal }),
    {
      key: `session:${activeId}`,
      enabled: readsOwnDetail,
      intervalMs: !row ? REFRESH_MS : DETAIL_REFRESH_MS,
    },
  )
  const refreshDetail = detail.refresh

  // Whichever copy was received last is the one shown.
  const fetched = detail.data && detail.data.id === activeId ? detail.data : null
  let selected = row || fetched
  if (row && fetched && (detail.loadedAt ?? 0) >= (list.loadedAt ?? 0)) selected = fetched
  const detailPending = activeId !== null && !selected && detail.loading
  const detailError = activeId !== null && !selected && detail.failed ? detail.error : null

  // After an action on the open session, read it straight away instead of
  // waiting for the next poll. Marking it watched turns its own reads on if
  // they were off, which loads it; if they were already on, ask again now.
  const sessionChanged = () => {
    setWatchedId(activeId)
    if (readsOwnDetail) refreshDetail()
  }

  useEffect(() => {
    const mql = window.matchMedia('(max-width: 1023px)')
    const onChange = () => {
      setNarrow(mql.matches)
      if (!mql.matches) setMobileOpen(false)
    }
    mql.addEventListener('change', onChange)
    return () => mql.removeEventListener('change', onChange)
  }, [])

  // No explicit abort here: the list hook aborts whenever the request
  // identity changes. Aborting on any parameter change instead left the list
  // stuck loading whenever the URL moved without the request following it —
  // which, now that typing no longer refetches, is every keystroke.
  const changeParams = useCallback((changes, replace = false) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current)
      Object.entries(changes).forEach(([key, value]) => {
        if (value === '' || value == null) next.delete(key)
        else next.set(key, value)
      })
      return next
    }, { replace })
  }, [setSearchParams])

  // A link to a page past the end (or the last page emptying) lands on the
  // last page that exists rather than on an empty list under a pager.
  const beyondLastPage = !list.loading && list.data !== null && rows.length === 0 && total > 0 && page > totalPages
  useEffect(() => {
    if (beyondLastPage) changeParams({ page: totalPages }, true)
  }, [beyondLastPage, totalPages, changeParams])

  const selectSession = (session) => {
    setMobileOpen(narrow)
    changeParams({ session: session.id }, true)
  }

  // Free-text filters replace rather than push: a select is one decision and
  // earns a history entry, but a text field would otherwise leave one entry per
  // character, so Back walked "AE" back to "A" instead of clearing the filter.
  const updateFilter = (key, value) => changeParams({ [key]: value, page: '', session: '' }, TEXT_FILTERS.has(key))
  const updateDate = (key, inputValue) => updateFilter(key, fromInputValue(inputValue, zone))
  const clearFilters = () => changeParams({ ...EMPTY_FILTERS, page: '', session: '' })

  // In-flight quick exports are abandoned when the page goes.
  const exportAbort = useRef(null)
  useEffect(() => () => exportAbort.current?.abort(), [])

  const handleExport = async (format) => {
    const controller = new AbortController()
    exportAbort.current = controller
    setExporting(format)
    setExportError(null)
    try {
      // The API returns the real file with its own Content-Disposition name;
      // an earlier version re-encoded every format as JSON and always saved
      // it with a .json extension.
      const { blob, filename, count, truncated } = await api.export.sessions(
        { ...query, format },
        { signal: controller.signal },
      )
      saveBlob(blob, filename)
      const matches = `${count.toLocaleString()} matching session${count === 1 ? '' : 's'}`
      setNotice(truncated ? `Exported the newest ${matches}. Narrow the filters to include the remaining records.` : `Exported ${matches}.`)
    } catch (err) {
      if (err?.name === 'AbortError') return
      setExportError(err.message || 'The export could not be produced.')
    } finally {
      if (!controller.signal.aborted) setExporting(null)
    }
  }

  const reportOnMatches = (format) => {
    const label = REPORT_FORMATS.find((item) => item.id === format)?.label || 'Report'
    reports.start({
      label: `${label} on ${total.toLocaleString()} matching session${total === 1 ? '' : 's'}`,
      params: { ...query, format, include_sensitive: isAdmin && reportSensitive },
    })
  }

  const reportOnSession = (session, format, includeSensitive) => {
    const label = REPORT_FORMATS.find((item) => item.id === format)?.label || 'Report'
    reports.start({
      label: `${label} on session ${String(session.session_uuid).slice(0, 8)}`,
      params: { format, session_ids: [session.id], include_sensitive: includeSensitive === true },
    })
  }

  /** A filter's value as the reader set it, not as the URL stores it. */
  const describeFilter = (key, value) => {
    if (key === 'date_from' || key === 'date_to') return formatTime(value, 'minute')
    if (key === 'exclude_scanners') return 'excluded'
    if (key === 'is_anomalous') return value === 'true' ? 'flagged only' : 'not flagged'
    return cleanLine(value)
  }

  // The session list API documents no technique filter. If rows come back
  // that do not carry the technique, the server ignored the parameter, and
  // saying "filtered" would be untrue.
  const techniqueIgnored = Boolean(query.technique) && rows.some(
    (item) => !(item.mitre_techniques || []).some((technique) => technique.id === query.technique),
  )

  return (
    <div className="mx-auto flex min-h-full max-w-[1600px] lg:h-full flex-col gap-3">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="eyebrow mb-1">Investigation workspace</p>
          <h1 className="text-2xl">Sessions</h1>
          <p className="mt-1 text-sm text-paper-2">Explore captured activity, inspect evidence, and share your findings.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <SavedSearches scope="sessions" />
          <ShareLink />
          <button className="control" onClick={list.reload} disabled={list.loading || list.refreshing}>
            <RefreshCw className={`h-3.5 w-3.5 ${list.refreshing ? 'animate-spin' : ''}`} />Refresh
          </button>
        </div>
      </header>

      {notice && <div role="status" className="panel flex items-center justify-between gap-3 p-3 text-sm text-paper-2">{notice}<button className="control" onClick={() => setNotice('')} aria-label="Dismiss notification">Dismiss</button></div>}
      {exportError && <ErrorBanner title="The export was not produced" message={exportError} />}
      {list.stale && <StaleNotice what="The session list" error={list.error} loadedAt={list.loadedAt} onRetry={list.reload} />}
      {detailError && (
        <div role="status" className="panel p-3 text-sm text-paper-2">
          Unable to open the linked session: {detailError}. You can still browse the matching sessions.
        </div>
      )}
      {techniqueIgnored && (
        <div role="alert" className="panel border-s3/60 p-3 text-sm text-paper-2">
          <span className="font-semibold text-paper">This list is not narrowed to {cleanLine(query.technique)}.</span>{' '}
          The API returned sessions without that technique, so it does not filter sessions by technique.
          Remove the technique filter, or open sessions from an address or indicator instead.
        </div>
      )}

      <ReportTray jobs={reports.jobs} onCancel={reports.cancel} onDismiss={reports.dismiss} />

      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <div className="relative min-w-0">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-paper-3"
              strokeWidth={1.75}
            />
            <input
              type="search"
              aria-label="Search sessions by address, session UUID or command text"
              placeholder="Address, session UUID or command text"
              title="Matches part of a source address, part of a session UUID, or text in the recorded commands"
              value={filters.search}
              onChange={(e) => updateFilter('search', e.target.value)}
              className="field w-[22rem] max-w-full pl-8"
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
              <span className="readout rounded-full bg-paper px-1.5 text-[12px] font-semibold text-ink-0">
                {activeFilterCount}
              </span>
            )}
          </button>
        </div>

        {canExport && (
          <div className="flex flex-col items-end gap-1.5">
            <div className="flex flex-wrap items-center justify-end gap-1.5">
              <span className="mr-1 hidden text-[12px] text-paper-3 sm:inline">Export matches</span>
              {QUICK_FORMATS.map(({ id, label, hint }) => (
                <button
                  key={id}
                  type="button"
                  disabled={exporting !== null || list.loading || total === 0}
                  onClick={() => handleExport(id)}
                  title={hint}
                  className="control"
                >
                  <Download className="h-3.5 w-3.5" strokeWidth={2} />
                  {exporting === id ? 'Preparing…' : label}
                </button>
              ))}
              <span className="mx-1 hidden h-5 w-px bg-line sm:inline-block" aria-hidden="true" />
              {REPORT_FORMATS.map(({ id, label, hint }) => (
                <button
                  key={id}
                  type="button"
                  disabled={list.loading || total === 0}
                  onClick={() => reportOnMatches(id)}
                  title={hint}
                  className="control"
                >
                  <FileText className="h-3.5 w-3.5" strokeWidth={2} />
                  {label}
                </button>
              ))}
            </div>
            {isAdmin && (
              <label
                className="flex cursor-pointer items-center gap-2 text-[12px] text-paper-2"
                title="Off by default. When on, Word and PDF reports carry the captured activity unredacted and the passwords tried. The request is recorded in the audit log."
              >
                <input
                  type="checkbox"
                  checked={reportSensitive}
                  onChange={(event) => setReportSensitive(event.target.checked)}
                  className="h-3.5 w-3.5 accent-paper"
                />
                Include original credentials in reports
              </label>
            )}
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
            <span className="eyebrow">{key === 'date_from' ? 'From' : 'Until'} ({zoneLabel()})</span>
            <input type="datetime-local" className="field" value={toInputValue(filters[key], zone)} onChange={(e) => updateDate(key, e.target.value)} />
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
        <span className="readout">
          {list.loading
            ? 'Searching…'
            : list.failed
              ? 'Not loaded'
              : `${total.toLocaleString()} matching session${total === 1 ? '' : 's'}`}
        </span>
        {/* The list API has one order and takes no sort parameter, so this is
            a statement, not a control. */}
        <span className="text-paper-3">newest first</span>
        {Object.entries(filters).filter(([, value]) => value).map(([key, value]) => (
          <button key={key} className="control text-xs" onClick={() => updateFilter(key, '')} aria-label={`Remove ${key.replaceAll('_', ' ')} filter`}>
            {key.replaceAll('_', ' ')}: {describeFilter(key, value)} ×
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
        <section className="panel flex min-h-0 flex-col overflow-hidden" aria-label="Sessions">
          {list.loading ? (
            <LoadingRegion label="Loading sessions" />
          ) : list.failed ? (
            <LoadFailure what="sessions" error={list.error} onRetry={list.reload} />
          ) : rows.length === 0 ? (
            <EmptyState
              title="No sessions match"
              hint={
                activeFilterCount > 0 || filters.search
                  ? 'Try widening or clearing the filters.'
                  : 'Sessions appear here as the honeypot engine captures traffic.'
              }
            />
          ) : (
            <ul className={`min-h-0 flex-1 overflow-y-auto ${list.stale ? 'is-stale' : ''}`}>
              {rows.map((session) => (
                <SessionRow
                  key={session.id}
                  session={session}
                  selected={activeId === session.id}
                  onSelect={selectSession}
                />
              ))}
            </ul>
          )}

          {total > PAGE_SIZE && !list.loading && !list.failed && (
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
            is selected, because there is no room for both. Only one of the
            two is mounted, so the open session is fetched and polled once. */}
        {!narrow && (
          <aside className="panel min-h-0" aria-label="Session details">
            {detailPending
              ? <LoadingRegion label="Loading session" />
              : <SessionDetail session={selected} onReport={reportOnSession} onChanged={sessionChanged} />}
          </aside>
        )}

        {narrow && selected && mobileOpen && (
          <Dialog label={`Session ${selected.session_uuid}`} onClose={() => setMobileOpen(false)}>
            <SessionDetail
              session={selected}
              onClose={() => setMobileOpen(false)}
              onReport={reportOnSession}
              onChanged={sessionChanged}
            />
          </Dialog>
        )}
      </div>
    </div>
  )
}
