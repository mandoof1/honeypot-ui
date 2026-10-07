import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Copy, Download, Search } from 'lucide-react'
import { api } from '../services/api'
import { useDebounced } from '../hooks/useDebounced'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import { LoadingRegion } from '../components/Loading'
import { clean } from '../lib/text'

/*
 * Indicators.
 *
 * Every session has written these since the first ingest — the attacker's
 * address, the hosts and URLs its droppers reached for, the tools it used,
 * hashes of what it uploaded. No route read the table, so the most directly
 * shareable output the system produces existed only in the database.
 *
 * Grouped by value, ordered by how many distinct sessions saw it. A single
 * session's indicators are a footnote; the same C2 host across forty sessions
 * from thirty addresses is the finding, and sorting by breadth is what makes
 * that the first row rather than the fortieth.
 */

const PAGE_SIZE = 50

const TYPES = [
  { id: '', label: 'All' },
  { id: 'ip', label: 'Addresses' },
  { id: 'domain', label: 'Domains' },
  { id: 'url', label: 'URLs' },
  { id: 'filename', label: 'Payload names' },
  { id: 'file_hash', label: 'Hashes' },
  { id: 'tool', label: 'Tools' },
]

/* Breadth of observation, not threat: a neutral ramp, since colour in this
   interface means severity and an indicator does not have one. */
function Breadth({ sessions, max }) {
  const width = max > 1 ? Math.max(4, (sessions / max) * 100) : 100
  return (
    <span className="flex items-center gap-2">
      <span className="h-1 w-16 shrink-0 rounded-[1px] bg-ink-3" aria-hidden="true">
        <span
          className="block h-full rounded-[1px] bg-paper-2"
          style={{ width: `${width}%` }}
        />
      </span>
      <span className="readout w-8 shrink-0 text-right text-[12px] tabular-nums text-paper-2">
        {sessions}
      </span>
    </span>
  )
}

export default function Indicators() {
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(0)
  const [type, setType] = useState('')
  const [search, setSearch] = useState('')
  // Two is the backend's own default for the feed: one sighting is a
  // footnote, the same host across sessions is the finding.
  const [minSessions, setMinSessions] = useState(2)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [copied, setCopied] = useState(null)

  const debouncedSearch = useDebounced(search)
  // Only the newest request may commit: a slow response for an earlier
  // filter must not overwrite the current one.
  const requestId = useRef(0)

  const load = useCallback(async () => {
    const id = ++requestId.current
    setLoading(true)
    try {
      const params = { page, page_size: PAGE_SIZE, min_sessions: minSessions }
      if (type) params.ioc_type = type
      if (debouncedSearch) params.search = debouncedSearch
      const data = await api.iocs.list(params)
      if (id !== requestId.current) return
      setRows(data.indicators || [])
      setTotal(data.total || 0)
      setError(null)
    } catch (err) {
      if (id !== requestId.current) return
      setError(err.message || 'Could not load indicators')
      setRows([])
    } finally {
      if (id === requestId.current) setLoading(false)
    }
  }, [page, type, debouncedSearch, minSessions])

  useEffect(() => {
    const timer = setTimeout(load, 0)
    return () => clearTimeout(timer)
  }, [load])

  const copy = async (value) => {
    try {
      // The sanitised value: hidden characters an attacker put in an
      // indicator must not travel into a blocklist via the clipboard.
      await navigator.clipboard.writeText(clean(value))
      setCopied(value)
      setTimeout(() => setCopied(null), 1200)
    } catch {
      // Clipboard access is denied in some contexts; the value is on screen
      // and selectable, so there is nothing useful to say about it.
    }
  }

  const downloadFeed = async () => {
    try {
      const { blob, filename } = await api.iocs.feed({
        ioc_type: type || 'ip',
        min_sessions: minSessions,
      })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (err) {
      setError(`Feed download failed: ${err.message}`)
    }
  }

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const max = rows.length ? Math.max(...rows.map((r) => r.sessions)) : 1

  return (
    <div className="mx-auto flex h-full max-w-[1100px] flex-col gap-3">
      {error && <ErrorBanner message={error} onRetry={load} />}

      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Search</span>
          <span className="relative">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-paper-3"
              strokeWidth={1.75}
            />
            <input
              type="search"
              aria-label="Search indicators"
              placeholder="Host, URL or hash"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1) }}
              className="field w-56 pl-8"
            />
          </span>
        </label>

        <label className="flex flex-col gap-1">
          <span className="eyebrow">Type</span>
          <select
            value={type}
            onChange={(e) => { setType(e.target.value); setPage(1) }}
            className="control"
          >
            {TYPES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="eyebrow">Seen in at least</span>
          <select
            value={minSessions}
            onChange={(e) => { setMinSessions(Number(e.target.value)); setPage(1) }}
            className="control"
          >
            <option value={1}>1 session</option>
            <option value={2}>2 sessions</option>
            <option value={5}>5 sessions</option>
            <option value={10}>10 sessions</option>
          </select>
        </label>

        <button
          type="button"
          onClick={downloadFeed}
          className="control ml-auto gap-1.5"
          title="One value per line — the shape ipset, pf, Suricata datasets and Splunk lookups read"
        >
          <Download className="h-3.5 w-3.5" strokeWidth={2} />
          {type ? 'Blocklist' : 'Blocklist (IPs only)'}
        </button>
      </div>

      <section className="panel flex min-h-0 flex-1 flex-col overflow-hidden">
        {loading ? (
          <LoadingRegion label="Loading indicators" />
        ) : rows.length === 0 ? (
          <EmptyState
            title="No indicators"
            hint={
              minSessions > 1
                ? `Nothing has been seen in ${minSessions} or more sessions yet.`
                : 'Indicators are extracted from every ingested session.'
            }
          />
        ) : (
          <div className="min-h-0 flex-1 overflow-y-auto">
            <table className="w-full border-collapse text-left">
              <thead className="sticky top-0 bg-ink-1">
                <tr className="border-b border-line">
                  <th className="eyebrow px-3.5 py-2 font-normal">Indicator</th>
                  <th className="eyebrow hidden px-3.5 py-2 font-normal sm:table-cell">
                    Type
                  </th>
                  <th className="eyebrow px-3.5 py-2 font-normal">Sessions</th>
                  <th className="eyebrow hidden px-3.5 py-2 font-normal md:table-cell">
                    Last seen
                  </th>
                  <th className="px-3.5 py-2">
                    <span className="sr-only">Copy</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr
                    key={`${row.type}:${row.value}`}
                    className="group border-b border-line last:border-b-0 hover:bg-ink-2"
                  >
                    <td className="max-w-0 px-3.5 py-2">
                      {row.type === 'ip' ? (
                        <Link
                          to={`/attackers/${encodeURIComponent(row.value)}`}
                          className="readout block truncate text-[12px] text-paper hover:underline"
                          title="Everything this address has done"
                        >
                          {clean(row.value)}
                        </Link>
                      ) : (
                        <span className="readout block truncate text-[12px] text-paper" title={clean(row.value)}>
                          {clean(row.value)}
                        </span>
                      )}
                    </td>
                    <td className="hidden px-3.5 py-2 sm:table-cell">
                      <span className="tag" style={{ color: 'var(--color-paper-3)' }}>
                        {row.type}
                      </span>
                    </td>
                    <td className="px-3.5 py-2">
                      <Breadth sessions={row.sessions} max={max} />
                    </td>
                    <td className="readout hidden px-3.5 py-2 text-[12px] text-paper-3 md:table-cell">
                      {new Date(row.last_seen).toLocaleDateString()}
                    </td>
                    <td className="px-3.5 py-2 text-right">
                      <button
                        type="button"
                        onClick={() => copy(row.value)}
                        aria-label={`Copy ${row.value}`}
                        className="rounded-[3px] p-1 text-paper-3 opacity-0 transition-opacity hover:text-paper focus-visible:opacity-100 group-hover:opacity-100"
                      >
                        <Copy className="h-3.5 w-3.5" strokeWidth={2} />
                      </button>
                      {copied === row.value && (
                        <span className="ml-1 text-[11px] text-paper-3">copied</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {pages > 1 && (
          <div className="flex items-center justify-between border-t border-line px-3 py-2">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
              className="control"
            >
              Previous
            </button>
            <span className="readout text-[12px] text-paper-3">{page} / {pages}</span>
            <button
              type="button"
              disabled={page >= pages}
              onClick={() => setPage((p) => p + 1)}
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
