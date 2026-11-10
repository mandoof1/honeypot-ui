import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Download, RefreshCw, Search } from 'lucide-react'
import { api } from '../services/api'
import { useDebounced } from '../hooks/useDebounced'
import { usePolledResource } from '../hooks/usePolledResource'
import CopyButton from '../components/CopyButton'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import { LoadFailure, StaleNotice } from '../components/LoadState'
import { LoadingRegion } from '../components/Loading'
import PageHeader from '../components/PageHeader'
import SavedSearches, { ShareLink } from '../components/SavedSearches'
import Timestamp from '../components/Timestamp'
import { saveBlob } from '../lib/download'
import {
  INDICATOR_TYPES, blocklistOffer, indicatorLinks, indicatorTypeLabel, isReferencedAddress,
} from '../lib/indicators'
import { cleanLine } from '../lib/text'

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
 *
 * The filters live in the URL, so a view can be saved, shared and returned to.
 */

const PAGE_SIZE = 50
const MIN_SESSION_CHOICES = [1, 2, 5, 10]

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

function IndicatorRow({ row, max }) {
  const links = indicatorLinks(row)
  const value = cleanLine(String(row.value ?? ''))

  return (
    <tr className="group border-b border-line last:border-b-0 hover:bg-ink-2">
      <td className="max-w-0 px-3.5 py-2">
        {links.profile ? (
          <Link
            to={links.profile}
            className="readout block truncate text-[12px] text-paper hover:underline"
            title="Everything this address has done"
          >
            {value}
          </Link>
        ) : (
          <span className="readout block truncate text-[12px] text-paper" title={value}>
            {value}
          </span>
        )}
        {isReferencedAddress(row) && (
          <span className="mt-0.5 block text-[12px] text-paper-3">
            Named in a command; it did not connect to the honeypot.
          </span>
        )}
      </td>
      <td className="hidden px-3.5 py-2 sm:table-cell">
        <span className="tag" style={{ color: 'var(--color-paper-3)' }}>
          {indicatorTypeLabel(row.type)}
        </span>
      </td>
      <td className="px-3.5 py-2">
        <Breadth sessions={row.sessions} max={max} />
      </td>
      <td className="readout hidden px-3.5 py-2 text-[12px] text-paper-3 md:table-cell">
        <Timestamp value={row.last_seen} style="date" />
      </td>
      <td className="whitespace-nowrap px-3.5 py-2 text-right">
        {links.sessions && (
          <Link
            to={links.sessions}
            className="mr-2 text-[12px] text-paper-3 transition-colors hover:text-paper"
            title="Search sessions for this value: source address, session id and command text"
            aria-label={`Sessions mentioning ${value}`}
          >
            sessions
          </Link>
        )}
        {links.payload && (
          <Link
            to={links.payload}
            className="mr-2 text-[12px] text-paper-3 transition-colors hover:text-paper"
            aria-label={`Captured sample ${value}`}
          >
            sample
          </Link>
        )}
        <CopyButton value={row.value} label={`Copy ${value}`} />
      </td>
    </tr>
  )
}

export default function Indicators() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [feedError, setFeedError] = useState(null)
  const [feedBusy, setFeedBusy] = useState(false)

  const type = searchParams.get('type') || ''
  const search = searchParams.get('q') || ''
  // One by default. Two is right for a blocklist, but as the default view it
  // made the page open empty on any deployment that had not yet seen a value
  // twice, which read as "no indicators" when there were plenty.
  const minSessions = Math.max(1, Math.floor(Number(searchParams.get('min'))) || 1)
  const page = Math.max(1, Math.floor(Number(searchParams.get('page'))) || 1)
  const debouncedSearch = useDebounced(search)

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

  const key = JSON.stringify({ type, search: debouncedSearch, minSessions, page })
  const list = usePolledResource(
    async ({ signal }) => {
      const params = { page, page_size: PAGE_SIZE, min_sessions: minSessions }
      if (type) params.ioc_type = type
      if (debouncedSearch) params.search = debouncedSearch
      const data = await api.iocs.list(params, { signal })
      return { rows: data.indicators || [], total: data.total || 0 }
    },
    { key },
  )
  const rows = list.data?.rows ?? []
  const total = list.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const max = rows.length ? Math.max(...rows.map((r) => r.sessions)) : 1
  const offer = blocklistOffer(type, minSessions)

  const downloadFeed = async () => {
    setFeedBusy(true)
    setFeedError(null)
    try {
      const { blob, filename } = await api.iocs.feed({
        ioc_type: offer.iocType,
        min_sessions: offer.minSessions,
      })
      saveBlob(blob, filename)
    } catch (err) {
      setFeedError(err.message || 'The blocklist could not be downloaded.')
    } finally {
      setFeedBusy(false)
    }
  }

  const filtered = Boolean(type || search || minSessions > 1)

  return (
    <div className="mx-auto flex h-full max-w-[1100px] flex-col gap-3">
      <PageHeader
        eyebrow="Threat intelligence"
        title="Indicators"
        description="Addresses, hosts, URLs, tools and hashes seen across sessions, ordered by how many sessions saw each."
      >
        <SavedSearches scope="indicators" />
        <ShareLink />
        <button type="button" className="control" onClick={list.reload} disabled={list.loading || list.refreshing}>
          <RefreshCw className={`h-3.5 w-3.5 ${list.refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
          Refresh
        </button>
      </PageHeader>

      {feedError && <ErrorBanner title="The blocklist was not downloaded" message={feedError} />}
      {list.stale && <StaleNotice what="The indicator list" error={list.error} loadedAt={list.loadedAt} onRetry={list.reload} />}

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
              onChange={(e) => setParams({ q: e.target.value, page: '' }, true)}
              className="field w-56 pl-8"
            />
          </span>
        </label>

        <label className="flex flex-col gap-1">
          <span className="eyebrow">Type</span>
          <select
            value={type}
            onChange={(e) => setParams({ type: e.target.value, page: '' })}
            className="control"
          >
            {INDICATOR_TYPES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="eyebrow">Seen in at least</span>
          <select
            value={minSessions}
            onChange={(e) => setParams({ min: Number(e.target.value) > 1 ? e.target.value : '', page: '' })}
            className="control"
          >
            {[...new Set([...MIN_SESSION_CHOICES, minSessions])].sort((a, b) => a - b).map((n) => (
              <option key={n} value={n}>{n} session{n === 1 ? '' : 's'}</option>
            ))}
          </select>
        </label>

        <div className="ml-auto flex max-w-sm flex-col items-end gap-1">
          {offer.iocType ? (
            <>
              <button
                type="button"
                onClick={downloadFeed}
                disabled={feedBusy}
                className="control gap-1.5"
                title="One value per line — the shape ipset, pf, Suricata datasets and Splunk lookups read"
              >
                <Download className="h-3.5 w-3.5" strokeWidth={2} />
                {feedBusy ? 'Preparing…' : offer.label}
              </button>
              <p className="text-right text-[12px] leading-snug text-paper-3" data-testid="blocklist-note">
                {offer.iocType === 'ip'
                  ? 'Only addresses that themselves connected to a decoy'
                  : 'Only values'}
                {' '}seen in at least {offer.minSessions} sessions. One sighting is never enough to block on.
              </p>
            </>
          ) : (
            <p className="text-right text-[12px] leading-snug text-paper-3" data-testid="blocklist-note">
              No blocklist for this type. {offer.reason}
            </p>
          )}
        </div>
      </div>

      <section className="panel flex min-h-0 flex-1 flex-col overflow-hidden">
        {list.loading ? (
          <LoadingRegion label="Loading indicators" />
        ) : list.failed ? (
          <LoadFailure what="indicators" error={list.error} onRetry={list.reload} />
        ) : rows.length === 0 ? (
          <EmptyState
            title={filtered ? 'No indicators match' : 'No indicators yet'}
            hint={
              minSessions > 1
                ? `Nothing has been seen in ${minSessions} or more sessions. Lower "Seen in at least" to see values seen less often.`
                : filtered
                  ? 'Try another type or a shorter search.'
                  : 'Indicators are extracted from every ingested session.'
            }
            action={minSessions > 1 ? (
              <button type="button" className="control" onClick={() => setParams({ min: '', page: '' })}>
                Show values seen once
              </button>
            ) : undefined}
          />
        ) : (
          <div className={`min-h-0 flex-1 overflow-y-auto ${list.stale ? 'is-stale' : ''}`}>
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
                    <span className="sr-only">Links and copy</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <IndicatorRow key={`${row.type}:${row.value}`} row={row} max={max} />
                ))}
              </tbody>
            </table>
          </div>
        )}

        {pages > 1 && !list.loading && !list.failed && (
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
              {Math.min(page, pages)} / {pages} · {total.toLocaleString()} indicators
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
