import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Search, RefreshCw, ShieldAlert } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { useDebounced } from '../hooks/useDebounced'
import { usePolledResource } from '../hooks/usePolledResource'
import Dialog from '../components/Dialog'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import { LoadFailure, StaleNotice } from '../components/LoadState'
import { LoadingRegion } from '../components/Loading'
import PayloadDetail from '../components/PayloadDetail'
import { cleanLine } from '../lib/text'

/*
 * Payloads.
 *
 * The files attackers uploaded, reverse-engineered. A sample is unique by
 * hash — the same loader dropped by forty addresses is one row seen forty
 * times — so this is the aggregate view, and the detail panel carries the
 * report: what the file is, what it can do, who it talks to, and every
 * session it arrived in.
 */

const PAGE_SIZE = 30

const KINDS = [
  { id: '', label: 'All types' },
  { id: 'elf', label: 'ELF' },
  { id: 'pe', label: 'Windows PE' },
  { id: 'script', label: 'Scripts' },
  { id: 'archive', label: 'Archives' },
  { id: 'text', label: 'Text' },
  { id: 'data', label: 'Binary data' },
]

const STATUSES = [
  { id: '', label: 'Any status' },
  { id: 'complete', label: 'Analysed' },
  { id: 'pending', label: 'Pending' },
  { id: 'failed', label: 'Failed' },
  { id: 'metadata_only', label: 'Hash only' },
]

/* The orders the list API offers. */
const SORTS = [
  { id: '', label: 'Last seen' },
  { id: 'first_seen', label: 'First seen' },
  { id: 'size', label: 'Largest' },
]

const KIND_LABEL = {
  elf: 'ELF', pe: 'PE', dos: 'PE', script: 'Script', archive: 'Archive',
  text: 'Text', data: 'Binary', image: 'Image', document: 'Document',
  ssh_key: 'Key', java: 'Java', macho: 'Mach-O', empty: 'Empty',
}

function StatTile({ label, value }) {
  return (
    <div className="panel px-3.5 py-2.5">
      <p className="eyebrow">{label}</p>
      <p className="readout mt-1 text-[19px] tabular-nums text-paper">{value}</p>
    </div>
  )
}

function PayloadRow({ sample, selected, onSelect }) {
  const kind = KIND_LABEL[sample.file_kind] || 'Unknown'
  const pending = sample.analysis_status !== 'complete'
  return (
    <li>
      <button
        type="button"
        onClick={() => onSelect(sample)}
        aria-current={selected ? 'true' : undefined}
        className={`flex w-full items-start gap-3 border-l-2 px-3 py-2 text-left transition-colors ${
          selected ? 'border-l-paper bg-ink-2' : 'border-l-transparent hover:bg-ink-2/60'
        }`}
      >
        <span className="min-w-0 flex-1">
          <span className="flex items-baseline gap-2">
            {/* The summary and family are built from the file's own contents,
                which the attacker chose. */}
            <span className="readout truncate text-[12px] text-paper">
              {cleanLine(sample.summary || sample.file_type) || `${kind} sample`}
            </span>
          </span>
          <span className="mt-1 flex flex-wrap items-center gap-1.5 text-[12px] text-paper-3">
            <span className="tag" style={{ color: 'var(--color-paper-3)' }}>{kind}</span>
            {sample.family && (
              <span className="tag" style={{ color: 'var(--color-s3)' }}>{cleanLine(sample.family)}</span>
            )}
            {pending && (
              <span className="tag" style={{ color: 'var(--color-paper-3)' }}>
                {sample.analysis_status === 'failed' ? 'analysis failed'
                  : sample.analysis_status === 'metadata_only' ? 'hash only' : 'pending'}
              </span>
            )}
            <span aria-hidden="true">·</span>
            <span className="readout">{sample.sessions_seen} session{sample.sessions_seen === 1 ? '' : 's'}</span>
            {sample.indicator_count > 0 && (
              <>
                <span aria-hidden="true">·</span>
                <span className="readout">{sample.indicator_count} indicator{sample.indicator_count === 1 ? '' : 's'}</span>
              </>
            )}
          </span>
          <span className="readout mt-1 block truncate text-[12px] text-paper-3" title={sample.sha256}>
            {sample.sha256}
          </span>
        </span>
      </button>
    </li>
  )
}

export default function Payloads() {
  const { hasRole } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const [narrow, setNarrow] = useState(() => window.matchMedia('(max-width: 1023px)').matches)

  const kind = searchParams.get('kind') || ''
  const status = searchParams.get('status') || ''
  const sort = searchParams.get('sort') || ''
  const search = searchParams.get('q') || ''
  const requested = searchParams.get('sha') || null
  const page = Math.max(1, Math.floor(Number(searchParams.get('page'))) || 1)
  const debouncedSearch = useDebounced(search)

  const setParam = useCallback((changes, replace = false) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current)
      Object.entries(changes).forEach(([key, value]) => {
        if (value === '' || value == null) next.delete(key)
        else next.set(key, value)
      })
      return next
    }, { replace })
  }, [setSearchParams])

  const list = usePolledResource(
    async ({ signal }) => {
      const params = { page, page_size: PAGE_SIZE }
      if (kind) params.file_kind = kind
      if (status) params.status = status
      if (sort) params.sort = sort
      if (debouncedSearch) params.search = debouncedSearch
      const data = await api.payloads.list(params, { signal })
      return { samples: data.payloads || [], total: data.total || 0 }
    },
    { key: JSON.stringify({ kind, status, sort, search: debouncedSearch, page }) },
  )
  const samples = list.data?.samples ?? []
  const total = list.data?.total ?? 0

  const stats = usePolledResource(({ signal }) => api.payloads.stats({ signal }), { key: 'payload-stats' })

  // The detail is its own request: a sample carries its full report and the
  // sessions it appeared in, which the list deliberately does not.
  const detail = usePolledResource(
    ({ signal }) => api.payloads.get(requested, { signal }),
    { key: `payload:${requested}`, enabled: Boolean(requested) },
  )

  useEffect(() => {
    const mql = window.matchMedia('(max-width: 1023px)')
    const onChange = () => setNarrow(mql.matches)
    mql.addEventListener('change', onChange)
    return () => mql.removeEventListener('change', onChange)
  }, [])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const refresh = () => {
    list.reload()
    stats.reload()
    if (requested) detail.reload()
  }
  const closeDetail = () => setParam({ sha: '' }, true)
  const filtered = Boolean(kind || status || search)

  return (
    <div className="mx-auto flex min-h-full max-w-[1600px] lg:h-full flex-col gap-3">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="eyebrow mb-1">Captured payloads</p>
          <h1 className="text-2xl">Payloads</h1>
          <p className="mt-1 text-sm text-paper-2">
            Files attackers uploaded, reverse-engineered — statically, without ever running them.
          </p>
        </div>
        <button className="control" onClick={refresh} disabled={list.loading || list.refreshing}>
          <RefreshCw className={`h-3.5 w-3.5 ${list.refreshing ? 'animate-spin' : ''}`} />Refresh
        </button>
      </header>

      {stats.data ? (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <StatTile label="Unique samples" value={(stats.data.total ?? 0).toLocaleString()} />
          <StatTile label="Awaiting analysis" value={(stats.data.pending_analysis ?? 0).toLocaleString()} />
          <StatTile label="Executables" value={((stats.data.by_kind?.elf || 0) + (stats.data.by_kind?.pe || 0)).toLocaleString()} />
          <StatTile label="Scripts" value={(stats.data.by_kind?.script || 0).toLocaleString()} />
        </div>
      ) : stats.failed ? (
        <p className="text-[13px] text-paper-3" role="alert">
          The totals could not be loaded ({stats.error}). The list below is unaffected.
        </p>
      ) : null}

      {list.stale && <StaleNotice what="The payload list" error={list.error} loadedAt={list.loadedAt} onRetry={list.reload} />}
      {requested && detail.failed && (
        // "Try again" used to set the address to the value it already had,
        // which changes nothing and so reloaded nothing.
        <ErrorBanner
          title="Could not open the linked sample"
          message={detail.error}
          onRetry={detail.reload}
        />
      )}

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-0">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-paper-3" strokeWidth={1.75} />
          <input
            type="search"
            aria-label="Search payloads by hash, family or type"
            placeholder="Hash, family or type"
            value={search}
            onChange={(e) => setParam({ q: e.target.value, page: '' }, true)}
            className="field w-60 pl-8"
          />
        </div>
        <select className="control" value={kind} aria-label="File type"
          onChange={(e) => setParam({ kind: e.target.value, page: '' })}>
          {KINDS.map((k) => <option key={k.id} value={k.id}>{k.label}</option>)}
        </select>
        <select className="control" value={status} aria-label="Analysis status"
          onChange={(e) => setParam({ status: e.target.value, page: '' })}>
          {STATUSES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
        </select>
        <label className="flex items-center gap-1.5">
          <span className="text-[12px] text-paper-3">Order</span>
          <select className="control" value={sort} aria-label="Order"
            onChange={(e) => setParam({ sort: e.target.value, page: '' })}>
            {SORTS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
        </label>
        <span className="readout ml-auto text-xs text-paper-3">
          {list.loading
            ? 'Searching…'
            : list.failed
              ? 'Not loaded'
              : `${total.toLocaleString()} sample${total === 1 ? '' : 's'}`}
        </span>
      </div>

      <div className="grid min-h-[24rem] flex-1 gap-3 lg:min-h-0 lg:grid-cols-[minmax(0,1fr)_minmax(0,32rem)]">
        <section className="panel flex min-h-0 flex-col overflow-hidden" aria-label="Samples">
          {list.loading ? (
            <LoadingRegion label="Loading payloads" />
          ) : list.failed ? (
            <LoadFailure what="payloads" error={list.error} onRetry={list.reload} />
          ) : samples.length === 0 ? (
            <EmptyState
              title={filtered ? 'No payloads match' : 'No payloads yet'}
              hint={filtered
                ? 'Try another type, status or search.'
                : 'Files uploaded through SSH, SFTP, SCP, FTP or HTTP are captured and analysed here.'}
            />
          ) : (
            <ul className={`min-h-0 flex-1 divide-y divide-line overflow-y-auto ${list.stale ? 'is-stale' : ''}`}>
              {samples.map((sample) => (
                <PayloadRow
                  key={sample.sha256}
                  sample={sample}
                  selected={requested === sample.sha256}
                  onSelect={(s) => setParam({ sha: s.sha256 }, true)}
                />
              ))}
            </ul>
          )}
          {totalPages > 1 && !list.loading && !list.failed && (
            <div className="flex items-center justify-between border-t border-line px-3 py-2">
              <button className="control" disabled={page <= 1}
                onClick={() => setParam({ page: page - 1 })}>Previous</button>
              <span className="readout text-[12px] text-paper-3">{page} / {totalPages}</span>
              <button className="control" disabled={page >= totalPages}
                onClick={() => setParam({ page: page + 1 })}>Next</button>
            </div>
          )}
        </section>

        {!narrow && (
          <aside className="panel min-h-0 overflow-hidden" aria-label="Sample analysis">
            {requested && detail.loading ? (
              <LoadingRegion label="Loading analysis" />
            ) : detail.data ? (
              <PayloadDetail detail={detail.data} canDownload={hasRole('admin')} />
            ) : (
              <div className="flex h-full items-center justify-center px-6 py-16 text-center">
                <p className="max-w-[16rem] text-[13px] leading-relaxed text-paper-3">
                  <ShieldAlert className="mx-auto mb-3 h-6 w-6 text-paper-3" strokeWidth={1.5} />
                  Select a sample to see what it is, what it can do, and every session it arrived in.
                </p>
              </div>
            )}
          </aside>
        )}
      </div>

      {/* Narrow screens: a modal sheet, since there is no room beside the
          list. A real dialog, so focus stays inside it and Escape closes it;
          it used to be a plain div over the page. */}
      {narrow && requested && detail.data && (
        <Dialog label="Sample analysis" onClose={closeDetail}>
          <PayloadDetail detail={detail.data} canDownload={hasRole('admin')} onClose={closeDetail} />
        </Dialog>
      )}
    </div>
  )
}
