import { useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Search, RefreshCw, ShieldAlert } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { useDebounced } from '../hooks/useDebounced'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import { LoadingRegion } from '../components/Loading'
import PayloadDetail from '../components/PayloadDetail'

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
            <span className="readout truncate text-[12px] text-paper">
              {sample.summary || sample.file_type || `${kind} sample`}
            </span>
          </span>
          <span className="mt-1 flex flex-wrap items-center gap-1.5 text-[11px] text-paper-3">
            <span className="tag" style={{ color: 'var(--color-paper-3)' }}>{kind}</span>
            {sample.family && (
              <span className="tag" style={{ color: 'var(--color-s3)' }}>{sample.family}</span>
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
          <span className="readout mt-1 block truncate text-[10px] text-paper-3" title={sample.sha256}>
            {sample.sha256}
          </span>
        </span>
      </button>
    </li>
  )
}

export default function Payloads() {
  const { hasRole } = useAuth()
  const [samples, setSamples] = useState([])
  const [total, setTotal] = useState(0)
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [searchParams, setSearchParams] = useSearchParams()
  const [reload, setReload] = useState(0)
  const [narrow, setNarrow] = useState(() => window.matchMedia('(max-width: 1023px)').matches)

  const kind = searchParams.get('kind') || ''
  const status = searchParams.get('status') || ''
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

  const queryKey = useMemo(
    () => JSON.stringify({ kind, status, search: debouncedSearch, page }),
    [kind, status, debouncedSearch, page],
  )

  useEffect(() => {
    const controller = new AbortController()
    const load = async () => {
      setLoading(true)
      try {
        const { kind, status, search, page } = JSON.parse(queryKey)
        const params = { page, page_size: PAGE_SIZE }
        if (kind) params.file_kind = kind
        if (status) params.status = status
        if (search) params.search = search
        const data = await api.payloads.list(params, { signal: controller.signal })
        if (controller.signal.aborted) return
        setSamples(data.payloads || [])
        setTotal(data.total || 0)
        setError(null)
      } catch (err) {
        if (controller.signal.aborted) return
        setError(err.message)
        setSamples([])
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }
    const timer = setTimeout(load, 0)
    return () => { controller.abort(); clearTimeout(timer) }
  }, [queryKey, reload])

  useEffect(() => {
    api.payloads.stats().then(setStats).catch(() => setStats(null))
  }, [reload])

  // The detail is its own request: a sample carries its full report and the
  // sessions it appeared in, which the list deliberately does not.
  useEffect(() => {
    const controller = new AbortController()
    const load = async () => {
      if (!requested) {
        setDetail(null)
        return
      }
      setDetailLoading(true)
      try {
        const data = await api.payloads.get(requested, { signal: controller.signal })
        if (!controller.signal.aborted) setDetail(data)
      } catch {
        if (!controller.signal.aborted) setDetail(null)
      } finally {
        if (!controller.signal.aborted) setDetailLoading(false)
      }
    }
    const timer = setTimeout(load, 0)
    return () => { controller.abort(); clearTimeout(timer) }
  }, [requested])

  useEffect(() => {
    const mql = window.matchMedia('(max-width: 1023px)')
    const onChange = () => setNarrow(mql.matches)
    mql.addEventListener('change', onChange)
    return () => mql.removeEventListener('change', onChange)
  }, [])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const refresh = () => setReload((v) => v + 1)

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
        <button className="control" onClick={refresh} disabled={loading}>
          <RefreshCw className="h-3.5 w-3.5" />Refresh
        </button>
      </header>

      {stats && (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <StatTile label="Unique samples" value={stats.total.toLocaleString()} />
          <StatTile label="Awaiting analysis" value={stats.pending_analysis.toLocaleString()} />
          <StatTile label="Executables" value={((stats.by_kind.elf || 0) + (stats.by_kind.pe || 0)).toLocaleString()} />
          <StatTile label="Scripts" value={(stats.by_kind.script || 0).toLocaleString()} />
        </div>
      )}

      {error && <ErrorBanner message={error} onRetry={refresh} />}

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
        <span className="readout ml-auto text-xs text-paper-3">
          {loading ? 'Searching…' : `${total.toLocaleString()} sample${total === 1 ? '' : 's'}`}
        </span>
      </div>

      <div className="grid min-h-[24rem] flex-1 gap-3 lg:min-h-0 lg:grid-cols-[minmax(0,1fr)_minmax(0,32rem)]">
        <section className="panel flex min-h-0 flex-col overflow-hidden">
          {loading ? (
            <LoadingRegion label="Loading payloads" />
          ) : samples.length === 0 ? (
            <EmptyState
              title="No payloads"
              hint="Files uploaded through SSH, SFTP, SCP, FTP or HTTP are captured and analysed here."
            />
          ) : (
            <ul className="min-h-0 flex-1 divide-y divide-line overflow-y-auto">
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
          {totalPages > 1 && (
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
        <aside className="panel min-h-0 overflow-hidden">
          {detailLoading && !detail ? (
            <LoadingRegion label="Loading analysis" />
          ) : detail ? (
            <PayloadDetail detail={detail} canDownload={hasRole('admin')} />
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

      {/* Mobile detail: a sheet, since there is no room beside the list. */}
      {narrow && requested && detail && (
        <div className="fixed inset-0 z-50 flex items-end bg-ink-0/85 lg:hidden" onClick={() => setParam({ sha: '' }, true)} role="presentation">
          <div className="panel max-h-[88vh] w-full overflow-y-auto rounded-b-none" onClick={(e) => e.stopPropagation()}>
            <PayloadDetail detail={detail} canDownload={hasRole('admin')} onClose={() => setParam({ sha: '' }, true)} />
          </div>
        </div>
      )}
    </div>
  )
}
