import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Download, ExternalLink, RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { usePreferences } from '../context/usePreferences'
import { usePolledResource } from '../hooks/usePolledResource'
import Dialog from '../components/Dialog'
import EmptyState from '../components/EmptyState'
import ErrorBanner from '../components/ErrorBanner'
import { LoadFailure, StaleNotice } from '../components/LoadState'
import { LoadingRegion } from '../components/Loading'
import PageHeader from '../components/PageHeader'
import Timestamp from '../components/Timestamp'
import { heatStep, normaliseMatrix, techniqueUrl } from '../lib/attack'
import { saveBlob } from '../lib/download'
import { CATEGORY_LABEL } from '../lib/severity'
import { cleanLine } from '../lib/text'
import { fromInputValue, toInputValue } from '../lib/time'

/*
 * ATT&CK matrix.
 *
 * What the captured sessions did, laid out the way ATT&CK lays it out:
 * tactics as columns in kill-chain order, the techniques observed under each,
 * shaded by how many sessions showed them. The count is printed in every
 * cell, so the shading is a second reading, never the only one.
 *
 * The matrix takes the same filters as the session list. The session list
 * itself cannot be filtered by technique, so opening a cell looks through
 * the newest matching sessions for the ones that carry it and says how far
 * it looked.
 */

const REFRESH_MS = 60000
const FILTER_KEYS = ['protocol', 'exclude_scanners', 'date_from', 'date_to']
const SCAN_PAGE_SIZE = 100
const SCAN_MAX_PAGES = 5

/** The sessions that show one technique, found by reading the newest matching sessions. */
function TechniqueSessions({ technique, tactic, filters, onClose }) {
  const [state, setState] = useState({ rows: [], scanned: 0, total: null, done: false, error: null })

  useEffect(() => {
    const controller = new AbortController()
    const scan = async () => {
      const found = []
      let scanned = 0
      let total = null
      try {
        for (let page = 1; page <= SCAN_MAX_PAGES; page += 1) {
          const data = await api.sessions.list(
            { ...filters, page, page_size: SCAN_PAGE_SIZE },
            { signal: controller.signal },
          )
          const batch = data.sessions || []
          total = data.total ?? total
          scanned += batch.length
          for (const session of batch) {
            const shows = (session.mitre_techniques || []).some(
              (item) => item.id === technique.id && !item.unconfirmed,
            )
            if (shows) found.push(session)
          }
          const exhausted = batch.length < SCAN_PAGE_SIZE || scanned >= (total ?? 0)
          const enough = found.length >= technique.count
          setState({ rows: [...found], scanned, total, done: exhausted || enough || page === SCAN_MAX_PAGES, error: null })
          if (exhausted || enough) return
        }
      } catch (err) {
        if (err?.name === 'AbortError') return
        setState({ rows: [...found], scanned, total, done: true, error: err.message || 'The sessions could not be read.' })
      }
    }
    const timer = setTimeout(scan, 0)
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [technique.id, technique.count, filters])

  const query = new URLSearchParams(filters).toString()
  const url = techniqueUrl(technique)
  const incomplete = state.done && !state.error && state.rows.length < technique.count

  return (
    <Dialog label={`Sessions showing ${technique.id}`} onClose={onClose} width="max-w-2xl">
      <div className="p-5" data-testid="technique-sessions">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="eyebrow">{cleanLine(tactic)}</p>
            <h2 className="mt-1 text-[17px] font-semibold text-paper">
              <span className="readout">{cleanLine(technique.id)}</span> {cleanLine(technique.name)}
            </h2>
          </div>
          <button type="button" className="control shrink-0" onClick={onClose}>Close</button>
        </div>
        <p className="mt-2 text-[13px] leading-relaxed text-paper-2">
          The matrix counts {technique.count.toLocaleString()} session{technique.count === 1 ? '' : 's'} showing
          this technique.
          {url && (
            <>
              {' '}
              <a href={url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-paper hover:underline">
                Read about it on attack.mitre.org
                <ExternalLink className="h-3 w-3" strokeWidth={2} aria-hidden="true" />
              </a>
            </>
          )}
        </p>

        {state.error && <p role="alert" className="mt-3 text-[13px] text-s4">{state.error}</p>}

        <p className="mt-3 text-[12px] text-paper-3" aria-live="polite">
          {!state.done
            ? `Looking through the newest matching sessions… ${state.scanned.toLocaleString()} read so far.`
            : `Found ${state.rows.length.toLocaleString()} in the newest ${state.scanned.toLocaleString()}`
              + `${state.total !== null ? ` of ${state.total.toLocaleString()}` : ''} matching sessions.`}
          {incomplete && ' The rest are older than that; narrow the dates above the matrix to reach them.'}
        </p>

        {state.rows.length > 0 && (
          <ul className="mt-2 max-h-80 divide-y divide-line overflow-y-auto rounded-[3px] border border-line">
            {state.rows.map((session) => (
              <li key={session.id}>
                <Link
                  to={`/sessions?${query ? `${query}&` : ''}session=${session.id}`}
                  className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-3 py-2 transition-colors hover:bg-ink-2"
                >
                  <span className="readout text-[13px] text-paper">{cleanLine(session.attacker_ip)}</span>
                  <span className="readout text-[12px] uppercase text-paper-3">{session.protocol || '—'}</span>
                  <span className="text-[12px] text-paper-2">
                    {CATEGORY_LABEL[session.attack_category] || CATEGORY_LABEL.unknown}
                  </span>
                  <Timestamp value={session.started_at} style="minute" className="readout ml-auto text-[12px] text-paper-3" />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Dialog>
  )
}

function Legend({ max }) {
  const steps = [1, 2, 3, 4]
  return (
    <div className="flex flex-wrap items-center gap-2 text-[12px] text-paper-3" aria-hidden="true">
      <span>Sessions showing the technique:</span>
      <span className="readout">1</span>
      <span className="inline-flex overflow-hidden rounded-[2px] border border-line">
        {steps.map((step) => <span key={step} className={`heat-${step} h-3 w-6`} />)}
      </span>
      <span className="readout">{max.toLocaleString()}</span>
    </div>
  )
}

export default function AttackMatrix() {
  const { hasRole } = useAuth()
  const { zone, zoneLabel } = usePreferences()
  const [searchParams, setSearchParams] = useSearchParams()
  const [open, setOpen] = useState(null)
  const [layerBusy, setLayerBusy] = useState(false)
  const [layerError, setLayerError] = useState(null)

  const filterKey = JSON.stringify(Object.fromEntries(
    FILTER_KEYS.map((key) => [key, searchParams.get(key) || '']).filter(([, value]) => value),
  ))
  // One object per distinct set of filters, so effects keyed on it do not
  // re-run on every render.
  const filters = useMemo(() => JSON.parse(filterKey), [filterKey])

  const setFilter = (key, value) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current)
      if (value) next.set(key, value)
      else next.delete(key)
      return next
    })
  }

  const resource = usePolledResource(
    ({ signal }) => api.attack.matrix(filters, { signal }),
    { key: `matrix:${filterKey}`, intervalMs: REFRESH_MS },
  )
  const matrix = resource.data ? normaliseMatrix(resource.data) : null

  const downloadLayer = async () => {
    setLayerBusy(true)
    setLayerError(null)
    try {
      const { blob, filename } = await api.attack.navigatorLayer(filters)
      saveBlob(blob, filename)
    } catch (err) {
      setLayerError(err.message || 'The layer file could not be downloaded.')
    } finally {
      setLayerBusy(false)
    }
  }

  const sessionQuery = new URLSearchParams(filters).toString()

  return (
    <div className="mx-auto flex max-w-[1800px] flex-col gap-3">
      <PageHeader
        eyebrow="MITRE ATT&CK"
        title="ATT&CK matrix"
        description="The techniques the captured sessions showed, by tactic in kill-chain order. A technique counts once per session; one the decision model could not confirm, or whose id is not in the ATT&CK catalog, is not counted."
      >
        {hasRole('analyst') ? (
          <button type="button" className="control" onClick={downloadLayer} disabled={layerBusy || !matrix}>
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            {layerBusy ? 'Preparing…' : 'Download Navigator layer'}
          </button>
        ) : (
          <span className="text-[12px] text-paper-3">Downloading the Navigator layer needs an analyst account.</span>
        )}
        <button type="button" className="control" onClick={resource.reload} disabled={resource.loading || resource.refreshing}>
          <RefreshCw className={`h-3.5 w-3.5 ${resource.refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
          Refresh
        </button>
      </PageHeader>

      {layerError && <ErrorBanner title="The Navigator layer was not downloaded" message={layerError} />}
      {resource.stale && <StaleNotice what="The matrix" error={resource.error} loadedAt={resource.loadedAt} onRetry={resource.reload} />}

      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Protocol</span>
          <select className="control" value={filters.protocol || ''} onChange={(e) => setFilter('protocol', e.target.value)}>
            <option value="">All protocols</option>
            {['ssh', 'ftp', 'telnet', 'http', 'https'].map((value) => <option key={value} value={value}>{value.toUpperCase()}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Research scanners</span>
          <select className="control" value={filters.exclude_scanners || ''} onChange={(e) => setFilter('exclude_scanners', e.target.value)}>
            <option value="">Include</option>
            <option value="true">Exclude</option>
          </select>
        </label>
        {['date_from', 'date_to'].map((key) => (
          <label key={key} className="flex flex-col gap-1">
            <span className="eyebrow">{key === 'date_from' ? 'From' : 'Until'} ({zoneLabel()})</span>
            <input
              type="datetime-local"
              className="field"
              value={toInputValue(filters[key], zone)}
              onChange={(e) => setFilter(key, fromInputValue(e.target.value, zone))}
            />
          </label>
        ))}
        {matrix && (
          <p className="ml-auto pb-2 text-[12px] text-paper-3" data-testid="matrix-scope">
            {matrix.sessions !== null && (
              <>
                <Link to={`/sessions${sessionQuery ? `?${sessionQuery}` : ''}`} className="text-paper-2 hover:text-paper hover:underline">
                  {matrix.sessions.toLocaleString()} session{matrix.sessions === 1 ? '' : 's'}
                </Link>
                {' '}in scope ·{' '}
              </>
            )}
            {matrix.techniqueCount} technique{matrix.techniqueCount === 1 ? '' : 's'} observed
            {matrix.version && <> · ATT&amp;CK {cleanLine(matrix.version)}</>}
          </p>
        )}
      </div>

      {resource.loading ? (
        <section className="panel"><LoadingRegion label="Loading the matrix" /></section>
      ) : resource.failed ? (
        <section className="panel"><LoadFailure what="the ATT&CK matrix" error={resource.error} onRetry={resource.reload} /></section>
      ) : matrix.techniqueCount === 0 ? (
        <section className="panel">
          <EmptyState
            title="No technique observed"
            hint={Object.keys(filters).length
              ? 'No session matching these filters shows a confirmed technique. Try widening them.'
              : 'Techniques appear here once a session shows one the ATT&CK catalog knows.'}
          />
        </section>
      ) : (
        <>
          <Legend max={matrix.max} />
          <section
            className={`panel overflow-x-auto ${resource.stale ? 'is-stale' : ''}`}
            aria-label="ATT&CK matrix"
            data-testid="attack-matrix"
          >
            <ol className="flex min-w-max divide-x divide-line">
              {matrix.columns.map((column) => (
                <li key={column.id} className="w-44 shrink-0" data-testid="matrix-tactic">
                  <div className="border-b border-line px-2.5 py-2">
                    <h2 className="text-[13px] font-semibold leading-tight text-paper">{cleanLine(column.name)}</h2>
                    <p className="readout mt-0.5 text-[12px] text-paper-3">
                      {cleanLine(column.id)} · {column.techniques.length}
                    </p>
                  </div>
                  {column.techniques.length === 0 ? (
                    <p className="px-2.5 py-2 text-[12px] text-paper-3">none observed</p>
                  ) : (
                    <ul className="space-y-[2px] p-[2px]">
                      {column.techniques.map((technique) => (
                        <li key={technique.id}>
                          <button
                            type="button"
                            onClick={() => setOpen({ technique, tactic: column.name })}
                            className={`heat-${heatStep(technique.count, matrix.max)} flex w-full items-start gap-2 rounded-[2px] px-2 py-1.5 text-left transition-shadow hover:ring-1 hover:ring-paper`}
                            title={`${technique.id} ${technique.name}: ${technique.count} session${technique.count === 1 ? '' : 's'}. Open to list them.`}
                          >
                            <span className="min-w-0 flex-1">
                              <span className="readout block text-[12px]">{cleanLine(technique.id)}</span>
                              <span className="block text-[12px] leading-tight">{cleanLine(technique.name)}</span>
                            </span>
                            <span className="readout shrink-0 text-[13px] font-semibold">
                              {technique.count.toLocaleString()}
                              <span className="sr-only"> session{technique.count === 1 ? '' : 's'}</span>
                            </span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ol>
          </section>
        </>
      )}

      {open && (
        <TechniqueSessions
          key={open.technique.id}
          technique={open.technique}
          tactic={open.tactic}
          filters={filters}
          onClose={() => setOpen(null)}
        />
      )}
    </div>
  )
}
