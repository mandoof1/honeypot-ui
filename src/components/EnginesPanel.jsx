import { useCallback, useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import ErrorBanner from './ErrorBanner'
import EmptyState from './EmptyState'
import { LoadingRegion } from './Loading'
import { useVisiblePoll } from '../hooks/useVisiblePoll'
import { diskFreeRatio, formatBytes, formatDuration, nodeLiveness, relativeTime } from '../lib/format'
import { clean } from '../lib/text'

/*
 * Engines.
 *
 * The console used to show one number — how many nodes were registered — and
 * nothing about whether any of them was alive. A node's heartbeat was only
 * ever written at registration, so the figure said nothing about liveness.
 * The engine now reports every minute, and this is where that report lands:
 * which listeners actually bound, how much is waiting in the spool because the
 * API was unreachable, and how full the capture disk is.
 */

const POLL_MS = 30000
const LOW_DISK = 0.1

const LIVENESS = {
  online: { label: 'Online', color: 'var(--color-s1)' },
  stale: { label: 'Not reporting', color: 'var(--color-s4)' },
  unknown: { label: 'Never reported', color: 'var(--color-paper-3)' },
}

function Stat({ label, children, warn = false, title }) {
  return (
    <div className="min-w-0" title={title}>
      <dt className="eyebrow">{label}</dt>
      <dd
        className="readout mt-1 truncate text-[13px]"
        style={{ color: warn ? 'var(--color-s3)' : 'var(--color-paper)' }}
      >
        {children}
      </dd>
    </div>
  )
}

export function NodeCard({ node, now }) {
  const liveness = nodeLiveness(node, now)
  const tone = LIVENESS[liveness.state]
  const status = node.status || null
  const configured = status?.protocols || []
  const bound = status?.protocols_bound || null
  const unbound = bound ? configured.filter((p) => !bound.includes(p)) : []
  const spool = status?.spool_pending ?? 0
  const freeRatio = diskFreeRatio(status?.disk)
  const lastSeen = liveness.ageSeconds === null
    ? null
    : relativeTime(now - liveness.ageSeconds * 1000, now)

  return (
    <article className="border-b border-line px-4 py-3.5 last:border-b-0" data-testid="engine-card">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h3 className="readout text-[14px] font-semibold text-paper">{clean(node.name)}</h3>
        <span className="tag" style={{ color: tone.color }}>
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: tone.color }} aria-hidden="true" />
          {tone.label}
        </span>
        {lastSeen && (
          <span className="text-[12px] text-paper-3">last seen {lastSeen}</span>
        )}
        {node.version && (
          <span className="readout ml-auto text-[11px] text-paper-3">v{clean(node.version)}</span>
        )}
      </div>

      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-4">
        <Stat label="Mode">
          <span className="capitalize">{status?.mode || node.mode || '—'}</span>
        </Stat>
        <Stat
          label="Protocols"
          warn={unbound.length > 0}
          title={unbound.length ? `Configured but not listening: ${unbound.join(', ')}` : undefined}
        >
          <span className="uppercase">
            {bound ? bound.join(' ') : configured.length ? configured.join(' ') : node.protocol || '—'}
          </span>
          {unbound.length > 0 && (
            <span className="ml-1 normal-case"> · {unbound.length} not bound</span>
          )}
        </Stat>
        <Stat label="Active sessions">{status?.active_sessions ?? '—'}</Stat>
        <Stat label="Total sessions">
          {typeof status?.total_sessions === 'number' ? status.total_sessions.toLocaleString() : '—'}
        </Stat>
        <Stat
          label="Spool"
          warn={spool > 0}
          title="Sessions captured while the API was unreachable, waiting to be sent"
        >
          {status ? (spool > 0 ? `${spool} waiting · ${formatBytes(status.spool_bytes || 0)}` : 'Empty') : '—'}
        </Stat>
        <Stat
          label="Capture disk"
          warn={freeRatio !== null && freeRatio < LOW_DISK}
          title={status?.disk?.path}
        >
          {freeRatio === null
            ? '—'
            : `${formatBytes(status.disk.free_bytes)} free · ${Math.round(freeRatio * 100)}%`}
        </Stat>
        <Stat label="Uptime">{status ? formatDuration(status.uptime_seconds) : '—'}</Stat>
        <Stat label="Blocked addresses">{status?.blocked_ips ?? '—'}</Stat>
      </dl>

      {liveness.state === 'stale' && (
        <p className="mt-3 text-[12px] leading-relaxed text-paper-3">
          The engine has not reported in. Its listeners may still be answering connections, but
          nothing it captures reaches the console until it does.
        </p>
      )}
      {!status && liveness.state !== 'stale' && (
        <p className="mt-3 text-[12px] leading-relaxed text-paper-3">
          No status report yet. Engines running an older version register but do not report.
        </p>
      )}
    </article>
  )
}

export default function EnginesPanel() {
  const [nodes, setNodes] = useState(null)
  const [error, setError] = useState(null)
  const [now, setNow] = useState(() => Date.now())

  const load = useCallback(async () => {
    try {
      const rows = await api.nodes.list(false)
      setNodes(Array.isArray(rows) ? rows : [])
      setNow(Date.now())
      setError(null)
    } catch (err) {
      setError(err.message || 'Could not load engines')
    }
  }, [])

  useEffect(() => {
    const timer = setTimeout(load, 0)
    return () => clearTimeout(timer)
  }, [load])
  useVisiblePoll(load, POLL_MS)

  const online = (nodes || []).filter((n) => nodeLiveness(n, now).state === 'online').length

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2 className="text-base font-semibold text-paper">Engines</h2>
          <p className="mt-0.5 max-w-xl text-[13px] text-paper-3">
            Every honeypot engine registered with this console, and what each last reported.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {nodes && (
            <span className="readout text-[12px] text-paper-3">
              {online} of {nodes.length} online
            </span>
          )}
          <button type="button" className="control" onClick={load} aria-label="Refresh engines">
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
      {error && <div className="p-3"><ErrorBanner message={error} onRetry={load} /></div>}
      {nodes === null && !error ? (
        <LoadingRegion label="Loading engines" className="py-10" />
      ) : nodes?.length === 0 ? (
        <EmptyState
          title="No engines registered"
          hint="An engine registers itself the first time it starts with a valid ingest token."
        />
      ) : (
        (nodes || []).map((node) => <NodeCard key={node.id} node={node} now={now} />)
      )}
    </section>
  )
}
