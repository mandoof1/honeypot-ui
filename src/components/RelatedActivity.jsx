import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ArrowUpRight, GitBranch } from 'lucide-react'
import { api } from '../services/api'

export default function RelatedActivity({ sessionId }) {
  const [open, setOpen] = useState(false)
  const [windowDays, setWindowDays] = useState('7')
  const [excludeScanners, setExcludeScanners] = useState(false)
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const [revision, setRevision] = useState(0)
  const [searchParams] = useSearchParams()

  useEffect(() => {
    if (!open) return
    const controller = new AbortController()
    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const result = await api.sessions.related(sessionId, {
          window_days: windowDays, exclude_scanners: excludeScanners,
        }, { signal: controller.signal })
        if (!controller.signal.aborted) setData(result)
      } catch (err) {
        if (!controller.signal.aborted) setError(err.message)
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }
    load()
    return () => controller.abort()
  }, [open, sessionId, windowDays, excludeScanners, revision])

  const sessionLink = (id) => {
    const next = new URLSearchParams(searchParams)
    next.set('session', id)
    return `/sessions?${next}`
  }

  return (
    <section className="border-t border-line px-4 py-3.5" aria-label="Related activity">
      <div className="flex items-center justify-between gap-2">
        <h3 className="eyebrow flex items-center gap-2"><GitBranch size={14} aria-hidden="true" />Related activity</h3>
        <button type="button" className="control" aria-expanded={open}
          onClick={() => setOpen((value) => !value)}>{open ? 'Hide related activity' : 'Find related activity'}</button>
      </div>
      <p className="mt-2 text-[12px] leading-relaxed text-paper-3">
        Follow shared source IPs, URLs, domains and file hashes. A match shows
        evidence overlap; it does not establish a common attacker.
      </p>
      {open && <div className="mt-3 space-y-3">
        <div className="flex flex-wrap items-center gap-3 text-[12px] text-paper-2">
          <label className="flex items-center gap-2">Around this session
            <select className="control" aria-label="Related activity time window"
              value={windowDays} onChange={(event) => setWindowDays(event.target.value)}>
              <option value="1">±1 day</option><option value="7">±7 days</option><option value="30">±30 days</option>
            </select>
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={excludeScanners} onChange={(event) => setExcludeScanners(event.target.checked)} />
            Hide research scanners
          </label>
        </div>
        {loading ? <p role="status" className="text-[13px] text-paper-3">Finding related activity…</p>
          : error ? <div role="alert" className="text-[13px] text-s4">
            {error}<button type="button" className="control ml-2" onClick={() => setRevision((value) => value + 1)}>Retry related activity</button>
          </div> : data && <>
            {data.matches?.length ? <ul className="space-y-2">
              {data.matches.map(({ session, same_source_ip, shared_indicators, shared_indicator_count }) => (
                <li key={session.id} className="rounded border border-line p-2.5">
                  <Link to={sessionLink(session.id)} className="flex items-center gap-2 text-[13px] text-paper hover:underline">
                    <span className="readout break-all">{session.attacker_ip}</span>
                    <span className="text-[11px] uppercase text-paper-3">{session.protocol || 'Unknown'}</span>
                    <ArrowUpRight size={14} className="ml-auto shrink-0" aria-hidden="true" />
                  </Link>
                  <p className="mt-1 text-[11px] text-paper-3">{new Date(session.started_at).toLocaleString()}</p>
                  {session.scanner_operator && <p className="mt-1 text-[12px] text-paper-3">{session.scanner_operator} scanner</p>}
                  {same_source_ip && <p className="mt-2 text-[12px] text-paper-2">Same source IP</p>}
                  {shared_indicators.map((ioc) => <p key={`${ioc.type}:${ioc.value}`} className="mt-1 break-all text-[12px] text-paper-2">
                    Shared {ioc.type.replace('_', ' ')}: <span className="readout">{ioc.value}</span>
                  </p>)}
                  {shared_indicator_count > shared_indicators.length && <p className="mt-1 text-[12px] text-paper-3">
                    +{shared_indicator_count - shared_indicators.length} more shared indicators
                  </p>}
                </li>
              ))}
            </ul> : <p className="text-[13px] text-paper-3">No related sessions in this time window.</p>}
            {data.truncated && <p className="text-[12px] text-paper-3">Showing the newest 20 matches. Choose a shorter time window to narrow the results.</p>}
            {data.indicators_truncated && <p className="text-[12px] text-paper-3">This search uses the first 100 distinct URL, domain and file hash indicators recorded for this session.</p>}
          </>}
      </div>}
    </section>
  )
}
