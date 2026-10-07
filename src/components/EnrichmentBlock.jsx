import { useState } from 'react'
import { Loader2, Sparkles } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { clean } from '../lib/text'

/*
 * Language-model analysis.
 *
 * Stage 2 of the pipeline: after the flow model and the rules have had their
 * say, the stored transcript is read by the project's own model and its
 * reading of intent, objectives and sophistication is merged back onto the
 * session. It runs out of band, so a session can be on screen minutes before
 * the analysis lands — which is why the stage's status is shown rather than
 * an empty panel.
 */

const SOPHISTICATION_LABEL = {
  automated: 'Automated',
  script_kiddie: 'Script kiddie',
  skilled: 'Skilled',
  apt: 'Advanced persistent threat',
  unknown: 'Unknown',
}

const STATUS_TEXT = {
  pending: 'Queued for analysis. The model reads one session at a time; this usually lands within a few minutes.',
  running: 'The model is reading this transcript now.',
  skipped: 'Not analysed: the pipeline only sends the model sessions with commands that the rules found worth reading.',
  not_configured: 'No analysis model is configured on this deployment. Set CHIMERA_URL on the API to enable it.',
}

function percent(value) {
  return typeof value === 'number' ? `${Math.round(value * 100)}%` : null
}

export default function EnrichmentBlock({ session, onQueued }) {
  const { hasRole } = useAuth()
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState(null)
  const [error, setError] = useState(null)
  const [localStatus, setLocalStatus] = useState(null)

  // Mounted with key={session.id} by the parent, so a different session on
  // screen remounts this and the queue state resets on its own.

  if (!session) return null
  // Older APIs do not report the stage at all; show nothing rather than a
  // misleading "not configured".
  if (session.enrichment_status === undefined && !session.enrichment) return null

  const status = localStatus || session.enrichment_status || (session.enrichment ? 'complete' : 'not_configured')
  const result = session.enrichment
  const canQueue = hasRole('analyst') && status !== 'not_configured' && status !== 'pending' && status !== 'running'
  const hasCommands = (session.command_count ?? 0) > 0

  const queue = async () => {
    setBusy(true)
    setError(null)
    try {
      const res = await api.sessions.enrich(session.id)
      setLocalStatus(res?.enrichment_status || 'pending')
      setNotice('Queued. The result appears here once the model has read the transcript.')
      onQueued?.(res)
    } catch (err) {
      setError(err.message || 'Could not queue the analysis')
    } finally {
      setBusy(false)
    }
  }

  const confidence = percent(result?.confidence)

  return (
    <section className="border-t border-line px-4 py-3.5" data-testid="enrichment-block">
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="eyebrow flex items-center gap-1.5">
          <Sparkles className="h-3 w-3" strokeWidth={2} aria-hidden="true" />
          Model analysis
        </h3>
        <span className="text-[12px] text-paper-3">
          {status === 'complete' && result?.model ? clean(result.model) : status.replace(/_/g, ' ')}
        </span>
      </div>

      <div className="mt-2.5 space-y-2.5">
        {status === 'complete' && result ? (
          <>
            {result.intent && (
              <p className="text-[13px] leading-relaxed text-paper">{clean(result.intent)}</p>
            )}
            {result.objectives?.length > 0 && (
              <ul className="space-y-1">
                {result.objectives.map((objective, i) => (
                  <li key={i} className="flex items-baseline gap-2 text-[13px] text-paper-2">
                    <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-paper-3" aria-hidden="true" />
                    <span className="min-w-0">{clean(objective)}</span>
                  </li>
                ))}
              </ul>
            )}
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
              <div>
                <dt className="eyebrow">Sophistication</dt>
                <dd className="mt-1 text-[13px] text-paper">
                  {SOPHISTICATION_LABEL[result.sophistication] || clean(result.sophistication) || '—'}
                </dd>
              </div>
              <div>
                <dt className="eyebrow">Model confidence</dt>
                <dd className="readout mt-1 text-[13px] text-paper">{confidence || '—'}</dd>
              </div>
            </dl>
            {result.analysed_at && (
              <p className="readout text-[11px] text-paper-3">
                analysed {new Date(result.analysed_at).toLocaleString()}
              </p>
            )}
          </>
        ) : status === 'failed' ? (
          <p className="text-[13px] leading-relaxed" style={{ color: 'var(--color-s4)' }}>
            Analysis failed{result?.error ? `: ${clean(result.error)}` : '.'}
          </p>
        ) : (
          <p className="flex items-start gap-2 text-[13px] leading-relaxed text-paper-3">
            {(status === 'pending' || status === 'running') && (
              <Loader2 className="mt-0.5 h-3.5 w-3.5 shrink-0 animate-spin" strokeWidth={2} aria-hidden="true" />
            )}
            <span>{STATUS_TEXT[status] || 'No analysis for this session.'}</span>
          </p>
        )}

        {notice && <p className="text-[12px] text-paper-3">{notice}</p>}
        {error && <p className="text-[12px]" style={{ color: 'var(--color-s4)' }}>{error}</p>}

        {canQueue && hasCommands && (
          <button type="button" onClick={queue} disabled={busy} className="control gap-1.5">
            <Sparkles className="h-3.5 w-3.5" strokeWidth={2} />
            {status === 'complete' || status === 'failed' ? 'Analyse again' : 'Analyse now'}
          </button>
        )}
      </div>
    </section>
  )
}
