import { useState } from 'react'
import { Loader2, Sparkles } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { scoreText } from '../lib/verdict'
import { clean, cleanLine } from '../lib/text'
import Timestamp from './Timestamp'

/*
 * Language-model analysis.
 *
 * Stage 2 of the pipeline: after the flow model and the rules have had their
 * say, the stored transcript is read by the project's own language model and
 * its reading of intent, objectives and sophistication is merged back onto
 * the session. It runs out of band, so a session can be on screen minutes
 * before the analysis lands — which is why the stage's status is shown
 * rather than an empty panel.
 */

const SOPHISTICATION_LABEL = {
  automated: 'Automated',
  script_kiddie: 'Script kiddie',
  skilled: 'Skilled',
  apt: 'Advanced persistent threat',
  unknown: 'Unknown',
}

const STATUS_LABEL = {
  triage: 'waiting for triage',
  pending: 'queued',
  running: 'reading now',
  skipped: 'not analysed',
  failed: 'failed',
  complete: 'complete',
  not_configured: 'switched off',
}

const STATUS_TEXT = {
  triage: 'Waiting for triage: the decision model reads the session first and decides whether the language model should.',
  pending: 'Queued for the language model. It reads one session at a time; this usually lands within a few minutes.',
  running: 'The language model is reading this transcript now.',
  skipped: 'Not analysed: the pipeline only sends the language model sessions with commands that the rules found worth reading.',
  not_configured: 'The language-model stage is switched off on this deployment: the API has no model address configured (its CHIMERA_URL setting is empty).',
}

/** What the server last said about this stage, as one comparable value. */
function serverSignature(session) {
  return `${session.enrichment_status}|${session.enrichment?.analysed_at || ''}`
}

export default function EnrichmentBlock({ session, onQueued }) {
  const { hasRole } = useAuth()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  // What the queue request answered, and what the session said at that
  // moment. It stands in only until the session itself says something new;
  // it used to override the server's status until the panel was remounted, so
  // a queued analysis never appeared to finish.
  const [queued, setQueued] = useState(null)

  // Mounted with key={session.id} by the parent, so a different session on
  // screen remounts this and the queue state resets on its own.

  if (!session) return null
  // Older APIs do not report the stage at all; show nothing rather than a
  // misleading "not configured".
  if (session.enrichment_status === undefined && !session.enrichment) return null

  const serverStatus = session.enrichment_status || (session.enrichment ? 'complete' : 'not_configured')
  const awaitingServer = queued !== null && queued.signature === serverSignature(session)
  const status = awaitingServer ? queued.status : serverStatus
  const result = session.enrichment
  const canQueue = hasRole('analyst') && status !== 'not_configured' && status !== 'pending' && status !== 'running'
  const hasCommands = (session.command_count ?? 0) > 0
  const inProgress = status === 'pending' || status === 'running'

  const queue = async () => {
    setBusy(true)
    setError(null)
    try {
      const res = await api.sessions.enrich(session.id)
      setQueued({ status: res?.enrichment_status || 'pending', signature: serverSignature(session) })
      onQueued?.(res)
    } catch (err) {
      setError(err.message || 'Could not queue the analysis')
    } finally {
      setBusy(false)
    }
  }

  const dropped = result?.dropped_techniques || []
  const modelName = result?.model ? cleanLine(result.model) : null

  return (
    <section className="border-t border-line px-4 py-3.5" data-testid="enrichment-block">
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="eyebrow flex items-center gap-1.5">
          <Sparkles className="h-3 w-3" strokeWidth={2} aria-hidden="true" />
          Language-model analysis
        </h3>
        <span className="text-[12px] text-paper-3" data-testid="enrichment-status">
          {STATUS_LABEL[status] || status.replace(/_/g, ' ')}
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
                <dt className="eyebrow">Self-reported confidence</dt>
                <dd className="readout mt-1 text-[13px] text-paper">{scoreText(result.confidence)}</dd>
              </div>
            </dl>
            {typeof result.confidence === 'number' && (
              <p className="text-[12px] leading-relaxed text-paper-3">
                The confidence is the language model&rsquo;s own statement about its reading, on a
                scale of 0 to 1. It is self-reported, not a measured probability.
              </p>
            )}
            {dropped.length > 0 && (
              <p className="text-[12px] leading-relaxed text-paper-3">
                Removed {dropped.length === 1 ? 'one technique' : `${dropped.length} techniques`} the transcript
                does not support: {dropped.map((t) => cleanLine(t.id)).join(', ')}.
              </p>
            )}
            <p className="text-[12px] leading-relaxed text-paper-3">
              {modelName
                ? <>Written by the language model <span className="readout text-paper-2">{modelName}</span></>
                : 'Written by the language model'}
              {result.analysed_at && <>, <Timestamp value={result.analysed_at} /></>}
              {result.checked_by && (
                <>
                  ; techniques checked by the decision model{' '}
                  <span className="readout text-paper-2">{cleanLine(result.checked_by)}</span>
                </>
              )}
              .
            </p>
          </>
        ) : status === 'failed' ? (
          <p className="text-[13px] leading-relaxed" style={{ color: 'var(--color-s4)' }}>
            Analysis failed{result?.error ? `: ${clean(result.error)}` : '.'}
          </p>
        ) : (
          <p className="flex items-start gap-2 text-[13px] leading-relaxed text-paper-3">
            {inProgress && (
              <Loader2 className="mt-0.5 h-3.5 w-3.5 shrink-0 animate-spin" strokeWidth={2} aria-hidden="true" />
            )}
            <span>
              {status === 'skipped' && session.triage?.route === 'skipped' && session.triage.route_reason
                ? `Not analysed: ${clean(session.triage.route_reason)}.`
                : STATUS_TEXT[status] || 'No analysis for this session.'}
            </span>
          </p>
        )}

        {inProgress && (
          <p className="text-[12px] text-paper-3" aria-live="polite">
            {queued ? 'Queued. ' : ''}This panel checks for the result every few seconds and updates by itself.
          </p>
        )}
        {error && <p className="text-[12px]" style={{ color: 'var(--color-s4)' }} role="alert">{error}</p>}

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
