import { Gauge, Loader2 } from 'lucide-react'
import { CATEGORY_COLOR, CATEGORY_LABEL, CATEGORY_ORDER } from '../lib/severity'
import { clean } from '../lib/text'

/*
 * Decision-model triage.
 *
 * A second opinion that reads the commands themselves, from a model that
 * answers with probabilities over fixed options instead of prose. It runs in
 * seconds, before the language model, and decides whether the language model
 * reads the session at all. Shown as distributions, not just the winning
 * label: 0.48 against 0.46 and 0.95 against 0.02 are different findings.
 */

const SEVERITY_LEVEL = ['Nothing harmful', 'Information gathering', 'Attempted compromise', 'High impact']

const OPERATOR_LABEL = { automated: 'Automated', human: 'Human at the keyboard' }

const STATUS_TEXT = {
  pending: 'Waiting for the decision model. It reads sessions in order, a few seconds each.',
  running: 'The decision model is reading this session now.',
  skipped: 'Not triaged: the session has no commands, or comes from a known research scanner.',
}

function pct(value) {
  return typeof value === 'number' ? `${Math.round(value * 100)}%` : '—'
}

function Distribution({ probabilities }) {
  const rows = CATEGORY_ORDER.filter((c) => probabilities?.[c] !== undefined)
  return (
    <ul className="space-y-1" aria-label="Category probabilities">
      {rows.map((category) => {
        const value = probabilities[category]
        return (
          <li key={category} className="grid grid-cols-[7.5rem_1fr_2.75rem] items-center gap-2">
            <span className="truncate text-[12px] text-paper-2">{CATEGORY_LABEL[category] || category}</span>
            <span className="h-1.5 overflow-hidden rounded-full bg-ink-3" aria-hidden="true">
              <span
                className="block h-full rounded-full"
                style={{ width: `${Math.max(2, value * 100)}%`, background: CATEGORY_COLOR[category] }}
              />
            </span>
            <span className="readout text-right text-[12px] text-paper">{pct(value)}</span>
          </li>
        )
      })}
    </ul>
  )
}

export default function TriageBlock({ session }) {
  if (!session) return null
  const status = session.triage_status
  if (!status || status === 'not_configured') return null
  const triage = session.triage

  return (
    <section className="border-t border-line px-4 py-3.5" data-testid="triage-block">
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="eyebrow flex items-center gap-1.5">
          <Gauge className="h-3 w-3" strokeWidth={2} aria-hidden="true" />
          Triage
        </h3>
        <span className="text-[12px] text-paper-3">
          {status === 'complete' && triage?.model ? clean(triage.model) : status}
        </span>
      </div>

      <div className="mt-2.5 space-y-2.5">
        {status === 'complete' && triage ? (
          <>
            <Distribution probabilities={triage.category_probabilities} />
            {triage.agrees_with_rules === false && session.attack_category && (
              <p className="text-[12px] leading-relaxed" style={{ color: 'var(--color-s2)' }}>
                Disagrees with the verdict above, which reads this session as{' '}
                {(CATEGORY_LABEL[session.attack_category] || session.attack_category).toLowerCase()}.
              </p>
            )}
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
              <div>
                <dt className="eyebrow">Severity</dt>
                <dd className="mt-1 text-[13px] text-paper">
                  {typeof triage.severity === 'number'
                    ? SEVERITY_LEVEL[Math.min(3, Math.max(0, Math.round(triage.severity)))]
                    : '—'}
                  {typeof triage.severity === 'number' && (
                    <span className="readout ml-1.5 text-[12px] text-paper-3">{triage.severity.toFixed(2)} / 3</span>
                  )}
                </dd>
              </div>
              <div>
                <dt
                  className="eyebrow"
                  title="Not yet measured against sessions with a known operator; read it as a hint"
                >
                  Operator · unvalidated
                </dt>
                <dd className="mt-1 text-[13px] text-paper">
                  {OPERATOR_LABEL[triage.operator] || clean(triage.operator) || '—'}
                  <span className="readout ml-1.5 text-[12px] text-paper-3">{pct(triage.operator_probability)}</span>
                </dd>
              </div>
            </dl>
            {(triage.route || triage.suggested_route) && (
              <p className="text-[12px] leading-relaxed text-paper-3">
                <span className="text-paper-2">
                  {triage.route
                    ? triage.route === 'pending' ? 'Sent to the language model' : 'Language model skipped'
                    : triage.suggested_route === 'pending'
                      ? 'Would have sent this to the language model'
                      : 'Would have skipped the language model'}
                </span>
                {triage.route_reason ? ` — ${clean(triage.route_reason)}.` : '.'}
                {!triage.route && ' Triage ran after the session was already queued or analysed, so nothing was changed.'}
              </p>
            )}
            <p className="readout text-[11px] text-paper-3">
              {triage.triaged_at && `triaged ${new Date(triage.triaged_at).toLocaleString()}`}
              {typeof triage.ms === 'number' && ` · ${(triage.ms / 1000).toFixed(1)} s`}
              {triage.reused_from_session && ` · same transcript as session ${triage.reused_from_session}`}
            </p>
          </>
        ) : status === 'failed' ? (
          <p className="text-[13px] leading-relaxed text-paper-3">
            Triage did not complete{triage?.error ? ` (${clean(triage.error)})` : ''}; the rules&rsquo; verdict
            decided whether the language model reads this session.
          </p>
        ) : (
          <p className="flex items-start gap-2 text-[13px] leading-relaxed text-paper-3">
            {(status === 'pending' || status === 'running') && (
              <Loader2 className="mt-0.5 h-3.5 w-3.5 shrink-0 animate-spin" strokeWidth={2} aria-hidden="true" />
            )}
            <span>{STATUS_TEXT[status] || 'No triage for this session.'}</span>
          </p>
        )}
      </div>
    </section>
  )
}
