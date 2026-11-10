import { Bot, Fingerprint, KeyRound } from 'lucide-react'
import {
  aiAgentReading, fingerprintRows, honeytokenIds, notableEvents, scoreText,
} from '../lib/verdict'
import { clean, cleanLine } from '../lib/text'
import CopyButton from './CopyButton'
import Timestamp from './Timestamp'

/*
 * Signals and fingerprints.
 *
 * Signals are the engine's own tripwires, as opposed to a model's opinion: a
 * canary instruction that only an automated agent would follow, a planted
 * credential that was used. Fingerprints identify the client software rather
 * than the address, so the same tool is recognisable from a new address.
 *
 * Every field here may be absent on sessions captured before it existed, so
 * each block draws nothing unless it has something to say.
 */

/** Badges for the header row: only the signals strong enough to act on. */
export function SignalBadges({ session, compact = false }) {
  const agent = aiAgentReading(session)
  const tokens = honeytokenIds(session)
  if (agent?.level !== 'likely' && tokens.length === 0) return null

  return (
    <>
      {agent?.level === 'likely' && (
        <span
          className="tag shrink-0"
          style={{ color: 'var(--color-s3)' }}
          title="The engine's AI-agent canary was triggered in this session"
          data-testid="ai-agent-badge"
        >
          <Bot className="h-3 w-3" strokeWidth={2} aria-hidden="true" />
          {compact ? 'AI agent' : 'Likely automated AI agent'}
        </span>
      )}
      {tokens.length > 0 && (
        <span
          className="tag shrink-0"
          style={{ color: 'var(--color-s4)' }}
          title="This session used a credential or file that exists only as bait"
          data-testid="honeytoken-badge"
        >
          <KeyRound className="h-3 w-3" strokeWidth={2} aria-hidden="true" />
          {compact ? 'Honeytoken' : 'Honeytoken used'}
        </span>
      )}
    </>
  )
}

function Heading({ icon: Icon, title, note }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <h3 className="eyebrow flex items-center gap-1.5">
        <Icon className="h-3 w-3" strokeWidth={2} aria-hidden="true" />
        {title}
      </h3>
      {note && <span className="text-[12px] text-paper-3">{note}</span>}
    </div>
  )
}

/** What the tripwires recorded, with the evidence behind each. */
export function SignalsBlock({ session }) {
  const agent = aiAgentReading(session)
  const tokens = honeytokenIds(session)
  const events = notableEvents(session)
  if (!agent && tokens.length === 0 && events.length === 0) return null

  return (
    <section className="border-t border-line px-4 py-3.5" data-testid="signals-block">
      <Heading icon={Bot} title="Signals" note="engine tripwires" />
      <div className="mt-2.5 space-y-2.5">
        {agent?.level === 'likely' && (
          <div>
            <p className="text-[13px] font-medium text-paper">Likely an automated AI agent</p>
            <p className="mt-0.5 text-[12px] leading-relaxed text-paper-2">
              The engine reports that this session triggered its AI-agent canary: bait placed for
              automated agents, which a person at a keyboard is unlikely to act on.
              {agent.score !== null && <> Agent score {scoreText(agent.score)}.</>}
            </p>
          </div>
        )}
        {agent?.level === 'possible' && (
          <p className="text-[13px] leading-relaxed text-paper-2" data-testid="ai-agent-note">
            <span className="font-medium text-paper">Possibly automated.</span>{' '}
            No canary was triggered. The gaps between commands are in the range the engine
            associates with an automated agent (timing score {scoreText(agent.score)}). Timing
            alone is suggestive, not a detection, and the score is not a probability.
          </p>
        )}
        {agent && agent.reasons.length > 0 && (
          <ul className="space-y-1">
            {agent.reasons.map((reason, i) => (
              <li key={i} className="flex items-baseline gap-2 text-[12px] text-paper-2">
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-paper-3" aria-hidden="true" />
                <span className="min-w-0">{clean(reason)}</span>
              </li>
            ))}
          </ul>
        )}

        {tokens.length > 0 && (
          <div>
            <p className="text-[13px] font-medium text-paper">
              Used {tokens.length === 1 ? 'a honeytoken' : `${tokens.length} honeytokens`}
            </p>
            <p className="mt-0.5 text-[12px] leading-relaxed text-paper-2">
              A honeytoken is a credential or file planted as bait. Nothing legitimate ever uses
              one, so its use ties this session to wherever the bait was taken from.
            </p>
            <ul className="mt-1 flex flex-wrap gap-1.5">
              {tokens.map((id) => (
                <li key={id} className="readout rounded-[3px] bg-ink-2 px-1.5 py-0.5 text-[12px] text-paper-2">
                  {cleanLine(id)}
                </li>
              ))}
            </ul>
          </div>
        )}

        {events.length > 0 && (
          <ul className="space-y-1">
            {events.map((event, i) => (
              <li key={i} className="flex flex-wrap items-baseline gap-x-2 text-[12px] text-paper-2">
                <span className="text-paper">{event.text}</span>
                {event.detail && <span className="readout break-all">{cleanLine(event.detail)}</span>}
                {event.at !== null && <Timestamp value={event.at * 1000} style="time" className="readout text-paper-3" />}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}

/** Client fingerprints, each with a copy button. */
export function FingerprintsBlock({ session }) {
  const { primary, details } = fingerprintRows(session)
  if (primary.length === 0 && details.length === 0) return null

  return (
    <section className="border-t border-line px-4 py-3.5" data-testid="fingerprints-block">
      <Heading icon={Fingerprint} title="Client fingerprints" note="identify the tool, not the address" />
      <dl className="mt-2.5 space-y-1.5">
        {primary.map((row) => (
          <div key={row.key} className="flex items-center gap-2">
            <dt className="eyebrow w-24 shrink-0" title={row.hint}>{row.label}</dt>
            <dd className="readout min-w-0 flex-1 break-all text-[12px] text-paper">{cleanLine(row.value)}</dd>
            <CopyButton value={row.value} label={`Copy ${row.label}`} />
          </div>
        ))}
      </dl>
      {details.length > 0 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-[12px] font-medium text-paper-2 hover:text-paper">
            What the fingerprints were computed from
          </summary>
          <dl className="mt-1.5 space-y-1.5">
            {details.map((row) => (
              <div key={row.key}>
                <dt className="eyebrow">{row.label}</dt>
                <dd className="readout mt-0.5 break-all text-[12px] text-paper-2">{cleanLine(row.value)}</dd>
              </div>
            ))}
          </dl>
        </details>
      )}
    </section>
  )
}
