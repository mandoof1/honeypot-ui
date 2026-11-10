import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ExternalLink, X, Download } from 'lucide-react'
import { useAuth } from '../context/useAuth'
import { CategoryTag } from './Severity'
import EnrichmentBlock from './EnrichmentBlock'
import TriageBlock from './TriageBlock'
import Timestamp from './Timestamp'
import { FingerprintsBlock, SignalBadges, SignalsBlock } from './SessionSignals'
import { clean, cleanLine } from '../lib/text'
import { PROFILE_LABEL } from '../lib/severity'
import SessionTranscript, {
  CredentialsBlock,
  DiversionBlock,
  RetrievalBlock,
} from './SessionTranscript'
import { orderTactics, techniqueUrl } from '../lib/attack'
import { diversionOf } from '../lib/diversion'
import { networkLabel } from '../lib/origin'
import { formatSessionDuration } from '../lib/format'
import {
  anomalyReading, flowAdvisory, isRefusal, probabilityText, refusalCount, rulesTruncated, scoreText,
  stageDisagreements, verdictSource,
} from '../lib/verdict'
import { CATEGORY_LABEL } from '../lib/severity'

/*
 * Session detail.
 *
 * Was a modal, which meant an analyst comparing two sessions had to open,
 * read, close, open. It is now a panel beside the list, so the list stays put
 * and moving between rows keeps the same reading position on screen. Below
 * the large breakpoint it becomes a sheet, since there is no room for both.
 *
 * The panel is a pure view of the session it is given. The page keeps that
 * object current (on every poll, and after an action), so status, duration,
 * triage and analysis change here without the reader selecting another row.
 */

function Fact({ label, children, mono = true, wide = false }) {
  return (
    <div className={`min-w-0 ${wide ? 'col-span-2' : ''}`}>
      <dt className="eyebrow">{label}</dt>
      <dd className={`mt-1 text-[13px] text-paper ${wide ? 'break-words' : 'truncate'} ${mono ? 'readout' : ''}`}>
        {children}
      </dd>
    </div>
  )
}

function Block({ title, note, children, testId }) {
  return (
    <section className="border-t border-line px-4 py-3.5" data-testid={testId}>
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="eyebrow">{title}</h3>
        {note && <span className="text-[12px] text-paper-3">{note}</span>}
      </div>
      <div className="mt-2.5">{children}</div>
    </section>
  )
}

function TagRow({ items, color, empty, transform }) {
  if (!items?.length) return <p className="text-[13px] text-paper-3">{empty}</p>
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((item) => (
        <span key={item} className="tag" style={{ color }}>
          {cleanLine(transform ? transform(item) : item)}
        </span>
      ))}
    </div>
  )
}

/**
 * Which stage chose the category, and what its number is.
 *
 * The heading used to be "Model verdict" with "Confidence 85.0%" beneath it,
 * whichever stage had produced the value. For most sessions that was a
 * constant written by the rule layer. Each number is now named for its
 * source, and nothing that is not a probability is formatted as one.
 */
function ClassificationBlock({ session }) {
  const source = verdictSource(session)
  const anomaly = anomalyReading(session)
  const flow = flowAdvisory(session)
  const disagreements = stageDisagreements(session)
  const truncated = rulesTruncated(session)

  return (
    <Block title="How this was classified" note={source.label} testId="classification-block">
      <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
        <Fact label="Category chosen by" mono={false} wide>
          {source.label}
          {source.detail && <span className="text-paper-3"> ({source.detail})</span>}
        </Fact>
        <Fact label={source.scoreLabel}>{scoreText(session.attack_confidence)}</Fact>
        <Fact label="Anomaly score" mono={anomaly.state !== 'not_calibrated'}>
          {anomaly.state === 'not_calibrated' ? (
            <span data-testid="anomaly-not-calibrated">Not calibrated</span>
          ) : (
            scoreText(anomaly.score, 3)
          )}
        </Fact>
      </dl>

      <p className="mt-2.5 text-[12px] leading-relaxed text-paper-3">{source.note}</p>

      {anomaly.state === 'not_calibrated' && (
        <p className="mt-2 text-[12px] leading-relaxed text-paper-3">
          The anomaly detector has no calibrated threshold yet, so this session is neither flagged
          nor cleared by it
          {anomaly.score !== null && <> (raw score <span className="readout">{scoreText(anomaly.score, 3)}</span>)</>}.
        </p>
      )}
      {anomaly.state === 'flagged' && (
        <p className="mt-2 text-[12px] leading-relaxed text-paper-3">
          Flagged as anomalous by the detector. Its score measures how unusual the session is; it
          is not a probability.
        </p>
      )}

      {session.model_source === 'rules' && (
        <p className="mt-2 text-[12px] leading-relaxed text-paper-3">
          The category is set by signature rules over the recorded commands, logins and uploads.
          {session.rule_reason ? (
            <>
              {' '}Matched: <span className="text-paper-2">{clean(session.rule_reason)}</span>.
            </>
          ) : (
            ' See the detected tools and intents below for what matched.'
          )}
        </p>
      )}

      {truncated && (
        <p className="mt-2 text-[12px] leading-relaxed" style={{ color: 'var(--color-s2)' }}>
          This session is longer than the rules read in full: they saw its start and its end. No
          finding from them is not a clearance.
        </p>
      )}

      {flow && (
        <p className="mt-2 text-[12px] leading-relaxed text-paper-3" data-testid="flow-advisory">
          Flow classifier, advisory only:{' '}
          <span className="text-paper-2">{(CATEGORY_LABEL[flow.category] || cleanLine(flow.category)).toLowerCase()}</span>
          {flow.score !== null && <> (score <span className="readout">{scoreText(flow.score)}</span>)</>}.
          {' '}It reads connection statistics and does not decide the category
          {flow.disagrees ? '; here it reads the session as more serious than the rules do.' : '.'}
        </p>
      )}

      {disagreements.map((item) => (
        <p key={item.stage} className="mt-2 text-[12px] leading-relaxed" style={{ color: 'var(--color-s2)' }}>
          The {item.name} read this session as{' '}
          {(CATEGORY_LABEL[item.category] || cleanLine(item.category)).toLowerCase()}, not as the
          rules&rsquo; {(CATEGORY_LABEL[item.rules || session.attack_category] || 'verdict').toLowerCase()}.
          The stored category stays the rules&rsquo;.
        </p>
      ))}

      {session.cluster?.fitted && (
        <p className="mt-2 text-[12px] leading-relaxed text-paper-3">
          Behaviourally grouped with cluster {session.cluster.cluster}
          {session.cluster.is_outlier
            ? ' — but far from its centre, so this session resembles nothing seen before.'
            : '.'}
        </p>
      )}

      <details className="mt-2.5">
        <summary className="cursor-pointer text-[12px] font-medium text-paper-2 hover:text-paper">
          What produces these readings
        </summary>
        <dl className="mt-2 space-y-2 text-[12px] leading-relaxed text-paper-3">
          <div>
            <dt className="font-medium text-paper-2">Signature rules</dt>
            <dd>Fixed patterns over the commands, logins and uploads. They decide the category.</dd>
          </div>
          <div>
            <dt className="font-medium text-paper-2">Flow classifier</dt>
            <dd>A model over connection statistics. Its reading is advisory and never changes the category.</dd>
          </div>
          <div>
            <dt className="font-medium text-paper-2">Anomaly detector</dt>
            <dd>Scores how unusual a session is. It flags; it does not classify.</dd>
          </div>
          <div>
            <dt className="font-medium text-paper-2">Decision model</dt>
            <dd>
              A small model that reads the commands and answers with probabilities over fixed
              options. Shown under &ldquo;Decision-model triage&rdquo;
              {session.triage?.model && <> (this deployment runs <span className="readout">{cleanLine(session.triage.model)}</span>)</>}.
            </dd>
          </div>
          <div>
            <dt className="font-medium text-paper-2">Language model</dt>
            <dd>
              The project&rsquo;s own language model, which reads the transcript and writes the
              intent and objectives. Shown under &ldquo;Language-model analysis&rdquo;
              {session.enrichment?.model && <> (this deployment runs <span className="readout">{cleanLine(session.enrichment.model)}</span>)</>}.
            </dd>
          </div>
        </dl>
      </details>
    </Block>
  )
}

function Technique({ technique }) {
  const url = techniqueUrl(technique)
  const fromLanguageModel = technique.source === 'chimera'
  const body = (
    <>
      <span className="readout shrink-0 text-[12px] text-paper-2">{cleanLine(technique.id)}</span>
      <span className="min-w-0 flex-1 text-[13px] text-paper">{clean(technique.name)}</span>
      {!url && (
        <span
          className="tag shrink-0"
          style={{ color: 'var(--color-s2)' }}
          title="This id was not confirmed against the ATT&CK catalog, so it is not linked"
        >
          unverified
        </span>
      )}
      {fromLanguageModel && (
        <span
          className="shrink-0 text-[12px]"
          style={{ color: 'var(--color-s2)' }}
          title="Named by the language model from the transcript, not matched by the rule map"
        >
          language model
        </span>
      )}
      {fromLanguageModel && typeof technique.support === 'number' && (
        <span
          className="readout shrink-0 text-[12px]"
          style={{ color: technique.unconfirmed ? 'var(--color-s3)' : 'var(--color-paper-3)' }}
          title={
            technique.unconfirmed
              ? 'The decision model found little sign of this technique in the transcript; its tactic is not counted'
              : 'The decision model\'s probability that the transcript shows this technique'
          }
        >
          {technique.unconfirmed ? 'unconfirmed' : 'checked'} {probabilityText(technique.support)}
        </span>
      )}
    </>
  )

  if (!url) {
    return <div className="flex items-baseline gap-2 px-1.5 py-1 -mx-1.5">{body}</div>
  }
  return (
    <a
      href={url}
      target="_blank"
      rel="noreferrer noopener"
      className="group flex items-baseline gap-2 rounded-[3px] px-1.5 py-1 -mx-1.5 transition-colors hover:bg-ink-2"
    >
      {body}
      <ExternalLink
        className="h-3 w-3 shrink-0 text-paper-3 opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100"
        strokeWidth={2}
        aria-label="opens attack.mitre.org"
      />
    </a>
  )
}

/** Tactics by name and in kill-chain order, then the techniques behind them. */
function AttackBlock({ session }) {
  const techniques = session.mitre_techniques || []
  const tactics = orderTactics(session.mitre_tactics)
  if (techniques.length === 0 && tactics.length === 0) return null

  return (
    <Block title="MITRE ATT&CK" note={tactics.length ? 'tactics in kill-chain order' : undefined} testId="attack-block">
      {tactics.length > 0 && (
        <ol className="mb-2.5 flex flex-wrap items-center gap-x-1.5 gap-y-1.5" aria-label="Tactics, in kill-chain order">
          {tactics.map((tactic, i) => (
            <li key={`${tactic.id}-${i}`} className="flex items-center gap-1.5">
              {i > 0 && <span className="text-paper-3" aria-hidden="true">›</span>}
              <span
                className="tag"
                style={{ color: 'var(--color-paper-2)' }}
                title={tactic.known ? tactic.id : 'Not a tactic id this console recognises'}
              >
                {cleanLine(tactic.name)}
              </span>
            </li>
          ))}
        </ol>
      )}
      {techniques.length > 0 && (
        <ul className="space-y-1">
          {techniques.map((technique, i) => (
            <li key={`${technique.id}-${i}`}>
              <Technique technique={technique} />
            </li>
          ))}
        </ul>
      )}
    </Block>
  )
}

/** Report export for this one session. The page owns the job; this only asks. */
function ReportControls({ session, onReport, isAdmin }) {
  const [sensitive, setSensitive] = useState(false)

  return (
    <div className="px-4 pb-3" data-testid="session-report-controls">
      <div className="flex flex-wrap items-center gap-2">
        {[['pdf', 'Export PDF report'], ['docx', 'Export Word report']].map(([format, label]) => (
          <button
            key={format}
            type="button"
            className="control gap-1.5"
            onClick={() => onReport(session, format, isAdmin && sensitive)}
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            {label}
          </button>
        ))}
      </div>
      <p className="mt-1.5 text-[12px] leading-relaxed text-paper-3">
        Written by the local language model from this session&rsquo;s evidence. It can take several
        minutes; progress is shown at the top of the page.
      </p>
      {isAdmin && (
        <label className="mt-1.5 flex cursor-pointer items-start gap-2">
          <input
            type="checkbox"
            checked={sensitive}
            onChange={(event) => setSensitive(event.target.checked)}
            className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-paper"
          />
          <span className="text-[12px] leading-relaxed text-paper-2">
            Include original credentials in this session&rsquo;s report
            <span className="block text-paper-3">
              Off by default. When on, the report carries the captured activity unredacted and the
              passwords this session tried, and the request is recorded in the audit log.
            </span>
          </span>
        </label>
      )}
    </div>
  )
}

/**
 * A connection the engine's rate limit turned away. Nothing was exchanged, so
 * there is no verdict, transcript or fingerprint to show, and drawing the
 * full panel would dress a refusal up as a session.
 */
function RefusedConnection({ session, onClose }) {
  const count = refusalCount(session)
  return (
    <div className="flex h-full flex-col overflow-y-auto" data-testid="refused-connection">
      <header className="flex items-start justify-between gap-3 px-4 pb-3 pt-4">
        <div className="min-w-0">
          <h2 className="readout truncate text-[17px] font-semibold text-paper">
            <Link to={`/attackers/${encodeURIComponent(session.attacker_ip)}`} className="hover:underline">
              {cleanLine(session.attacker_ip)}
            </Link>
          </h2>
          <p className="mt-1 text-[13px] font-medium text-paper-2">Refused connection</p>
        </div>
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            aria-label="Close details"
            className="shrink-0 rounded-[3px] p-1 text-paper-3 transition-colors hover:text-paper lg:hidden"
          >
            <X className="h-5 w-5" strokeWidth={1.75} />
          </button>
        )}
      </header>
      <div className="border-t border-line px-4 py-3.5">
        <p className="text-[13px] leading-relaxed text-paper-2">
          This is not a session. The engine&rsquo;s connection limit refused
          {count && count > 1 ? ` ${count.toLocaleString()} connections` : ' a connection'} from this
          address, so nothing was exchanged and there is nothing to analyse.
        </p>
        <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-3">
          <Fact label="Protocol"><span className="uppercase">{session.protocol || '—'}</span></Fact>
          <Fact label="Connections refused">{count ?? 'not recorded'}</Fact>
          <Fact label="Recorded" wide><Timestamp value={session.started_at} /></Fact>
        </dl>
      </div>
    </div>
  )
}

export default function SessionDetail({ session, onClose, onReport, onChanged }) {
  const { hasRole } = useAuth()

  if (!session) {
    return (
      <div className="flex h-full items-center justify-center px-6 py-16 text-center">
        <p className="max-w-[15rem] text-[13px] leading-relaxed text-paper-3">
          Select a session to see its verdict, tooling and ATT&amp;CK mapping.
        </p>
      </div>
    )
  }

  const anomaly = anomalyReading(session)
  const diversion = diversionOf(session)

  if (isRefusal(session)) {
    return <RefusedConnection session={session} onClose={onClose} />
  }

  return (
    <div className="flex h-full flex-col overflow-y-auto" data-testid="session-detail">
      <header className="flex items-start justify-between gap-3 px-4 pb-3 pt-4">
        <div className="min-w-0">
          <h2 className="readout truncate text-[17px] font-semibold text-paper">
            <Link
              to={`/attackers/${encodeURIComponent(session.attacker_ip)}`}
              className="transition-colors hover:underline"
              title="Everything this address has done"
            >
              {cleanLine(session.attacker_ip)}
            </Link>
          </h2>
          <p className="readout mt-1 truncate text-[12px] text-paper-3" title="Session UUID">
            {session.session_uuid}
          </p>
        </div>
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            aria-label="Close session details"
            className="shrink-0 rounded-[3px] p-1 text-paper-3 transition-colors hover:text-paper lg:hidden"
          >
            <X className="h-5 w-5" strokeWidth={1.75} />
          </button>
        )}
      </header>

      {onReport && hasRole('analyst') && (
        <ReportControls key={`r${session.id}`} session={session} onReport={onReport} isAdmin={hasRole('admin')} />
      )}

      <div className="flex flex-wrap gap-1.5 px-4 pb-3.5">
        <CategoryTag category={session.attack_category} />
        {anomaly.state === 'flagged' && (
          <span className="tag" style={{ color: 'var(--color-s4)' }}>Anomalous</span>
        )}
        {anomaly.state === 'not_calibrated' && (
          <span
            className="tag"
            style={{ color: 'var(--color-paper-3)' }}
            title="The anomaly detector has no calibrated threshold yet"
          >
            Anomaly: not calibrated
          </span>
        )}
        <span className="tag" style={{ color: 'var(--color-paper-3)' }}>
          {PROFILE_LABEL[session.attacker_profile] || PROFILE_LABEL.unknown}
        </span>
        {session.scanner_operator && (
          <span
            className="tag"
            style={{ color: 'var(--color-paper-2)' }}
            title="This address belongs to a public research scanner. The session is real, but it is not an attack."
          >
            {cleanLine(session.scanner_operator)} scanner
          </span>
        )}
        {diversion && (
          <span
            className="tag"
            style={{ color: 'var(--color-s3)' }}
            title={`Answered by the decoy copy of the website: ${cleanLine(diversion.reason) || 'earlier attack'}`}
          >
            Diverted to decoy
          </span>
        )}
        <SignalBadges session={session} />
      </div>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-3 border-t border-line px-4 py-3.5">
        <Fact label="Origin" mono={false}>
          {cleanLine(session.geo?.country_name || session.geo?.country) || networkLabel(session.attacker_ip) || 'Unknown'}
        </Fact>
        <Fact label="Protocol">
          <span className="uppercase">{session.protocol || '—'}</span>
        </Fact>
        <Fact label="Duration">
          <span data-testid="session-duration">{formatSessionDuration(session.duration_seconds)}</span>
        </Fact>
        <Fact label="Status" mono={false}>
          <span className="capitalize" data-testid="session-status">{session.status}</span>
        </Fact>
        <Fact label="Started" wide>
          <Timestamp value={session.started_at} />
        </Fact>
        <Fact label="Commands">{session.command_count ?? 0}</Fact>
      </dl>

      <ClassificationBlock session={session} />

      {session.command_summary && (
        <Block title="Summary">
          <p className="whitespace-pre-line text-[13px] leading-relaxed text-paper-2">
            {clean(session.command_summary.slice(0, 600))}
          </p>
        </Block>
      )}

      <Block title="Tools detected">
        <TagRow
          items={session.detected_tools}
          color="var(--color-s3)"
          empty="None detected."
          transform={(t) => String(t).replace(/_/g, ' ')}
        />
      </Block>

      <Block title="Intents">
        <TagRow
          items={session.detected_intents}
          color="var(--color-s2)"
          empty="None inferred."
          transform={(t) => String(t).replace(/_/g, ' ')}
        />
      </Block>

      <AttackBlock session={session} />
      <SignalsBlock session={session} />
      <FingerprintsBlock session={session} />
      <TriageBlock session={session} />
      <EnrichmentBlock key={`e${session.id}`} session={session} onQueued={onChanged} />
      <DiversionBlock session={session} />
      <RetrievalBlock session={session} />
      {/* Keyed so switching sessions remounts them and their loaded state
          resets, rather than being cleared afterwards by an effect. */}
      <SessionTranscript key={`t${session.id}`} session={session} />
      <CredentialsBlock key={`c${session.id}`} session={session} />

      {session.uploaded_files?.length > 0 && (
        <Block title="Files uploaded" note={String(session.uploaded_files.length)}>
          <ul className="space-y-1">
            {session.uploaded_files.map((file) => (
              <li key={file} className="readout text-[12px] break-all text-paper-2">
                {cleanLine(file)}
              </li>
            ))}
          </ul>
        </Block>
      )}
    </div>
  )
}
