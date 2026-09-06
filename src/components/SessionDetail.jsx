import { ExternalLink, X } from 'lucide-react'
import { CategoryTag } from './Severity'
import { PROFILE_LABEL } from '../lib/severity'
import RelatedActivity from './RelatedActivity'
import SessionTranscript, {
  CredentialsBlock,
  RetrievalBlock,
} from './SessionTranscript'

/*
 * Session detail.
 *
 * Was a modal, which meant an analyst comparing two sessions had to open,
 * read, close, open. It is now a panel beside the list, so the list stays put
 * and moving between rows keeps the same reading position on screen. Below
 * the large breakpoint it becomes a sheet, since there is no room for both.
 */

/* What the classifier was actually running on when it produced the verdict. */
const MODEL_SOURCE_NOTE = {
  synthetic: 'Bootstrap model',
  cicids2017: 'Trained · CIC-IDS2017',
  pretrained: 'Trained model',
  unloaded: 'No model loaded',
}

function percent(value) {
  return typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : '—'
}

function duration(seconds) {
  if (typeof seconds !== 'number') return 'In progress'
  if (seconds < 60) return `${seconds.toFixed(1)}s`
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`
}

function Fact({ label, children, mono = true }) {
  return (
    <div className="min-w-0">
      <dt className="eyebrow">{label}</dt>
      <dd className={`mt-1 truncate text-[13px] text-paper ${mono ? 'readout' : ''}`}>
        {children}
      </dd>
    </div>
  )
}

function Block({ title, note, children }) {
  return (
    <section className="border-t border-line px-4 py-3.5">
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
          {transform ? transform(item) : item}
        </span>
      ))}
    </div>
  )
}

export default function SessionDetail({ session, onClose }) {
  if (!session) {
    return (
      <div className="flex h-full items-center justify-center px-6 py-16 text-center">
        <p className="max-w-[15rem] text-[13px] leading-relaxed text-paper-3">
          Select a session to see its verdict, tooling and ATT&amp;CK mapping.
        </p>
      </div>
    )
  }

  const techniques = session.mitre_techniques || []
  const tactics = session.mitre_tactics || []

  return (
    <div className="flex h-full flex-col overflow-y-auto">
      <header className="flex items-start justify-between gap-3 px-4 pb-3 pt-4">
        <div className="min-w-0">
          <h2 className="readout truncate text-[17px] font-semibold text-paper">
            {session.attacker_ip}
          </h2>
          <p className="readout mt-1 truncate text-[11px] text-paper-3">
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

      <div className="flex flex-wrap gap-1.5 px-4 pb-3.5">
        <CategoryTag category={session.attack_category} />
        {session.is_anomalous && (
          <span className="tag" style={{ color: 'var(--color-s4)' }}>Anomalous</span>
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
            {session.scanner_operator} scanner
          </span>
        )}
      </div>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-3 border-t border-line px-4 py-3.5">
        <Fact label="Origin" mono={false}>
          {session.geo?.country_name || session.geo?.country || 'Unknown'}
        </Fact>
        <Fact label="Protocol">
          <span className="uppercase">{session.protocol || '—'}</span>
        </Fact>
        <Fact label="Duration">{duration(session.duration_seconds)}</Fact>
        <Fact label="Status" mono={false}>
          <span className="capitalize">{session.status}</span>
        </Fact>
        <Fact label="Started" mono>
          {new Date(session.started_at).toLocaleString()}
        </Fact>
        <Fact label="Commands">{session.command_count ?? 0}</Fact>
      </dl>

      {Object.keys(session.capture_dropped || {}).length > 0 && (
        <Block title="Capture limits reached">
          <p className="text-[12px] leading-relaxed text-paper-2">
            This session exceeded capture limits. Retained evidence is incomplete.
          </p>
          <dl className="mt-2 space-y-1 text-[12px] text-paper-3">
            {Object.entries(session.capture_dropped).map(([kind, count]) => (
              <div key={kind} className="flex justify-between gap-3">
                <dt className="capitalize">{kind.replaceAll('_', ' ')} omitted</dt>
                <dd className="readout">{count.toLocaleString()}</dd>
              </div>
            ))}
          </dl>
        </Block>
      )}

      <RelatedActivity key={`r${session.id}`} sessionId={session.id} />

      <Block title="Model verdict" note={MODEL_SOURCE_NOTE[session.model_source]}>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
          <Fact label="Confidence">{percent(session.attack_confidence)}</Fact>
          <Fact label="Anomaly score">
            {typeof session.anomaly_score === 'number'
              ? session.anomaly_score.toFixed(3)
              : '—'}
          </Fact>
        </dl>
        {session.model_source === 'synthetic' && (
          <p className="mt-2.5 text-[12px] leading-relaxed text-paper-3">
            This classifier has not been trained on captured traffic. Treat the
            confidence above as a placeholder, not a measurement.
          </p>
        )}
        {session.cluster?.fitted && (
          <p className="mt-2.5 text-[12px] leading-relaxed text-paper-3">
            Behaviourally grouped with cluster {session.cluster.cluster}
            {session.cluster.is_outlier
              ? ' — but far from its centre, so this session resembles nothing seen before.'
              : '.'}
          </p>
        )}
      </Block>

      {session.command_summary && (
        <Block title="Summary">
          <p className="whitespace-pre-line text-[13px] leading-relaxed text-paper-2">
            {session.command_summary.slice(0, 600)}
          </p>
        </Block>
      )}

      <Block title="Tools detected">
        <TagRow
          items={session.detected_tools}
          color="var(--color-s3)"
          empty="None detected."
          transform={(t) => t.replace(/_/g, ' ')}
        />
      </Block>

      <Block title="Intents">
        <TagRow
          items={session.detected_intents}
          color="var(--color-s2)"
          empty="None inferred."
          transform={(t) => t.replace(/_/g, ' ')}
        />
      </Block>

      {(techniques.length > 0 || tactics.length > 0) && (
        <Block
          title="MITRE ATT&CK"
          note={
            tactics.length
              ? tactics.map((t) => (typeof t === 'string' ? t : t.name)).join(' · ')
              : undefined
          }
        >
          <ul className="space-y-1">
            {techniques.map((technique) => (
              <li key={technique.id}>
                <a
                  href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="group flex items-baseline gap-2 rounded-[3px] px-1.5 py-1 -mx-1.5 transition-colors hover:bg-ink-2"
                >
                  <span className="readout shrink-0 text-[12px] text-paper-2">
                    {technique.id}
                  </span>
                  <span className="min-w-0 flex-1 text-[13px] text-paper">
                    {technique.name}
                  </span>
                  {technique.source === 'chimera' && (
                    <span
                      className="shrink-0 text-[11px]"
                      style={{ color: 'var(--color-s2)' }}
                      title="Inferred by the language model, not matched by the rule map"
                    >
                      inferred
                    </span>
                  )}
                  <ExternalLink
                    className="h-3 w-3 shrink-0 text-paper-3 opacity-0 transition-opacity group-hover:opacity-100"
                    strokeWidth={2}
                  />
                </a>
              </li>
            ))}
          </ul>
        </Block>
      )}

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
                {file}
              </li>
            ))}
          </ul>
        </Block>
      )}
    </div>
  )
}
