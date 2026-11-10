import { useCallback, useState } from 'react'
import { AlertTriangle, ChevronDown, Download, Eye, Loader2, Play, Shuffle } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { SECRET_MASK, useSecretsHidden } from '../hooks/useSecretsHidden'
import { diversionOf } from '../lib/diversion'
import { clean, cleanLine } from '../lib/text'
import { plural } from '../lib/format'
import { LINE_STEP, WINDOW_LINE_BUDGET, windowTranscript } from '../lib/transcript'
import SessionReplay from './SessionReplay'
import Timestamp from './Timestamp'
import TranscriptEntry from './TranscriptEntry'

/** Protocols whose transcript is an interactive shell, and so worth replaying on a clock. */
const SHELL_PROTOCOLS = new Set(['ssh', 'telnet'])

/*
 * The transcript.
 *
 * Every session has held one since the pipeline was written — captured,
 * encrypted, stored, and read by nothing. This is the primary evidence a
 * honeypot produces and it was the one thing the interface could not show.
 *
 * Fetched on demand rather than with the session: the list view carries
 * hundreds of sessions and none of them need a decrypted transcript in hand
 * before someone asks to read one.
 */

/** The transcript as a window of commands, extended on request. */
function TranscriptWindow({ entries, truncated }) {
  const [budget, setBudget] = useState(WINDOW_LINE_BUDGET)
  const [allowances, setAllowances] = useState({})

  const { rows, hiddenEntries } = windowTranscript(entries, { budget, allowances })

  const moreOf = (index, shown) => {
    setAllowances((current) => ({ ...current, [index]: shown + LINE_STEP }))
    // An output the reader asked for must not be cut off by the total.
    setBudget((current) => current + LINE_STEP)
  }

  return (
    <>
      <div className="readout max-h-[26rem] overflow-y-auto rounded-[4px] border border-line bg-ink-0 p-3 text-[12px] leading-[1.6]">
        <div className="space-y-2">
          {rows.map((row) => (
            <TranscriptEntry
              key={row.index}
              entry={row.entry}
              index={row.index}
              lines={row.lines}
              hiddenLines={row.hiddenLines}
              onMore={() => moreOf(row.index, row.lines.length)}
            />
          ))}
        </div>
        {hiddenEntries > 0 && (
          <button
            type="button"
            onClick={() => setBudget((current) => current + LINE_STEP)}
            className="control mt-3"
          >
            Show more commands ({hiddenEntries.toLocaleString()} of {entries.length.toLocaleString()} not shown)
          </button>
        )}
      </div>
      {truncated && (
        <p className="mt-2 text-[12px] text-paper-3">
          The API returned the first {entries.length} commands; the session recorded more.
        </p>
      )}
    </>
  )
}

/*
 * Mounted with key={session.id} by the parent, so moving between sessions
 * remounts this and the open/loaded state resets on its own. Resetting it in
 * an effect instead would leave the previous session's commands on screen for
 * a render, under the new session's header.
 */
export default function SessionTranscript({ session }) {
  const sessionId = session?.id
  const [open, setOpen] = useState(false)
  const [mode, setMode] = useState('read')
  const [state, setState] = useState({ status: 'idle', data: null, error: null })

  const load = useCallback(async () => {
    setState({ status: 'loading', data: null, error: null })
    try {
      const data = await api.sessions.transcript(sessionId)
      setState({ status: 'ready', data, error: null })
    } catch (err) {
      setState({
        status: 'error',
        data: null,
        error: err.message || 'Could not load transcript',
      })
    }
  }, [sessionId])

  if (!session?.has_transcript && !session?.command_count) return null

  const toggle = () => {
    const next = !open
    setOpen(next)
    if (next && state.status === 'idle') load()
  }

  const entries = state.data?.entries || []
  const canReplay = SHELL_PROTOCOLS.has(String(session.protocol || '').toLowerCase())

  return (
    <section className="border-t border-line" data-testid="transcript-block">
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        className="flex w-full items-baseline justify-between gap-3 px-4 py-3.5 text-left transition-colors hover:bg-ink-2"
      >
        <span className="eyebrow">Transcript</span>
        <span className="flex items-baseline gap-2 text-[12px] text-paper-3">
          {plural(session.command_count, 'command')}
          <ChevronDown
            className={`h-3.5 w-3.5 shrink-0 self-center transition-transform ${open ? 'rotate-180' : ''}`}
            strokeWidth={2}
          />
        </span>
      </button>

      {open && (
        <div className="px-4 pb-4">
          {state.status === 'loading' && (
            <p className="flex items-center gap-2 py-3 text-[13px] text-paper-3" aria-live="polite">
              <Loader2 className="h-3.5 w-3.5 animate-spin" strokeWidth={2} />
              Decrypting…
            </p>
          )}

          {state.status === 'error' && (
            <div className="py-3" role="alert">
              <p className="text-[13px]" style={{ color: 'var(--color-s4)' }}>
                The transcript could not be loaded: {state.error}
              </p>
              <button type="button" className="control mt-2" onClick={load}>Try again</button>
            </div>
          )}

          {state.status === 'ready' && !state.data.available && (
            <p className="py-3 text-[13px] text-paper-3">
              No commands were recorded for this session.
            </p>
          )}

          {state.status === 'ready' && state.data.available && (
            <>
              {canReplay && (
                <div className="mb-2.5 inline-flex overflow-hidden rounded-[3px] border border-line" role="group" aria-label="Transcript view">
                  {[['read', 'Read'], ['replay', 'Replay']].map(([id, label]) => (
                    <button
                      key={id}
                      type="button"
                      aria-pressed={mode === id}
                      onClick={() => setMode(id)}
                      className={`flex items-center gap-1.5 px-2.5 py-1 text-[12px] font-medium transition-colors ${
                        mode === id ? 'bg-paper text-ink-0' : 'bg-ink-2 text-paper-2 hover:text-paper'
                      }`}
                    >
                      {id === 'replay' && <Play className="h-3 w-3" strokeWidth={2} aria-hidden="true" />}
                      {label}
                    </button>
                  ))}
                </div>
              )}
              {canReplay && mode === 'replay'
                ? <SessionReplay entries={entries} />
                : <TranscriptWindow entries={entries} truncated={state.data.truncated} />}
            </>
          )}
        </div>
      )}
    </section>
  )
}

/*
 * Retrieval and execution.
 *
 * The emulator used to answer wget and curl with "command not found", which
 * ended every dropper one line in — before it named its C2. It now lets the
 * fetch appear to succeed without making any request, so the URL, the payload
 * name and the attempt to run it are all observed. This is where they land.
 */
export function RetrievalBlock({ session }) {
  const events = session?.network_events || []
  const downloads = events.filter((e) => e.event_type === 'file_download')
  const executions = events.filter((e) => e.event_type === 'payload_execution')
  if (!downloads.length && !executions.length) return null

  return (
    <section className="border-t border-line px-4 py-3.5">
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="eyebrow">Retrieval</h3>
        <span className="text-[12px] text-paper-3">
          nothing was fetched or run
        </span>
      </div>

      <ul className="mt-2.5 space-y-2.5">
        {downloads.map((event, i) => (
          <li key={`d${i}`} className="min-w-0">
            <div className="flex items-baseline gap-2">
              <Download
                className="h-3 w-3 shrink-0 self-center"
                strokeWidth={2}
                style={{ color: 'var(--color-s3)' }}
              />
              <span className="readout bidi-isolate min-w-0 flex-1 break-all text-[12px] text-paper">
                {cleanLine(event.url)}
              </span>
            </div>
            <div className="mt-1 flex flex-wrap items-baseline gap-x-3 gap-y-1 pl-5 text-[12px] text-paper-3">
              <span className="readout">{cleanLine(event.tool) || 'fetch'}</span>
              {event.filename && <span className="readout">{cleanLine(event.filename)}</span>}
              {event.piped_to_shell && (
                <span className="tag" style={{ color: 'var(--color-s4)' }}>
                  piped to shell
                </span>
              )}
            </div>
          </li>
        ))}

        {executions.map((event, i) => (
          <li key={`x${i}`} className="flex items-baseline gap-2">
            <Play
              className="h-3 w-3 shrink-0 self-center"
              strokeWidth={2}
              style={{ color: 'var(--color-s4)' }}
            />
            <span className="readout bidi-isolate min-w-0 flex-1 break-all text-[12px] text-paper">
              {cleanLine(event.path)}
            </span>
            <span className="shrink-0 text-[12px] text-paper-3">attempted</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

/*
 * Diversion to the decoy application.
 *
 * With a decoy copy of the website configured, a client that gives itself
 * away as an attacker is answered by the copy from then on. This says why,
 * and since when: the reason may come from an earlier connection, which is
 * why a session of ordinary-looking requests can carry it.
 */
export function DiversionBlock({ session }) {
  const event = diversionOf(session)
  if (!event) return null

  return (
    <section className="border-t border-line px-4 py-3.5">
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="eyebrow">Decoy application</h3>
        <span className="text-[12px] text-paper-3">the live site was not reached</span>
      </div>
      <div className="mt-2.5 flex items-baseline gap-2">
        <Shuffle
          className="h-3 w-3 shrink-0 self-center"
          strokeWidth={2}
          style={{ color: 'var(--color-s3)' }}
        />
        <span className="min-w-0 flex-1 text-[12px] text-paper">
          Diverted: {clean(event.reason) || 'earlier attack'}
        </span>
      </div>
      <div className="mt-1 flex flex-wrap items-baseline gap-x-3 gap-y-1 pl-5 text-[12px] text-paper-3">
        {event.path && <span className="readout bidi-isolate break-all">{cleanLine(event.path)}</span>}
        {event.since && (
          <span className="readout">
            since <Timestamp value={event.since * 1000} />
          </span>
        )}
      </div>
      <p className="mt-2 text-[12px] text-paper-3">
        Requests before the first diverted one were answered by the live site; the transcript marks each one the decoy answered.
      </p>
    </section>
  )
}

/*
 * Captured credentials.
 *
 * Admin-only, and hidden until asked for. These are passwords in active
 * circulation against real hosts; the server records every read, and putting
 * them on screen by default would mean a shoulder-surf is a breach. In
 * presentation mode the passwords stay masked even after Reveal.
 */
export function CredentialsBlock({ session }) {
  const { hasRole } = useAuth()
  const masked = useSecretsHidden()
  const sessionId = session?.id
  const [state, setState] = useState({ status: 'idle', rows: [], error: null })

  if (!session?.has_credentials || !hasRole('admin')) return null

  const reveal = async () => {
    setState({ status: 'loading', rows: [], error: null })
    try {
      const data = await api.sessions.credentials(sessionId)
      setState({ status: 'ready', rows: data.credentials || [], error: null })
    } catch (err) {
      setState({ status: 'error', rows: [], error: err.message || 'Could not load' })
    }
  }

  return (
    <section className="border-t border-line px-4 py-3.5" data-testid="credentials-block">
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="eyebrow">Credentials tried</h3>
        <span className="flex items-center gap-1 text-[12px] text-paper-3">
          <AlertTriangle className="h-3 w-3" strokeWidth={2} />
          access logged
        </span>
      </div>

      {state.status === 'idle' && (
        <>
          <button type="button" onClick={reveal} className="control mt-2.5 gap-1.5">
            <Eye className="h-3.5 w-3.5" strokeWidth={2} />
            Reveal
          </button>
          <p className="mt-1.5 text-[12px] leading-relaxed text-paper-3">
            {masked
              ? 'Presentation mode is on: the usernames will be shown and the passwords kept masked. The read is still recorded in the audit log.'
              : 'Shows the usernames and passwords this session tried. The read is recorded in the audit log.'}
          </p>
        </>
      )}

      {state.status === 'loading' && (
        <p className="mt-2.5 text-[13px] text-paper-3">Decrypting…</p>
      )}

      {state.status === 'error' && (
        <p className="mt-2.5 text-[13px]" style={{ color: 'var(--color-s4)' }} role="alert">
          The credentials could not be loaded: {state.error}
        </p>
      )}

      {state.status === 'ready' && state.rows.length === 0 && (
        <p className="mt-2.5 text-[13px] text-paper-3">No credentials are stored for this session.</p>
      )}

      {state.status === 'ready' && state.rows.length > 0 && (
        <>
          {masked && (
            <p className="mt-2.5 text-[12px] text-paper-2">
              Passwords are masked while presentation mode is on.
            </p>
          )}
          <ul className="readout mt-2.5 space-y-1 text-[12px]">
            {state.rows.map((row, i) => (
              <li key={i} className="flex items-baseline gap-2">
                <span
                  aria-hidden
                  className="h-1 w-1 shrink-0 rounded-full"
                  style={{
                    background: row.success
                      ? 'var(--color-s4)'
                      : 'var(--color-paper-3)',
                  }}
                />
                <span className="bidi-isolate min-w-0 flex-1 break-all text-paper">
                  {cleanLine(row.username)}
                  <span className="text-paper-3"> : </span>
                  {masked
                    ? <span aria-label="password hidden">{SECRET_MASK}</span>
                    : cleanLine(row.password)}
                </span>
                {row.success && (
                  <span className="shrink-0 text-[12px]" style={{ color: 'var(--color-s4)' }}>
                    accepted
                  </span>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  )
}
