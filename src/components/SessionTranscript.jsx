import { useCallback, useState } from 'react'
import { AlertTriangle, ChevronDown, Download, Eye, Loader2, Play, Shuffle } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { diversionOf } from '../lib/diversion'

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

/** Lines that reveal infrastructure, marked so the eye finds them first. */
function classifyLine(text) {
  if (/^--\d{4}-\d{2}-\d{2}/.test(text) || /\bHTTP request sent\b/.test(text)) {
    return 'fetch'
  }
  if (/No such file|command not found|Permission denied|denied/i.test(text)) {
    return 'refused'
  }
  return 'plain'
}

const LINE_COLOR = {
  fetch: 'var(--color-s3)',
  refused: 'var(--color-s4)',
  plain: 'var(--color-paper-2)',
}

function Entry({ entry, index }) {
  const lines = (entry.output || '').replace(/\n+$/, '').split('\n')
  return (
    <div className="group">
      <div className="flex items-baseline gap-2">
        <span
          aria-hidden
          className="select-none text-[11px] tabular-nums text-paper-3"
          style={{ minWidth: '2ch', textAlign: 'right' }}
        >
          {index + 1}
        </span>
        <span aria-hidden className="select-none" style={{ color: 'var(--color-s1)' }}>
          $
        </span>
        <span className="min-w-0 flex-1 whitespace-pre-wrap break-all text-paper">
          {entry.command}
        </span>
      </div>
      {entry.output ? (
        <div className="mt-0.5 pl-[calc(2ch+1.25rem)]">
          {lines.map((line, i) => (
            <div
              key={i}
              className="whitespace-pre-wrap break-all"
              style={{ color: LINE_COLOR[classifyLine(line)] }}
            >
              {line || ' '}
            </div>
          ))}
        </div>
      ) : null}
    </div>
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
  const [state, setState] = useState({ status: 'idle', data: null, error: null })

  const load = useCallback(async () => {
    setState((prev) => (prev.status === 'idle' ? { status: 'loading', data: null, error: null } : prev))
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

  return (
    <section className="border-t border-line">
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        className="flex w-full items-baseline justify-between gap-3 px-4 py-3.5 text-left transition-colors hover:bg-ink-2"
      >
        <span className="eyebrow">Transcript</span>
        <span className="flex items-baseline gap-2 text-[12px] text-paper-3">
          {session.command_count || 0} commands
          <ChevronDown
            className={`h-3.5 w-3.5 shrink-0 self-center transition-transform ${open ? 'rotate-180' : ''}`}
            strokeWidth={2}
          />
        </span>
      </button>

      {open && (
        <div className="px-4 pb-4">
          {state.status === 'loading' && (
            <p className="flex items-center gap-2 py-3 text-[13px] text-paper-3">
              <Loader2 className="h-3.5 w-3.5 animate-spin" strokeWidth={2} />
              Decrypting…
            </p>
          )}

          {state.status === 'error' && (
            <p className="py-3 text-[13px]" style={{ color: 'var(--color-s4)' }}>
              {state.error}
            </p>
          )}

          {state.status === 'ready' && !state.data.available && (
            <p className="py-3 text-[13px] text-paper-3">
              No commands were recorded for this session.
            </p>
          )}

          {state.status === 'ready' && state.data.available && (
            <>
              <div className="readout max-h-[26rem] overflow-y-auto rounded-[4px] bg-ink-0 p-3 text-[12px] leading-[1.6]">
                <div className="space-y-2">
                  {entries.map((entry, i) => (
                    <Entry key={i} entry={entry} index={i} />
                  ))}
                </div>
              </div>
              {state.data.truncated && (
                <p className="mt-2 text-[12px] text-paper-3">
                  Showing the first {entries.length} commands; the session recorded more.
                </p>
              )}
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
              <span className="readout min-w-0 flex-1 break-all text-[12px] text-paper">
                {event.url}
              </span>
            </div>
            <div className="mt-1 flex flex-wrap items-baseline gap-x-3 gap-y-1 pl-5 text-[12px] text-paper-3">
              <span className="readout">{event.tool || 'fetch'}</span>
              {event.filename && <span className="readout">{event.filename}</span>}
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
            <span className="readout min-w-0 flex-1 break-all text-[12px] text-paper">
              {event.path}
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
          Diverted: {event.reason || 'earlier attack'}
        </span>
      </div>
      <div className="mt-1 flex flex-wrap items-baseline gap-x-3 gap-y-1 pl-5 text-[12px] text-paper-3">
        {event.path && <span className="readout break-all">{event.path}</span>}
        {event.since && (
          <span className="readout">
            since {new Date(event.since * 1000).toLocaleString()}
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
 * them on screen by default would mean a shoulder-surf is a breach.
 */
export function CredentialsBlock({ session }) {
  const { hasRole } = useAuth()
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
    <section className="border-t border-line px-4 py-3.5">
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="eyebrow">Credentials tried</h3>
        <span className="flex items-center gap-1 text-[12px] text-paper-3">
          <AlertTriangle className="h-3 w-3" strokeWidth={2} />
          access logged
        </span>
      </div>

      {state.status === 'idle' && (
        <button type="button" onClick={reveal} className="control mt-2.5 gap-1.5">
          <Eye className="h-3.5 w-3.5" strokeWidth={2} />
          Reveal
        </button>
      )}

      {state.status === 'loading' && (
        <p className="mt-2.5 text-[13px] text-paper-3">Decrypting…</p>
      )}

      {state.status === 'error' && (
        <p className="mt-2.5 text-[13px]" style={{ color: 'var(--color-s4)' }}>
          {state.error}
        </p>
      )}

      {state.status === 'ready' && (
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
              <span className="min-w-0 flex-1 break-all text-paper">
                {row.username}
                <span className="text-paper-3"> : </span>
                {row.password}
              </span>
              {row.success && (
                <span className="shrink-0 text-[11px]" style={{ color: 'var(--color-s4)' }}>
                  accepted
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
