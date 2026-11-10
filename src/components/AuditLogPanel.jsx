import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import { usePreferences } from '../context/usePreferences'
import { useDebounced } from '../hooks/useDebounced'
import { usePolledResource } from '../hooks/usePolledResource'
import { cleanLine } from '../lib/text'
import { fromInputValue, toInputValue } from '../lib/time'
import EmptyState from './EmptyState'
import { LoadFailure, StaleNotice } from './LoadState'
import { LoadingRegion } from './Loading'
import Timestamp from './Timestamp'

/*
 * Audit log.
 *
 * Every privileged action writes a row: sign-ins and failures, role changes,
 * credential reveals, exports, blocks, mode changes. The rows have been
 * written since the first release and nothing in the console could read
 * them, so the answer to "who revealed these passwords" needed a database
 * shell. Administrators only; the API enforces that.
 */

const PAGE_SIZE = 50

/** A row's `details` on one line. It can hold anything the API chose to record. */
function describeDetails(details) {
  if (details === null || details === undefined || details === '') return ''
  if (typeof details === 'string') return details
  try {
    return Object.entries(details)
      .map(([key, value]) => `${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}`)
      .join(' · ')
  } catch {
    return String(details)
  }
}

function resource(entry) {
  if (!entry.resource_type) return '—'
  const type = String(entry.resource_type).replace(/_/g, ' ')
  return entry.resource_id != null ? `${type} ${entry.resource_id}` : type
}

export default function AuditLogPanel() {
  const { zone, zoneLabel } = usePreferences()
  const [action, setAction] = useState('')
  const [userId, setUserId] = useState('')
  const [since, setSince] = useState('')
  const [offset, setOffset] = useState(0)

  const debouncedAction = useDebounced(action.trim())
  const debouncedUser = useDebounced(userId.trim())
  const validUser = /^[1-9]\d*$/.test(debouncedUser) ? debouncedUser : ''

  const params = { limit: PAGE_SIZE, offset }
  if (debouncedAction) params.action = debouncedAction
  if (validUser) params.user_id = validUser
  if (since) params.since = since

  const log = usePolledResource(
    async ({ signal }) => {
      const data = await api.auditLogs.list(params, { signal })
      return { items: data.items || [], total: data.total || 0 }
    },
    { key: JSON.stringify(params) },
  )
  const items = log.data?.items ?? []
  const total = log.data?.total ?? 0
  const filtered = Boolean(debouncedAction || validUser || since)

  // Changing a filter starts again from the newest row.
  const change = (setter) => (value) => {
    setter(value)
    setOffset(0)
  }

  return (
    <section className="panel" id="audit" aria-labelledby="audit-heading" data-testid="audit-log">
      <div className="panel-head">
        <div>
          <h2 id="audit-heading" className="text-base font-semibold text-paper">Audit log</h2>
          <p className="mt-0.5 max-w-xl text-[13px] text-paper-3">
            Who did what: sign-ins, account changes, credential reveals, exports, blocks and mode
            changes. Newest first.
          </p>
        </div>
        <button type="button" className="control" onClick={log.reload} aria-label="Refresh audit log">
          <RefreshCw className={`h-3.5 w-3.5 ${log.refreshing ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <div className="flex flex-wrap items-end gap-3 border-t border-line px-4 py-3">
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Action</span>
          <input
            type="search"
            value={action}
            onChange={(e) => change(setAction)(e.target.value)}
            placeholder="credentials_viewed"
            title="The exact action name, as shown in the Action column"
            className="field w-52"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="eyebrow">User id</span>
          <input
            type="text"
            inputMode="numeric"
            value={userId}
            onChange={(e) => change(setUserId)(e.target.value)}
            placeholder="1"
            className={`field w-24 ${userId.trim() && !/^[1-9]\d*$/.test(userId.trim()) ? 'field-invalid' : ''}`}
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Since ({zoneLabel()})</span>
          <input
            type="datetime-local"
            value={toInputValue(since, zone)}
            onChange={(e) => change(setSince)(fromInputValue(e.target.value, zone))}
            className="field"
          />
        </label>
        {filtered && (
          <button
            type="button"
            className="pb-2 text-[13px] font-medium text-paper-2 transition-colors hover:text-paper"
            onClick={() => { setAction(''); setUserId(''); setSince(''); setOffset(0) }}
          >
            Reset
          </button>
        )}
        {log.data && (
          <p className="ml-auto pb-2 text-[12px] text-paper-3">
            {total.toLocaleString()} entr{total === 1 ? 'y' : 'ies'}
          </p>
        )}
      </div>

      {log.stale && (
        <div className="px-4 pb-3">
          <StaleNotice what="The audit log" error={log.error} loadedAt={log.loadedAt} onRetry={log.reload} />
        </div>
      )}

      {log.loading ? (
        <LoadingRegion label="Loading the audit log" className="py-10" />
      ) : log.failed ? (
        <LoadFailure what="the audit log" error={log.error} onRetry={log.reload} className="px-4 py-8" />
      ) : items.length === 0 ? (
        <EmptyState
          title={filtered ? 'No entries match' : 'No entries yet'}
          hint={filtered
            ? 'The action filter matches the whole action name. Try another filter or reset them.'
            : 'Entries appear as soon as someone signs in or changes something.'}
        />
      ) : (
        <div className={`overflow-x-auto border-t border-line ${log.stale ? 'is-stale' : ''}`}>
          <table className="w-full border-collapse text-left">
            <thead>
              <tr className="border-b border-line">
                <th scope="col" className="eyebrow px-4 py-2 font-normal">When</th>
                <th scope="col" className="eyebrow px-3 py-2 font-normal">Who</th>
                <th scope="col" className="eyebrow px-3 py-2 font-normal">Action</th>
                <th scope="col" className="eyebrow px-3 py-2 font-normal">On</th>
                <th scope="col" className="eyebrow px-3 py-2 font-normal">Details</th>
                <th scope="col" className="eyebrow px-3 py-2 font-normal">From</th>
              </tr>
            </thead>
            <tbody>
              {items.map((entry) => (
                <tr key={entry.id} className="border-b border-line align-top last:border-b-0" data-testid="audit-row">
                  <td className="readout whitespace-nowrap px-4 py-2 text-[12px] text-paper-2">
                    <Timestamp value={entry.created_at} />
                  </td>
                  <td className="px-3 py-2 text-[12px] text-paper">
                    {entry.user_email
                      ? cleanLine(entry.user_email)
                      : entry.user_id != null ? `user ${entry.user_id}` : <span className="text-paper-3">system</span>}
                  </td>
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      className="readout text-left text-[12px] text-paper hover:underline"
                      title="Show only this action"
                      onClick={() => change(setAction)(String(entry.action))}
                    >
                      {cleanLine(String(entry.action))}
                    </button>
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-[12px] text-paper-2">{cleanLine(resource(entry))}</td>
                  <td className="readout max-w-xs break-words px-3 py-2 text-[12px] text-paper-3">
                    {cleanLine(describeDetails(entry.details)) || '—'}
                  </td>
                  <td className="readout whitespace-nowrap px-3 py-2 text-[12px] text-paper-3">
                    {cleanLine(entry.ip_address || '') || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {total > PAGE_SIZE && !log.loading && !log.failed && (
        <div className="flex items-center justify-between border-t border-line px-3 py-2">
          <button
            type="button"
            className="control"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            Newer
          </button>
          <span className="readout text-[12px] text-paper-3">
            {(offset + 1).toLocaleString()}–{Math.min(offset + PAGE_SIZE, total).toLocaleString()} of {total.toLocaleString()}
          </span>
          <button
            type="button"
            className="control"
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            Older
          </button>
        </div>
      )}
    </section>
  )
}
