import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Ban, RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import { usePolledResource } from '../hooks/usePolledResource'
import { networkLabel } from '../lib/origin'
import { cleanLine } from '../lib/text'
import ConfirmDialog from './ConfirmDialog'
import EmptyState from './EmptyState'
import { LoadFailure } from './LoadState'
import { LoadingRegion } from './Loading'

/*
 * Blocking an address.
 *
 * The API has had block and unblock routes since the engine got its control
 * channel, and nothing in the console called them. Blocking is the one
 * action here that changes what an attacker experiences, and it ends the
 * observation of that address, so it asks first and says what it will do.
 *
 * Blocking needs an analyst; unblocking needs an administrator. Both are
 * written to the audit log by the API.
 */

const BLOCKED_POLL_MS = 30000

/** The engine's blocked list as plain strings, whatever shape it arrives in. */
function blockedList(payload) {
  const raw = Array.isArray(payload) ? payload : payload?.blocked_ips
  if (!Array.isArray(raw)) return []
  return raw.map((item) => (typeof item === 'string' ? item : item?.ip)).filter(Boolean).map(String)
}

function useBlockedAddresses() {
  const resource = usePolledResource(
    async ({ signal }) => blockedList(await api.honeypot.blockedIPs({ signal })),
    { key: 'blocked-addresses', intervalMs: BLOCKED_POLL_MS },
  )
  return resource
}

/** Block or unblock one address, from its profile page. */
export function BlockAddressControl({ ip }) {
  const { hasRole } = useAuth()
  const blocked = useBlockedAddresses()
  const [dialog, setDialog] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)

  const canBlock = hasRole('analyst')
  const canUnblock = hasRole('admin')
  const isBlocked = (blocked.data || []).includes(ip)
  const network = networkLabel(ip)
  const address = cleanLine(ip)

  const run = async (action) => {
    setBusy(true)
    setError(null)
    try {
      if (action === 'block') await api.honeypot.blockIP(ip)
      else await api.honeypot.unblockIP(ip)
      setNotice(action === 'block'
        ? `${address} is blocked. The engine refuses its connections.`
        : `${address} is unblocked. The engine accepts its connections again.`)
      setDialog(null)
      await blocked.refresh()
    } catch (err) {
      setError(err.message || 'The engine did not apply the change.')
    } finally {
      setBusy(false)
    }
  }

  if (!canBlock) return null

  return (
    <div className="flex flex-col items-end gap-1" data-testid="block-control">
      <div className="flex items-center gap-2">
        {isBlocked && (
          <span className="tag" style={{ color: 'var(--color-s4)' }} data-testid="blocked-tag">
            <Ban className="h-3 w-3" strokeWidth={2} aria-hidden="true" />
            Blocked
          </span>
        )}
        {isBlocked ? (
          canUnblock ? (
            <button type="button" className="control" onClick={() => { setError(null); setDialog('unblock') }}>
              Unblock address…
            </button>
          ) : (
            <span className="text-[12px] text-paper-3">An administrator can unblock it.</span>
          )
        ) : (
          <button
            type="button"
            className="control"
            onClick={() => { setError(null); setDialog('block') }}
            disabled={blocked.loading}
          >
            <Ban className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />
            Block address…
          </button>
        )}
      </div>
      {blocked.failed && (
        <p className="text-[12px] text-paper-3" role="alert">
          Whether this address is blocked is not known: the engine&rsquo;s block list could not be read.
        </p>
      )}
      {notice && <p className="text-[12px] text-paper-2" role="status">{notice}</p>}

      {dialog === 'block' && (
        <ConfirmDialog
          title={`Block ${address}?`}
          confirmLabel={busy ? 'Blocking…' : 'Block address'}
          busy={busy}
          error={error}
          onConfirm={() => run('block')}
          onCancel={() => setDialog(null)}
        >
          <p>
            Every engine will refuse new connections from this address. From then on the honeypot
            records nothing more about what it does, so block an address only when watching it is
            no longer useful.
          </p>
          {network && (
            <p style={{ color: 'var(--color-s3)' }}>
              This is a {network.toLowerCase()} address, not a public one. Blocking it can cut off
              your own access to the decoys from that network.
            </p>
          )}
          <p>
            The block is held by the engine and lapses after its block period. The action is
            recorded in the audit log under your account. Unblocking needs an administrator.
          </p>
        </ConfirmDialog>
      )}

      {dialog === 'unblock' && (
        <ConfirmDialog
          title={`Unblock ${address}?`}
          confirmLabel={busy ? 'Unblocking…' : 'Unblock address'}
          busy={busy}
          error={error}
          onConfirm={() => run('unblock')}
          onCancel={() => setDialog(null)}
        >
          <p>
            The engines will accept connections from this address again, and its sessions will be
            recorded as before. The action is recorded in the audit log.
          </p>
        </ConfirmDialog>
      )}
    </div>
  )
}

/** Every address the engine is refusing, for Settings. */
export function BlockedAddressesPanel() {
  const { hasRole } = useAuth()
  const blocked = useBlockedAddresses()
  const [target, setTarget] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const canUnblock = hasRole('admin')
  const rows = blocked.data || []

  const unblock = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.honeypot.unblockIP(target)
      setTarget(null)
      await blocked.refresh()
    } catch (err) {
      setError(err.message || 'The engine did not apply the change.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel" id="blocked" aria-labelledby="blocked-heading">
      <div className="panel-head">
        <div>
          <h2 id="blocked-heading" className="text-base font-semibold text-paper">Blocked addresses</h2>
          <p className="mt-0.5 max-w-xl text-[13px] text-paper-3">
            Addresses the engine is refusing. An address is blocked from its profile page; a block
            lapses by itself after the engine&rsquo;s block period.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {blocked.data && <span className="readout text-[12px] text-paper-3">{rows.length} blocked</span>}
          <button type="button" className="control" onClick={blocked.reload} aria-label="Refresh blocked addresses">
            <RefreshCw className={`h-3.5 w-3.5 ${blocked.refreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {blocked.loading ? (
        <LoadingRegion label="Loading blocked addresses" className="py-10" />
      ) : blocked.failed ? (
        <LoadFailure what="the block list" error={blocked.error} onRetry={blocked.reload} className="px-4 py-8" />
      ) : rows.length === 0 ? (
        <EmptyState title="No address is blocked" hint="The engine is accepting connections from everywhere." />
      ) : (
        <ul className={blocked.stale ? 'is-stale' : undefined}>
          {rows.map((ip) => (
            <li key={ip} className="flex items-center gap-3 border-t border-line px-4 py-2.5" data-testid="blocked-row">
              <Link
                to={`/attackers/${encodeURIComponent(ip)}`}
                className="readout min-w-0 flex-1 truncate text-[13px] text-paper hover:underline"
              >
                {cleanLine(ip)}
              </Link>
              {networkLabel(ip) && <span className="text-[12px] text-paper-3">{networkLabel(ip)}</span>}
              {canUnblock ? (
                <button type="button" className="control" onClick={() => { setError(null); setTarget(ip) }}>
                  Unblock…
                </button>
              ) : (
                <span className="text-[12px] text-paper-3">administrators can unblock</span>
              )}
            </li>
          ))}
        </ul>
      )}
      {blocked.stale && (
        <p className="border-t border-line px-4 py-2 text-[12px] text-paper-3" role="alert">
          The last refresh failed ({blocked.error}); this list may be out of date.
        </p>
      )}

      {target && (
        <ConfirmDialog
          title={`Unblock ${cleanLine(target)}?`}
          confirmLabel={busy ? 'Unblocking…' : 'Unblock address'}
          busy={busy}
          error={error}
          onConfirm={unblock}
          onCancel={() => setTarget(null)}
        >
          <p>
            The engines will accept connections from this address again, and its sessions will be
            recorded as before. The action is recorded in the audit log.
          </p>
        </ConfirmDialog>
      )}
    </section>
  )
}
