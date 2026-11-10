import { useCallback, useEffect, useState } from 'react'
import { KeyRound, Plus, ShieldOff, UserCheck, UserX } from 'lucide-react'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import EmptyState from './EmptyState'
import ErrorBanner from './ErrorBanner'
import { LoadingRegion } from './Loading'
import Secret from './Secret'
import Timestamp from './Timestamp'
import { cleanLine } from '../lib/text'

/*
 * Accounts.
 *
 * Sign-up verifies the address by email, and a deployment without a mail
 * provider cannot send one, so the only way to add an analyst was a curl
 * against the admin endpoint. This is that endpoint with a form in front of
 * it, plus the things an administrator is asked for when someone loses a
 * phone or leaves: reset the authenticator, set a temporary password, switch
 * the account off.
 *
 * Temporary passwords are hidden until asked for and can be copied without
 * being shown, so creating an account in front of a room discloses nothing.
 */

const ROLES = ['viewer', 'analyst', 'admin']
const ROLE_HINT = {
  viewer: 'Reads everything, changes nothing.',
  analyst: 'Triages alerts, exports evidence, queues analysis.',
  admin: 'Everything, including accounts, mode and credentials.',
}

const MIN_PASSWORD = 12

function randomPassword(length = 20) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_!#%'
  const bytes = new Uint32Array(length)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
}

function Panel({ title, description, action, children }) {
  return (
    <section className="panel" id="accounts">
      <div className="panel-head">
        <div>
          <h2 className="text-base font-semibold text-paper">{title}</h2>
          {description && <p className="mt-0.5 max-w-xl text-[13px] text-paper-3">{description}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}

function CreateForm({ onCreate, onCancel }) {
  const [form, setForm] = useState({ email: '', name: '', role: 'analyst', password: randomPassword() })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await onCreate(form)
    } catch (err) {
      setError(err.message || 'Could not create the account')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3 border-b border-line bg-ink-0/40 p-4">
      <div className="grid gap-3 sm:grid-cols-4">
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Email</span>
          <input type="email" required value={form.email} className="field"
            onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder="analyst@soc.internal" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Name</span>
          <input type="text" value={form.name} className="field"
            onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </label>
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Role</span>
          <select value={form.role} className="control capitalize"
            onChange={(e) => setForm({ ...form, role: e.target.value })}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Temporary password</span>
          <input type="password" autoComplete="new-password" required minLength={MIN_PASSWORD} value={form.password} className="field readout"
            onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </label>
      </div>
      <p className="text-[12px] text-paper-3">
        {ROLE_HINT[form.role]} A password has been generated; it can be revealed or copied once the
        account exists. Hand it over out of band and ask them to change it from Settings.
      </p>
      {error && <p className="text-[13px]" style={{ color: 'var(--color-s4)' }}>{error}</p>}
      <div className="flex items-center gap-2">
        <button type="submit" className="control control-primary" disabled={busy || !form.email || form.password.length < MIN_PASSWORD}>
          {busy ? 'Creating…' : 'Create account'}
        </button>
        <button type="button" onClick={onCancel} className="text-[13px] font-medium text-paper-2 hover:text-paper">Cancel</button>
      </div>
    </form>
  )
}

function UserRow({ user, me, onAction }) {
  const [busy, setBusy] = useState(null)
  const [reveal, setReveal] = useState(null)
  const [error, setError] = useState(null)
  const isMe = me?.id === user.id

  const act = async (name, fn) => {
    setBusy(name)
    setError(null)
    try {
      await fn()
    } catch (err) {
      setError(err.message || 'That did not work')
    } finally {
      setBusy(null)
    }
  }

  const resetPassword = () => {
    if (!window.confirm(`Set a new temporary password for ${user.email}? Their current password stops working.`)) return
    const password = randomPassword()
    act('password', async () => {
      await onAction('resetPassword', user, password)
      setReveal(password)
    })
  }

  const resetMfa = () => {
    if (!window.confirm(`Remove the authenticator from ${user.email}? They sign in with their password alone until they enrol again.`)) return
    act('mfa', () => onAction('resetMfa', user))
  }

  const toggleActive = () => {
    const next = !user.is_active
    if (!next && !window.confirm(`Deactivate ${user.email}? They are signed out at their next request and cannot sign in again until reactivated.`)) return
    act('active', () => onAction('setActive', user, next))
  }

  return (
    <div className="border-b border-line px-4 py-3 last:border-0" data-testid="user-row">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="min-w-48 flex-1">
          <p className="text-sm font-semibold text-paper">
            {cleanLine(user.email)}
            {isMe && <span className="ml-2 text-[12px] font-normal text-paper-3">you</span>}
          </p>
          <p className="mt-0.5 text-[12px] text-paper-3">
            {user.name ? `${cleanLine(user.name)} · ` : ''}
            {user.last_login ? <>last sign-in <Timestamp value={user.last_login} style="date" /></> : 'never signed in'}
            {user.totp_enabled ? ' · authenticator on' : ''}
          </p>
        </div>

        <label className="flex items-center gap-2">
          <span className="eyebrow">Role</span>
          <select
            value={user.role}
            disabled={isMe || busy !== null}
            aria-label={`Role for ${user.email}`}
            className="control capitalize"
            onChange={(e) => act('role', () => onAction('setRole', user, e.target.value))}
          >
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>

        <span className="tag" style={{ color: user.is_active ? 'var(--color-s1)' : 'var(--color-paper-3)' }}>
          {user.is_active ? 'Active' : 'Deactivated'}
        </span>

        <div className="flex items-center gap-1.5">
          <button type="button" className="control gap-1.5" onClick={resetPassword} disabled={busy !== null} title="Set a temporary password">
            <KeyRound className="h-3.5 w-3.5" strokeWidth={2} />
            Reset password
          </button>
          {user.totp_enabled && (
            <button type="button" className="control gap-1.5" onClick={resetMfa} disabled={busy !== null} title="Remove the authenticator">
              <ShieldOff className="h-3.5 w-3.5" strokeWidth={2} />
              Reset MFA
            </button>
          )}
          {!isMe && (
            <button type="button" className="control gap-1.5" onClick={toggleActive} disabled={busy !== null}>
              {user.is_active
                ? <><UserX className="h-3.5 w-3.5" strokeWidth={2} />Deactivate</>
                : <><UserCheck className="h-3.5 w-3.5" strokeWidth={2} />Reactivate</>}
            </button>
          )}
        </div>
      </div>
      {reveal && (
        <p className="mt-2 rounded-[3px] border border-line bg-ink-2 px-3 py-2 text-[13px] text-paper">
          Temporary password for {cleanLine(user.email)}:{' '}
          <Secret value={reveal} label="temporary password" />
          <span className="block text-[12px] text-paper-3">
            Available until you leave this page. Copy it now; it cannot be read again later.
          </span>
        </p>
      )}
      {error && <p className="mt-2 text-[13px]" style={{ color: 'var(--color-s4)' }}>{error}</p>}
    </div>
  )
}

export default function UsersPanel({ signupAvailable = false }) {
  const { user: me } = useAuth()
  const [users, setUsers] = useState(null)
  const [error, setError] = useState(null)
  const [creating, setCreating] = useState(false)
  const [created, setCreated] = useState(null)

  const load = useCallback(async () => {
    try {
      const rows = await api.auth.users.list()
      setUsers(Array.isArray(rows) ? rows : [])
      setError(null)
    } catch (err) {
      setError(err.message || 'Could not load accounts')
    }
  }, [])

  useEffect(() => {
    const timer = setTimeout(load, 0)
    return () => clearTimeout(timer)
  }, [load])

  const create = async (form) => {
    const row = await api.auth.users.create(form)
    setCreated({ email: row?.email || form.email, password: form.password })
    setCreating(false)
    await load()
  }

  const onAction = async (name, target, value) => {
    if (name === 'setRole') await api.auth.users.setRole(target.id, value)
    else if (name === 'setActive') await api.auth.users.update(target.id, { is_active: value })
    else if (name === 'resetMfa') await api.auth.users.resetMfa(target.id)
    else if (name === 'resetPassword') await api.auth.users.resetPassword(target.id, value)
    await load()
  }

  return (
    <Panel
      title="Accounts"
      description={signupAvailable
        ? 'Who can sign in to this console. People can also request an account from the sign-in page; it is confirmed by a code sent to their address.'
        : 'Who can sign in to this console. Self sign-up is off because this deployment has no mail provider to confirm an address with, so administrators create accounts here.'}
      action={
        <button type="button" onClick={() => setCreating((o) => !o)} className="control flex shrink-0 items-center gap-1.5">
          <Plus className="h-3.5 w-3.5" strokeWidth={2} />
          New account
        </button>
      }
    >
      {error && <div className="p-3"><ErrorBanner message={error} onRetry={load} /></div>}
      {creating && <CreateForm onCreate={create} onCancel={() => setCreating(false)} />}
      {created && (
        <div className="border-b border-line bg-ink-2 px-4 py-3 text-[13px] text-paper" role="status">
          Account created for <span className="readout">{cleanLine(created.email)}</span>. Temporary password:{' '}
          <Secret value={created.password} label="temporary password" />
          <span className="block text-[12px] text-paper-3">
            Available until dismissed. Hand it over out of band; they should change it after signing in.
          </span>
          <button type="button" className="control mt-2" onClick={() => setCreated(null)}>Dismiss</button>
        </div>
      )}
      {users === null && !error ? (
        <LoadingRegion label="Loading accounts" className="py-10" />
      ) : users?.length === 0 ? (
        <EmptyState title="No accounts" hint="Create the first analyst account above." />
      ) : (
        (users || []).map((u) => <UserRow key={u.id} user={u} me={me} onAction={onAction} />)
      )}
    </Panel>
  )
}

/** Every user can change their own password. */
export function ChangePasswordPanel({ resetByMail = false }) {
  const { endSession } = useAuth()
  const [form, setForm] = useState({ current: '', next: '', confirm: '' })
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState(null)
  const [error, setError] = useState(null)

  const submit = async (e) => {
    e.preventDefault()
    setError(null)
    setMessage(null)
    if (form.next.length < MIN_PASSWORD) {
      setError(`Use at least ${MIN_PASSWORD} characters.`)
      return
    }
    if (form.next !== form.confirm) {
      setError('The new passwords do not match.')
      return
    }
    setBusy(true)
    try {
      await api.auth.changePassword(form.current, form.next)
      setForm({ current: '', next: '', confirm: '' })
      setMessage('Password changed.')
      // The API signs the account out everywhere when its password changes,
      // this session included. Leave now, with the reason, rather than be
      // thrown out by the next request with "session expired".
      endSession('Password changed. Sign in again with the new password.')
    } catch (err) {
      setError(err.message || 'Could not change the password')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2 className="text-base font-semibold text-paper">Change my password</h2>
          <p className="mt-0.5 max-w-xl text-[13px] text-paper-3">
            Changing it signs you out everywhere, here included.{' '}
            {resetByMail
              ? 'A forgotten password can be reset from the sign-in page.'
              : 'This deployment cannot reset a password by e-mail; a forgotten one has to be reset by an administrator.'}
          </p>
        </div>
      </div>
      <form onSubmit={submit} className="grid gap-3 p-4 sm:grid-cols-3">
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Current password</span>
          <input type="password" autoComplete="current-password" required value={form.current} className="field"
            onChange={(e) => setForm({ ...form, current: e.target.value })} />
        </label>
        <label className="flex flex-col gap-1">
          <span className="eyebrow">New password</span>
          <input type="password" autoComplete="new-password" required minLength={MIN_PASSWORD} value={form.next} className="field"
            onChange={(e) => setForm({ ...form, next: e.target.value })} />
        </label>
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Repeat new password</span>
          <input type="password" autoComplete="new-password" required value={form.confirm} className="field"
            onChange={(e) => setForm({ ...form, confirm: e.target.value })} />
        </label>
        <div className="flex items-center gap-3 sm:col-span-3">
          <button type="submit" className="control control-primary" disabled={busy}>
            {busy ? 'Saving…' : 'Change password'}
          </button>
          {message && <span className="text-[13px] text-paper-2" role="status">{message}</span>}
          {error && <span className="text-[13px]" style={{ color: 'var(--color-s4)' }}>{error}</span>}
        </div>
      </form>
    </section>
  )
}
