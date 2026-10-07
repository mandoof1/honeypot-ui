import { useState, useEffect, useCallback } from 'react'
import { Mail, Plus, ShieldCheck, Trash2, Webhook } from 'lucide-react'
import qrcode from 'qrcode-generator'
import { api } from '../services/api'
import { useAuth } from '../context/useAuth'
import ErrorBanner from '../components/ErrorBanner'
import EmptyState from '../components/EmptyState'
import { LoadingRegion } from '../components/Loading'
import { SeverityRail } from '../components/Severity'
import EnginesPanel from '../components/EnginesPanel'
import UsersPanel, { ChangePasswordPanel } from '../components/UsersPanel'
import { SEVERITY_ORDER } from '../lib/severity'

const BLANK_THRESHOLD = {
  name: '',
  min_severity: 'medium',
  // The anomaly score is on a 0–1 scale where the detector's own boundary
  // sits near 0.6; the old default of 0.7 was above anything it ever produced.
  anomaly_score_threshold: 0.6,
  email_enabled: true,
  webhook_enabled: false,
}

function Panel({ title, description, action, children }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2 className="text-base font-semibold text-paper">{title}</h2>
          {description && (
            <p className="mt-0.5 max-w-xl text-[13px] text-paper-3">{description}</p>
          )}
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}

/** Checkbox with its label, used for the two delivery channels. */
function Toggle({ checked, onChange, disabled, icon: Icon, children }) {
  return (
    <label
      className={`flex items-center gap-2 ${disabled ? 'opacity-50' : 'cursor-pointer'}`}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="h-3.5 w-3.5 accent-paper"
      />
      <span className="flex items-center gap-1.5 text-[13px] font-medium text-paper-2">
        <Icon className="h-3.5 w-3.5" strokeWidth={1.75} />
        {children}
      </span>
    </label>
  )
}

/** Shared editor for both creating and editing a threshold. */
function ThresholdForm({ value, onChange, onSubmit, onCancel, submitLabel }) {
  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-3">
        <label className="flex flex-col gap-1">
          <span className="eyebrow">Name</span>
          <input
            type="text"
            value={value.name}
            placeholder="Critical only"
            onChange={(e) => onChange({ ...value, name: e.target.value })}
            className="field"
          />
        </label>

        <label className="flex flex-col gap-1">
          <span className="eyebrow">Alert at or above</span>
          <select
            value={value.min_severity}
            onChange={(e) => onChange({ ...value, min_severity: e.target.value })}
            className="control capitalize"
          >
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="eyebrow">Anomaly score above</span>
          <input
            type="number"
            step="0.05"
            min="0"
            max="1"
            value={value.anomaly_score_threshold}
            onChange={(e) =>
              onChange({
                ...value,
                anomaly_score_threshold: Number.isFinite(parseFloat(e.target.value))
                  ? parseFloat(e.target.value)
                  : 0,
              })
            }
            className="field"
          />
        </label>
      </div>

      <div className="flex flex-wrap items-center gap-5">
        <Toggle
          checked={value.email_enabled}
          onChange={(v) => onChange({ ...value, email_enabled: v })}
          icon={Mail}
        >
          Email
        </Toggle>
        <Toggle
          checked={value.webhook_enabled}
          onChange={(v) => onChange({ ...value, webhook_enabled: v })}
          icon={Webhook}
        >
          Webhook
        </Toggle>
      </div>

      <div className="flex items-center gap-2 pt-1">
        <button
          type="button"
          onClick={onSubmit}
          disabled={!value.name.trim()}
          className="control control-primary"
        >
          {submitLabel}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="text-[13px] font-medium text-paper-2 transition-colors hover:text-paper"
        >
          Cancel
        </button>
      </div>
    </div>
  )
}

function ThresholdRow({ threshold, onUpdate, onDelete, canEdit }) {
  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState(threshold)

  const startEditing = () => {
    setForm(threshold)
    setEditing(true)
  }

  const save = async () => {
    // Stay in the editor on failure, so a rejected change is not lost.
    const ok = await onUpdate(threshold.id, form)
    if (ok) setEditing(false)
  }

  if (editing) {
    return (
      <div className="border-b border-line p-4 last:border-0">
        <ThresholdForm
          value={form}
          onChange={setForm}
          onSubmit={save}
          onCancel={() => setEditing(false)}
          submitLabel="Save changes"
        />
      </div>
    )
  }

  const channels = [
    threshold.email_enabled && 'Email',
    threshold.webhook_enabled && 'Webhook',
  ].filter(Boolean)

  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-line px-4 py-3 last:border-0">
      <div className="min-w-40 flex-1">
        <p className="text-sm font-semibold text-paper">{threshold.name}</p>
        <p className="mt-0.5 text-[13px] text-paper-3">
          {channels.length ? `Notifies by ${channels.join(' and ').toLowerCase()}` : 'No delivery channel selected'}
        </p>
      </div>

      <div>
        <p className="eyebrow">At or above</p>
        <div className="mt-1">
          <SeverityRail level={threshold.min_severity} />
        </div>
      </div>

      <div>
        <p className="eyebrow">Anomaly above</p>
        <p className="readout mt-1 text-sm text-paper">
          {threshold.anomaly_score_threshold}
        </p>
      </div>

      <div className="flex items-center gap-3">
        <span
          className="tag"
          style={{
            color: threshold.is_active
              ? 'var(--color-s1)'
              : 'var(--color-paper-3)',
          }}
        >
          {threshold.is_active ? 'Active' : 'Paused'}
        </span>
        {canEdit && (
          <>
            <button
              type="button"
              onClick={startEditing}
              className="text-[13px] font-medium text-paper-2 transition-colors hover:text-paper"
            >
              Edit
            </button>
            <button
              type="button"
              onClick={() => onDelete(threshold.id)}
              aria-label={`Delete ${threshold.name}`}
              className="text-paper-3 transition-colors hover:text-s4"
            >
              <Trash2 className="h-4 w-4" strokeWidth={1.75} />
            </button>
          </>
        )}
      </div>
    </div>
  )
}

/** The otpauth:// URI as a scannable image, drawn locally: the secret never leaves the page. */
function EnrolmentQR({ uri }) {
  const qr = qrcode(0, 'M')
  qr.addData(uri)
  qr.make()
  return (
    <img
      src={qr.createDataURL(4, 8)}
      alt="Authenticator enrolment QR code"
      className="h-44 w-44 rounded-[3px] bg-white p-1 [image-rendering:pixelated]"
    />
  )
}

/*
 * Two-factor authentication for the signed-in account.
 *
 * The API has enforced TOTP since it was added, but nothing in the UI could
 * enrol an authenticator or send a code at sign-in, so turning it on locked
 * the user out of the dashboard. Enrolment is two steps on purpose: the
 * secret is only activated once a code proves the app holds it.
 */
function TwoFactorPanel() {
  const { user, refreshUser } = useAuth()
  const [step, setStep] = useState('idle') // idle | scanning | done | disabling
  const [enrolment, setEnrolment] = useState(null)
  const [code, setCode] = useState('')
  const [recovery, setRecovery] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const enabled = Boolean(user?.totp_enabled)

  const act = async (fn) => {
    setBusy(true)
    setError(null)
    try {
      await fn()
    } catch (err) {
      setError(err.message || 'Something went wrong')
    } finally {
      setBusy(false)
    }
  }

  const begin = () => act(async () => {
    setEnrolment(await api.auth.mfa.enroll())
    setCode('')
    setStep('scanning')
  })

  const confirm = (e) => {
    e.preventDefault()
    act(async () => {
      const result = await api.auth.mfa.confirm(code.replace(/\s+/g, ''))
      setRecovery(result.recovery_codes || [])
      setEnrolment(null)
      setCode('')
      setStep('done')
      await refreshUser()
    })
  }

  const disable = (e) => {
    e.preventDefault()
    act(async () => {
      await api.auth.mfa.disable(code.replace(/\s+/g, ''))
      setCode('')
      setStep('idle')
      await refreshUser()
    })
  }

  const codeInput = (
    <input
      type="text"
      inputMode="numeric"
      autoComplete="one-time-code"
      placeholder="123 456"
      value={code}
      onChange={(e) => setCode(e.target.value)}
      className="field readout w-40 tracking-[0.2em]"
    />
  )

  return (
    <Panel
      title="Two-factor authentication"
      description="Require a code from an authenticator app at sign-in, on top of the password."
      action={
        <span
          className="tag flex items-center gap-1"
          style={{ color: enabled ? 'var(--color-s1)' : 'var(--color-paper-3)' }}
        >
          <ShieldCheck className="h-3 w-3" strokeWidth={2} />
          {enabled ? 'On' : 'Off'}
        </span>
      }
    >
      <div className="space-y-4 p-4">
        {error && <p className="text-[13px] text-s4">{error}</p>}

        {step === 'done' && recovery.length > 0 && (
          <div className="rounded-[3px] border border-line bg-ink-2 p-4">
            <p className="text-[13px] font-medium text-paper">
              Save these recovery codes now. They are shown once, and each works once.
            </p>
            <p className="mt-1 text-[13px] text-paper-3">
              Password reset needs email, which this deployment does not have, so
              losing both your phone and these codes means losing the account.
            </p>
            <ul className="readout mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-[13px] text-paper sm:grid-cols-4">
              {recovery.map((c) => <li key={c}>{c}</li>)}
            </ul>
            <button
              type="button"
              className="control mt-3"
              onClick={() => navigator.clipboard?.writeText(recovery.join('\n'))}
            >
              Copy all
            </button>
          </div>
        )}

        {!enabled && step !== 'scanning' && (
          <button type="button" className="control control-primary" onClick={begin} disabled={busy}>
            Set up an authenticator
          </button>
        )}

        {step === 'scanning' && enrolment && (
          <form onSubmit={confirm} className="flex flex-col gap-4 sm:flex-row sm:items-start">
            <EnrolmentQR uri={enrolment.otpauth_uri} />
            <div className="min-w-0 space-y-3">
              <p className="text-[13px] text-paper-2">
                Scan the code with Google Authenticator, 1Password, Authy or any
                TOTP app, then enter the six digits it shows.
              </p>
              <p className="text-[12px] text-paper-3">
                Can't scan? Enter this key manually:{' '}
                <span className="readout break-all text-paper">{enrolment.secret}</span>
              </p>
              <div className="flex flex-wrap items-center gap-2">
                {codeInput}
                <button type="submit" className="control control-primary" disabled={busy || !code.trim()}>
                  Turn on
                </button>
                <button type="button" className="control" onClick={() => setStep('idle')} disabled={busy}>
                  Cancel
                </button>
              </div>
            </div>
          </form>
        )}

        {enabled && step !== 'disabling' && step !== 'done' && (
          <button type="button" className="control" onClick={() => { setCode(''); setStep('disabling') }}>
            Turn off
          </button>
        )}

        {enabled && step === 'disabling' && (
          <form onSubmit={disable} className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] text-paper-2">Confirm with a current code or a recovery code:</span>
            {codeInput}
            <button type="submit" className="control" disabled={busy || !code.trim()}>
              Turn off
            </button>
            <button type="button" className="control" onClick={() => setStep('idle')} disabled={busy}>
              Cancel
            </button>
          </form>
        )}
      </div>
    </Panel>
  )
}

export default function Settings() {
  const { hasRole } = useAuth()
  const isAdmin = hasRole('admin')
  const [error, setError] = useState(null)
  const [thresholds, setThresholds] = useState([])
  const [systemConfig, setSystemConfig] = useState(null)
  const [honeypotMode, setHoneypotMode] = useState('active')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [modeNotice, setModeNotice] = useState(null)
  const [creating, setCreating] = useState(false)
  const [newThreshold, setNewThreshold] = useState(BLANK_THRESHOLD)

  const fetchData = useCallback(async () => {
    try {
      const [thresholdsData, configData] = await Promise.all([
        api.settings.thresholds(),
        api.settings.systemConfig(),
      ])
      setThresholds(thresholdsData || [])
      setSystemConfig(configData)
      setHoneypotMode(configData?.honeypot_mode || 'active')
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    // Deferred so no state update happens synchronously in the effect body.
    const timer = setTimeout(fetchData, 0)
    return () => clearTimeout(timer)
  }, [fetchData])

  const run = async (action) => {
    try {
      await action()
      setError(null)
      await fetchData()
      return true
    } catch (err) {
      setError(err.message)
      return false
    }
  }

  const handleUpdateThreshold = (id, data) =>
    run(() => api.settings.updateThreshold(id, data))

  const handleDeleteThreshold = (id) => {
    // Deleting a threshold silently stops alert delivery, so confirm first.
    if (!window.confirm('Delete this threshold? Alerts matching it will stop being delivered.')) {
      return Promise.resolve(false)
    }
    return run(() => api.settings.deleteThreshold(id))
  }

  const handleCreateThreshold = async () => {
    if (!newThreshold.name.trim()) return
    const ok = await run(() => api.settings.createThreshold(newThreshold))
    if (!ok) return
    setNewThreshold(BLANK_THRESHOLD)
    setCreating(false)
  }

  const handleUpdateMode = async () => {
    setSaving(true)
    setModeNotice(null)
    let result = null
    const ok = await run(async () => {
      result = await api.settings.updateSystemConfig({ honeypot_mode: honeypotMode })
    })
    // Saved is not the same as applied: the engine is what answers attackers.
    if (ok && result?.engine_applied === false) {
      setModeNotice(
        'Saved, but the engine could not be reached. It switches when it next registers with the API.',
      )
    } else if (ok) {
      setModeNotice('Applied to the running engine.')
    }
    setSaving(false)
  }

  if (loading) return <LoadingRegion label="Loading settings" className="py-24" />

  const modeChanged = honeypotMode !== (systemConfig?.honeypot_mode || 'active')

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      {error && <ErrorBanner message={error} onRetry={fetchData} />}

      {!isAdmin && (
        <div className="rounded-[3px] border border-line bg-ink-1 px-4 py-3">
          <p className="text-[13px] text-paper-2">
            You have read-only access. Changing the emulation mode or alert
            thresholds needs an administrator account.
          </p>
        </div>
      )}

      <Panel
        title="Emulation mode"
        description="How the honeypot responds to whoever connects to it."
      >
        <div className="p-4">
          <div className="grid gap-3 sm:grid-cols-2">
            {[
              {
                value: 'active',
                label: 'Active',
                desc: 'Answers connections, records the full session and every command.',
              },
              {
                value: 'passive',
                label: 'Passive',
                desc: 'Logs connection attempts only. Nothing is answered.',
              },
            ].map((mode) => {
              const selected = honeypotMode === mode.value
              return (
                <button
                  key={mode.value}
                  type="button"
                  disabled={!isAdmin}
                  onClick={() => setHoneypotMode(mode.value)}
                  aria-pressed={selected}
                  className={`rounded-[3px] border p-3.5 text-left transition-colors ${
                    selected
                      ? 'border-paper bg-ink-2'
                      : 'border-line bg-ink-0 hover:border-bone-mute'
                  } ${!isAdmin ? 'cursor-not-allowed opacity-60' : ''}`}
                >
                  <span className="flex items-center gap-2">
                    <span
                      className={`h-2.5 w-2.5 shrink-0 rounded-full border-2 ${
                        selected ? 'border-paper bg-paper' : 'border-bone-mute'
                      }`}
                      aria-hidden="true"
                    />
                    <span className="text-sm font-semibold text-paper">
                      {mode.label}
                    </span>
                  </span>
                  <span className="mt-1.5 block text-[13px] leading-relaxed text-paper-3">
                    {mode.desc}
                  </span>
                </button>
              )
            })}
          </div>

          <div className="mt-3 flex items-center gap-3">
            <button
              type="button"
              onClick={handleUpdateMode}
              disabled={saving || !isAdmin || !modeChanged}
              className="control control-primary"
            >
              {saving ? 'Saving…' : 'Save mode'}
            </button>
            {modeChanged && !saving && (
              <span className="text-[13px] text-paper-3">Unsaved change</span>
            )}
            {!modeChanged && !saving && modeNotice && (
              <span className="text-[13px] text-paper-3">{modeNotice}</span>
            )}
          </div>
        </div>

        <dl className="grid grid-cols-2 divide-line border-t border-line sm:grid-cols-3 sm:divide-x">
          <div className="px-4 py-3">
            <dt className="eyebrow">Engines</dt>
            <dd className="readout mt-1 text-sm text-paper">
              <a href="#engines" className="hover:underline">{systemConfig?.active_nodes ?? 0} registered</a>
            </dd>
          </div>
          <div className="px-4 py-3">
            <dt className="eyebrow">Protocols</dt>
            <dd className="readout mt-1 text-sm uppercase text-paper">
              {systemConfig?.protocols?.length
                ? systemConfig.protocols.join(' · ')
                : 'None'}
            </dd>
          </div>
          <div className="px-4 py-3">
            <dt className="eyebrow">Running as</dt>
            <dd className="readout mt-1 text-sm capitalize text-paper">
              {systemConfig?.honeypot_mode || 'active'}
            </dd>
          </div>
        </dl>
      </Panel>

      <div id="engines">
        <EnginesPanel />
      </div>

      <Panel
        title="Alert thresholds"
        description="Rules that decide which detections are worth notifying someone about."
        action={
          isAdmin && (
            <button
              type="button"
              onClick={() => setCreating((open) => !open)}
              className="control flex shrink-0 items-center gap-1.5"
            >
              <Plus className="h-3.5 w-3.5" strokeWidth={2} />
              New threshold
            </button>
          )
        }
      >
        {creating && (
          <div className="border-b border-line bg-ink-0/40 p-4">
            <ThresholdForm
              value={newThreshold}
              onChange={setNewThreshold}
              onSubmit={handleCreateThreshold}
              onCancel={() => { setCreating(false); setNewThreshold(BLANK_THRESHOLD) }}
              submitLabel="Create threshold"
            />
          </div>
        )}

        {thresholds.length > 0 ? (
          <div>
            {thresholds.map((t) => (
              <ThresholdRow
                key={t.id}
                threshold={t}
                canEdit={isAdmin}
                onUpdate={handleUpdateThreshold}
                onDelete={handleDeleteThreshold}
              />
            ))}
          </div>
        ) : (
          <EmptyState
            title="No thresholds yet"
            hint={
              isAdmin
                ? 'Create one to start receiving alerts about what the honeypot catches.'
                : 'An administrator can create one to start alert delivery.'
            }
          />
        )}
      </Panel>

      <Panel
        title="Integration"
        description="Where to point a SIEM or threat intelligence platform."
      >
        <dl className="divide-y divide-line">
          <div className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-2.5">
            <dt className="eyebrow">API endpoint</dt>
            <dd className="readout text-[13px] break-all text-paper">
              {import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'}
            </dd>
          </div>
          <div className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-2.5">
            <dt className="eyebrow">Export formats</dt>
            {/* JSON, CEF and STIX 2.1 are what the export route actually
                serves. This previously advertised TAXII, which is not
                implemented anywhere in the backend. */}
            <dd className="readout text-[13px] text-paper">CSV · JSON · CEF · STIX 2.1</dd>
          </div>
          <div className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-2.5">
            <dt className="eyebrow">Alert delivery</dt>
            <dd className="readout text-[13px] text-paper">In-app · Email · Signed webhook</dd>
          </div>
          {systemConfig?.enrichment && (
            <div className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-2.5">
              <dt className="eyebrow">Model analysis</dt>
              <dd className="readout text-[13px] text-paper">
                {systemConfig.enrichment.configured
                  ? `On · ${systemConfig.enrichment.model || 'local model'}`
                  : 'Not configured (CHIMERA_URL unset)'}
              </dd>
            </div>
          )}
          {systemConfig?.retention && (
            <div className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-2.5">
              <dt className="eyebrow">Retention</dt>
              <dd className="readout text-[13px] text-paper">
                {systemConfig.retention.sessions_days ? `sessions ${systemConfig.retention.sessions_days} d` : 'sessions kept'}
                {' · '}
                {systemConfig.retention.audit_days ? `audit log ${systemConfig.retention.audit_days} d` : 'audit log kept'}
              </dd>
            </div>
          )}
          {systemConfig?.alerting && (
            <div className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-2.5">
              <dt className="eyebrow">Alert grouping</dt>
              <dd className="readout text-[13px] text-paper">
                {systemConfig.alerting.dedup_window_minutes
                  ? `repeat within ${systemConfig.alerting.dedup_window_minutes} min grouped`
                  : 'no grouping'}
                {systemConfig.alerting.suppress_scanners ? ' · research scanners suppressed' : ''}
              </dd>
            </div>
          )}
        </dl>
      </Panel>
      <TwoFactorPanel />
      <ChangePasswordPanel />
      {isAdmin && <UsersPanel />}
    </div>
  )
}
