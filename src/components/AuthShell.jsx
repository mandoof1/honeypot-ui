/*
 * Shared frame for sign in, request access and password reset.
 *
 * The three pages used to repeat this layout with small drifts between them.
 * One frame keeps the entry experience consistent and puts the console's
 * identity — the mark and one line about what this is — in the same place
 * every time.
 */

import { useEffect } from 'react'
import { Link } from 'react-router-dom'

function Mark({ className = '' }) {
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden="true" fill="none">
      <path
        d="M12 2.6 20.5 7.3v9.4L12 21.4 3.5 16.7V7.3L12 2.6Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path d="M12 8.2 16 10.4v4.4L12 17l-4-2.2v-4.4L12 8.2Z" fill="currentColor" opacity="0.9" />
    </svg>
  )
}

export default function AuthShell({ title, subtitle, children, footer, pageTitle }) {
  // The tab says which step this is, so the history and open tabs can be
  // told apart and a screen reader announces the new page.
  const name = pageTitle || (typeof title === 'string' ? title : 'Sign in')
  useEffect(() => {
    document.title = `${name} · HoneySentinel`
  }, [name])

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-ink-0 px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-7 flex items-center gap-2.5">
          <Mark className="h-6 w-6 shrink-0 text-paper" />
          <span className="text-lg font-semibold leading-none tracking-tight text-paper">
            HoneySentinel
          </span>
        </div>

        <div className="panel p-6">
          {/* Omitted on terminal steps, where <Outcome> supplies its own
              heading and this frame is only the surround. */}
          {title && (
            <h1 className="text-2xl font-semibold leading-tight text-paper">{title}</h1>
          )}
          {subtitle && (
            <p className="mt-1.5 text-sm leading-relaxed text-paper-2">{subtitle}</p>
          )}
          <div className={title ? 'mt-6' : ''}>{children}</div>
        </div>

        {footer && <div className="mt-4 text-center text-[13px]">{footer}</div>}
      </div>
    </div>
  )
}

/** Labelled text input with its error message. */
export function Field({ label, error, hint, children }) {
  return (
    <label className="block">
      <span className="eyebrow">{label}</span>
      <div className="mt-1.5">{children}</div>
      {error ? (
        <span className="mt-1.5 block text-[13px] text-s4">{error}</span>
      ) : hint ? (
        <span className="mt-1.5 block text-[13px] text-paper-3">{hint}</span>
      ) : null}
    </label>
  )
}

/** Full-width primary action for the auth forms. */
export function SubmitButton({ loading, children, loadingLabel, ...props }) {
  return (
    <button
      type="submit"
      disabled={loading}
      className="control control-primary w-full py-2.5"
      {...props}
    >
      {loading ? loadingLabel : children}
    </button>
  )
}

/**
 * Six-digit verification code. Wide tracking and a large size because this is
 * transcribed from an email one character at a time, and read back to check.
 */
export function OtpInput({ value, onChange, invalid, id = 'otp-code' }) {
  return (
    <input
      id={id}
      type="text"
      inputMode="numeric"
      autoComplete="one-time-code"
      maxLength={6}
      placeholder="000000"
      value={value}
      onChange={(e) => onChange(e.target.value.replace(/\D/g, ''))}
      className={`field py-3 text-center text-2xl tracking-[0.45em] ${invalid ? 'field-invalid' : ''}`}
    />
  )
}

/** Terminal state for a completed flow: verified, reset, done. */
export function Outcome({ title, children, action }) {
  return (
    <div className="text-center">
      <svg
        viewBox="0 0 32 32"
        className="mx-auto h-10 w-10 text-s1"
        fill="none"
        aria-hidden="true"
      >
        <path
          d="M16 3.5 27.5 10v13L16 29.5 4.5 23V10L16 3.5Z"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
        <path
          d="m11.5 16.2 3.2 3.3 6-6.6"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <h1 className="mt-4 text-2xl font-semibold text-paper">{title}</h1>
      <p className="mx-auto mt-1.5 max-w-xs text-sm leading-relaxed text-paper-2">
        {children}
      </p>
      <div className="mt-6">{action}</div>
    </div>
  )
}

/** A non-error status message: a code was sent, an account was created. */
export function Notice({ tone = 'info', title, children }) {
  const color =
    tone === 'success' ? 'var(--color-s1)'
      : tone === 'warn' ? 'var(--color-s3)'
        : 'var(--color-paper)'

  return (
    <div className="flex gap-2.5 rounded-[3px] border border-line bg-ink-0 px-3.5 py-3">
      <span
        className="mt-1.5 h-2 w-2 shrink-0 rounded-full"
        style={{ background: color }}
        aria-hidden="true"
      />
      <div className="min-w-0">
        {title && (
          <p className="text-[13px] font-semibold text-paper">{title}</p>
        )}
        <div className="text-[13px] leading-relaxed text-paper-2">{children}</div>
      </div>
    </div>
  )
}

/**
 * Shown in place of a flow this deployment cannot complete. Sign-up and
 * password reset both end with a code sent by e-mail; without a mail
 * provider the form would accept the request and the code would never come.
 */
export function Unavailable({ title, children }) {
  return (
    <AuthShell
      title={title}
      footer={
        <Link to="/login" className="font-medium text-paper-2 hover:text-paper">
          Back to sign in
        </Link>
      }
    >
      <Notice tone="warn" title="Not available on this deployment">
        {children}
      </Notice>
    </AuthShell>
  )
}
