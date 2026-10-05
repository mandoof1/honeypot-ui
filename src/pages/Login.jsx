import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Eye, EyeOff } from 'lucide-react'
import { useAuth } from '../context/useAuth'
import { api } from '../services/api'
import AuthShell, { Field, Notice, SubmitButton } from '../components/AuthShell'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ email: '', password: '', code: '' })
  // Set once the password has been accepted and the account wants its
  // authenticator code; the email and password are resent with it.
  const [needsCode, setNeedsCode] = useState(false)
  const [errors, setErrors] = useState({})
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [unverifiedEmail, setUnverifiedEmail] = useState('')
  const [resendMsg, setResendMsg] = useState('')
  const [resendCooldown, setResendCooldown] = useState(0)
  const cooldownTimer = useRef(null)

  // Clear the interval on unmount; the previous version left it running after
  // the component was gone.
  useEffect(() => () => clearInterval(cooldownTimer.current), [])

  const validate = () => {
    const e = {}
    if (!form.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
      e.email = 'Enter a valid email address.'
    if (!form.password) e.password = 'Enter your password.'
    if (needsCode && !form.code.trim()) e.code = 'Enter the code from your authenticator app.'
    return e
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    const errs = validate()
    if (Object.keys(errs).length) { setErrors(errs); return }
    setLoading(true)
    setUnverifiedEmail('')
    setResendMsg('')
    try {
      await login(form.email, form.password, needsCode ? form.code.replace(/\s+/g, '') : undefined)
      navigate('/')
    } catch (err) {
      const msg = err.message || 'That email and password did not match.'
      if (err.mfaRequired) {
        setNeedsCode(true)
        setErrors({})
      } else if (needsCode && err.status === 401) {
        setErrors({ code: msg })
      } else if (msg.includes('not verified')) {
        setUnverifiedEmail(form.email)
        setErrors({})
      } else {
        setErrors({ password: msg })
      }
    } finally {
      setLoading(false)
    }
  }

  const handleResendOtp = async () => {
    if (resendCooldown > 0 || !unverifiedEmail) return
    setLoading(true)
    try {
      await api.auth.resendOtp({ email: unverifiedEmail })
      setResendMsg('Sent. Check your inbox.')
    } catch (err) {
      setErrors({ email: err.message || 'Could not send the code.' })
    } finally {
      setLoading(false)
      setResendCooldown(60)
      cooldownTimer.current = setInterval(() => {
        setResendCooldown((prev) => {
          if (prev <= 1) { clearInterval(cooldownTimer.current); return 0 }
          return prev - 1
        })
      }, 1000)
    }
  }

  const field = (key) => ({
    value: form[key],
    onChange: (ev) => {
      setForm({ ...form, [key]: ev.target.value })
      // A different account may not use MFA at all.
      if (key !== 'code' && needsCode) setNeedsCode(false)
      if (errors[key]) setErrors({ ...errors, [key]: null })
      setUnverifiedEmail('')
      setResendMsg('')
    },
  })

  return (
    <AuthShell
      title="Sign in"
      subtitle="Captured attacker sessions and threat intelligence for your honeypot nodes."
      footer={
        <span className="text-paper-3">
          No account yet?{' '}
          <Link to="/signup" className="font-medium text-paper-2 hover:text-paper">
            Request access
          </Link>
        </span>
      }
    >
      {unverifiedEmail && (
        <div className="mb-5">
          <Notice tone="warn" title="Verify your email first">
            We sent a code to{' '}
            <span className="readout text-paper">{unverifiedEmail}</span>.
            {resendCooldown > 0 ? (
              <span className="mt-1.5 block text-paper-3">
                You can send another in {resendCooldown}s.
              </span>
            ) : (
              <button
                type="button"
                onClick={handleResendOtp}
                disabled={loading}
                className="mt-1.5 block font-display font-medium text-paper hover:underline disabled:opacity-50"
              >
                Send a new code
              </button>
            )}
            {resendMsg && (
              <span className="mt-1.5 block text-s1">{resendMsg}</span>
            )}
          </Notice>
        </div>
      )}

      <form onSubmit={handleSubmit} noValidate className="space-y-4">
        <Field label="Email" error={errors.email}>
          <input
            type="email"
            autoComplete="email"
            placeholder="analyst@soc.internal"
            className={`field ${errors.email ? 'field-invalid' : ''}`}
            {...field('email')}
          />
        </Field>

        <Field label="Password" error={errors.password}>
          <div className="relative">
            <input
              type={showPw ? 'text' : 'password'}
              autoComplete="current-password"
              className={`field pr-10 ${errors.password ? 'field-invalid' : ''}`}
              {...field('password')}
            />
            <button
              type="button"
              onClick={() => setShowPw(!showPw)}
              aria-label={showPw ? 'Hide password' : 'Show password'}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-paper-3 transition-colors hover:text-paper"
            >
              {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </Field>

        {needsCode && (
          <Field
            label="Authenticator code"
            error={errors.code}
            hint="Six digits from your app, or one of your recovery codes."
          >
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              placeholder="123 456"
              className={`field readout tracking-[0.2em] ${errors.code ? 'field-invalid' : ''}`}
              {...field('code')}
            />
          </Field>
        )}

        <SubmitButton loading={loading} loadingLabel="Signing in…">
          {needsCode ? 'Verify and sign in' : 'Sign in'}
        </SubmitButton>
      </form>

      <p className="mt-4 text-center text-[13px]">
        <Link to="/forgot-password" className="text-paper-3 hover:text-paper">
          Forgot your password?
        </Link>
      </p>
    </AuthShell>
  )
}
