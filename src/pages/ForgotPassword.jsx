import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { api } from '../services/api'
import { useCapabilities } from '../hooks/useCapabilities'
import AuthShell, {
  Field, Outcome, OtpInput, SubmitButton, Unavailable,
} from '../components/AuthShell'

const MIN_PASSWORD_LENGTH = 12

/**
 * Password reset.
 *
 * The backend has exposed /auth/request-password-reset and /auth/reset-password
 * from the start, but nothing in the UI reached them, so a user who forgot
 * their password had no way back in.
 */
export default function ForgotPassword() {
  const navigate = useNavigate()
  const [step, setStep] = useState('request')
  const [email, setEmail] = useState('')
  const [otpCode, setOtpCode] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [errors, setErrors] = useState({})
  const [loading, setLoading] = useState(false)
  const capabilities = useCapabilities()

  const handleRequest = async (event) => {
    event.preventDefault()
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setErrors({ email: 'Enter a valid email address.' })
      return
    }
    setLoading(true)
    try {
      await api.auth.requestPasswordReset(email)
      setErrors({})
      setStep('confirm')
    } catch (err) {
      setErrors({ email: err.message })
    } finally {
      setLoading(false)
    }
  }

  const handleConfirm = async (event) => {
    event.preventDefault()
    const next = {}
    if (otpCode.length !== 6) next.otp = 'Enter all six digits.'
    if (password.length < MIN_PASSWORD_LENGTH) {
      next.password = `Use at least ${MIN_PASSWORD_LENGTH} characters.`
    }
    if (password !== confirm) next.confirm = 'These do not match.'
    if (Object.keys(next).length) {
      setErrors(next)
      return
    }

    setLoading(true)
    try {
      await api.auth.resetPassword({
        email,
        otp_code: otpCode,
        new_password: password,
      })
      setStep('done')
    } catch (err) {
      setErrors({ otp: err.message })
    } finally {
      setLoading(false)
    }
  }

  if (capabilities.status === 'loading') {
    return <AuthShell title="Reset your password" subtitle="Checking what this deployment offers…" />
  }
  if (!capabilities.password_reset) {
    return (
      <Unavailable title="Reset your password">
        A password is reset here with a code sent by e-mail, and this deployment
        {capabilities.known ? ' has no mail provider to send one.' : ' did not confirm that it can send one.'}
        {' '}Ask an administrator to set a temporary password for your account.
      </Unavailable>
    )
  }

  if (step === 'done') {
    return (
      <AuthShell pageTitle="Password updated">
        <Outcome
          title="Password updated"
          action={
            <button
              type="button"
              onClick={() => navigate('/login')}
              className="control control-primary"
            >
              Sign in
            </button>
          }
        >
          Use your new password to sign in.
        </Outcome>
      </AuthShell>
    )
  }

  if (step === 'confirm') {
    return (
      <AuthShell
        title="Set a new password"
        subtitle={
          <>
            If an account exists for{' '}
            <span className="readout text-paper">{email}</span>, we sent it a
            six-digit code.
          </>
        }
      >
        <button
          type="button"
          onClick={() => setStep('request')}
          className="mb-5 flex items-center gap-1.5 text-[13px] font-medium text-paper-3 transition-colors hover:text-paper"
        >
          <ArrowLeft className="h-3.5 w-3.5" strokeWidth={2} />
          Use a different email
        </button>

        <form onSubmit={handleConfirm} noValidate className="space-y-4">
          <Field label="Reset code" error={errors.otp}>
            <OtpInput
              value={otpCode}
              invalid={Boolean(errors.otp)}
              onChange={setOtpCode}
            />
          </Field>

          <Field
            label="New password"
            error={errors.password}
            hint={`At least ${MIN_PASSWORD_LENGTH} characters.`}
          >
            <input
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={`field ${errors.password ? 'field-invalid' : ''}`}
            />
          </Field>

          <Field label="Confirm password" error={errors.confirm}>
            <input
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className={`field ${errors.confirm ? 'field-invalid' : ''}`}
            />
          </Field>

          <SubmitButton loading={loading} loadingLabel="Updating…">
            Update password
          </SubmitButton>
        </form>
      </AuthShell>
    )
  }

  return (
    <AuthShell
      title="Reset your password"
      subtitle="We'll email you a code to set a new one."
      footer={
        <Link to="/login" className="text-paper-3 hover:text-paper">
          Back to sign in
        </Link>
      }
    >
      <form onSubmit={handleRequest} noValidate className="space-y-4">
        <Field label="Email" error={errors.email}>
          <input
            type="email"
            autoComplete="email"
            placeholder="analyst@soc.internal"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className={`field ${errors.email ? 'field-invalid' : ''}`}
          />
        </Field>

        <SubmitButton loading={loading} loadingLabel="Sending…">
          Send reset code
        </SubmitButton>
      </form>
    </AuthShell>
  )
}
