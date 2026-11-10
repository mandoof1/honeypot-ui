import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { api } from '../services/api'
import { useCapabilities } from '../hooks/useCapabilities'
import AuthShell, {
  Field, Notice, Outcome, OtpInput, SubmitButton, Unavailable,
} from '../components/AuthShell'

const MIN_PASSWORD_LENGTH = 12

const REGISTER_FIELDS = [
  { key: 'name', label: 'Full name', type: 'text', placeholder: 'Jane Analyst', autoComplete: 'name' },
  { key: 'email', label: 'Email', type: 'email', placeholder: 'analyst@soc.internal', autoComplete: 'email' },
  { key: 'password', label: 'Password', type: 'password', autoComplete: 'new-password' },
  { key: 'confirm', label: 'Confirm password', type: 'password', autoComplete: 'new-password' },
]

export default function Signup() {
  const capabilities = useCapabilities()
  const [step, setStep] = useState('register')
  const [form, setForm] = useState({ name: '', email: '', password: '', confirm: '' })
  const [otpCode, setOtpCode] = useState('')
  const [errors, setErrors] = useState({})
  const [loading, setLoading] = useState(false)
  const [notice, setNotice] = useState('')
  const [resendCooldown, setResendCooldown] = useState(0)
  const cooldownTimer = useRef(null)

  // Clear the interval on unmount; the previous version left it running after
  // the component was gone.
  useEffect(() => () => clearInterval(cooldownTimer.current), [])

  const startCooldown = () => {
    clearInterval(cooldownTimer.current)
    setResendCooldown(60)
    cooldownTimer.current = setInterval(() => {
      setResendCooldown((prev) => {
        if (prev <= 1) { clearInterval(cooldownTimer.current); return 0 }
        return prev - 1
      })
    }, 1000)
  }

  const validate = () => {
    const e = {}
    if (!form.name.trim()) e.name = 'Enter your full name.'
    if (!form.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
      e.email = 'Enter a valid email address.'
    // Must match the backend's minimum, or the API rejects the form.
    if (!form.password || form.password.length < MIN_PASSWORD_LENGTH)
      e.password = `Use at least ${MIN_PASSWORD_LENGTH} characters.`
    if (form.password !== form.confirm) e.confirm = 'These do not match.'
    return e
  }

  const handleRegister = async (ev) => {
    ev.preventDefault()
    const errs = validate()
    if (Object.keys(errs).length) { setErrors(errs); return }
    setLoading(true)
    try {
      const result = await api.auth.register({
        name: form.name,
        email: form.email,
        password: form.password,
      })
      setNotice(result.message)
      setStep('verify')
      startCooldown()
    } catch (err) {
      setErrors({ email: err.message || 'Could not create the account.' })
    } finally {
      setLoading(false)
    }
  }

  const handleVerify = async (ev) => {
    ev.preventDefault()
    if (otpCode.length !== 6) {
      setErrors({ otp: 'Enter all six digits.' })
      return
    }
    setLoading(true)
    try {
      await api.auth.verifyOtp({ email: form.email, otp_code: otpCode })
      setStep('success')
    } catch (err) {
      setErrors({ otp: err.message || 'That code was not accepted.' })
    } finally {
      setLoading(false)
    }
  }

  const handleResend = async () => {
    if (resendCooldown > 0) return
    setLoading(true)
    try {
      await api.auth.resendOtp({ email: form.email })
      setNotice('A new code is on its way.')
      setErrors({})
      startCooldown()
    } catch (err) {
      setErrors({ resend: err.message || 'Could not send the code.' })
    } finally {
      setLoading(false)
      startCooldown()
    }
  }

  const field = (key) => ({
    value: form[key],
    onChange: (ev) => {
      setForm({ ...form, [key]: ev.target.value })
      if (errors[key]) setErrors({ ...errors, [key]: null })
    },
  })

  // Reached by a typed address or an old link. The form would accept the
  // details and then wait for a code that is never sent.
  if (capabilities.status === 'loading') {
    return <AuthShell title="Request access" subtitle="Checking what this deployment offers…" />
  }
  if (!capabilities.signup) {
    return (
      <Unavailable title="Request access">
        Creating an account here needs a confirmation code sent by e-mail, and this deployment
        {capabilities.known ? ' has no mail provider to send one.' : ' did not confirm that it can send one.'}
        {' '}Ask an administrator to create an account for you.
      </Unavailable>
    )
  }

  if (step === 'success') {
    return (
      <AuthShell pageTitle="Email verified">
        <Outcome
          title="Email verified"
          action={<Link to="/login" className="control control-primary inline-block">Sign in</Link>}
        >
          Your account is ready. Sign in to reach the console.
        </Outcome>
      </AuthShell>
    )
  }

  if (step === 'verify') {
    return (
      <AuthShell
        title="Check your email"
        subtitle={
          <>
            We sent a six-digit code to{' '}
            <span className="readout text-paper">{form.email}</span>.
          </>
        }
        footer={
          <span className="text-paper-3">
            Didn&apos;t get it?{' '}
            {resendCooldown > 0 ? (
              <span>You can ask again in {resendCooldown}s.</span>
            ) : (
              <button
                type="button"
                onClick={handleResend}
                disabled={loading}
                className="font-medium text-paper-2 hover:text-paper disabled:opacity-50"
              >
                Send a new code
              </button>
            )}
          </span>
        }
      >
        <button
          type="button"
          onClick={() => setStep('register')}
          className="mb-5 flex items-center gap-1.5 text-[13px] font-medium text-paper-3 transition-colors hover:text-paper"
        >
          <ArrowLeft className="h-3.5 w-3.5" strokeWidth={2} />
          Back to details
        </button>

        {notice && (
          <div className="mb-4">
            <Notice tone="success">{notice}</Notice>
          </div>
        )}

        <form onSubmit={handleVerify} noValidate className="space-y-4">
          <Field label="Verification code" error={errors.otp || errors.resend}>
            <OtpInput
              value={otpCode}
              invalid={Boolean(errors.otp)}
              onChange={(v) => {
                setOtpCode(v)
                if (errors.otp) setErrors({ ...errors, otp: null })
              }}
            />
          </Field>

          <SubmitButton
            loading={loading}
            loadingLabel="Verifying…"
            disabled={loading || otpCode.length !== 6}
          >
            Verify email
          </SubmitButton>
        </form>
      </AuthShell>
    )
  }

  return (
    <AuthShell
      title="Request access"
      subtitle="We'll email you a code to confirm the address before the account goes live."
      footer={
        <span className="text-paper-3">
          Already have an account?{' '}
          <Link to="/login" className="font-medium text-paper-2 hover:text-paper">
            Sign in
          </Link>
        </span>
      }
    >
      <form onSubmit={handleRegister} noValidate className="space-y-4">
        {REGISTER_FIELDS.map(({ key, label, type, placeholder, autoComplete }) => (
          <Field
            key={key}
            label={label}
            error={errors[key]}
            hint={key === 'password' ? `At least ${MIN_PASSWORD_LENGTH} characters.` : undefined}
          >
            <input
              type={type}
              placeholder={placeholder}
              autoComplete={autoComplete}
              className={`field ${errors[key] ? 'field-invalid' : ''}`}
              {...field(key)}
            />
          </Field>
        ))}

        <SubmitButton loading={loading} loadingLabel="Creating account…">
          Create account
        </SubmitButton>
      </form>
    </AuthShell>
  )
}
