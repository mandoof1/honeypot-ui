import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ShieldAlert, AlertCircle, Mail, CheckCircle, ArrowLeft } from 'lucide-react'
import { api } from '../services/api'

export default function Signup() {
  const [step, setStep] = useState('register')
  const [form, setForm] = useState({ name: '', email: '', password: '', confirm: '' })
  const [otpCode, setOtpCode] = useState('')
  const [errors, setErrors] = useState({})
  const [loading, setLoading] = useState(false)
  const [successMsg, setSuccessMsg] = useState('')
  const [resendCooldown, setResendCooldown] = useState(0)

  const validate = () => {
    const e = {}
    if (!form.name.trim()) e.name = 'Full name is required.'
    if (!form.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
      e.email = 'A valid email address is required.'
    if (!form.password || form.password.length < 8)
      e.password = 'Password must be at least 8 characters.'
    if (form.password !== form.confirm) e.confirm = 'Passwords do not match.'
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
      setSuccessMsg(result.message)
      setStep('verify')
      startCooldown()
    } catch (err) {
      setErrors({ email: err.message || 'Registration failed' })
    } finally {
      setLoading(false)
    }
  }

  const handleVerify = async (ev) => {
    ev.preventDefault()
    if (otpCode.length !== 6) {
      setErrors({ otp: 'Enter the 6-digit code.' })
      return
    }
    setLoading(true)
    try {
      await api.auth.verifyOtp({
        email: form.email,
        otp_code: otpCode,
      })
      setStep('success')
    } catch (err) {
      setErrors({ otp: err.message || 'Verification failed' })
    } finally {
      setLoading(false)
    }
  }

  const handleResend = async () => {
    if (resendCooldown > 0) return
    setLoading(true)
    try {
      await api.auth.resendOtp({ email: form.email })
      setSuccessMsg('A new code has been sent to your email.')
      setErrors({})
      startCooldown()
    } catch (err) {
      setErrors({ resend: err.message || 'Failed to resend' })
    } finally {
      setLoading(false)
    }
  }

  const startCooldown = () => {
    setResendCooldown(60)
    const timer = setInterval(() => {
      setResendCooldown((prev) => {
        if (prev <= 1) { clearInterval(timer); return 0 }
        return prev - 1
      })
    }, 1000)
  }

  const field = (key) => ({
    value: form[key],
    onChange: (ev) => {
      setForm({ ...form, [key]: ev.target.value })
      if (errors[key]) setErrors({ ...errors, [key]: null })
    },
  })

  const inputClass = (key) =>
    `w-full bg-surface-700 border rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-600 font-mono outline-none transition-all focus:ring-1 focus:ring-accent-blue ${
      errors[key] ? 'border-accent-red' : 'border-border focus:border-accent-blue'
    }`

  if (step === 'success') {
    return (
      <div className="min-h-screen grid-bg flex items-center justify-center px-4 py-12">
        <div className="w-full max-w-md animate-slide-up">
          <div className="flex items-center gap-3 mb-10 justify-center">
            <ShieldAlert className="text-accent-cyan w-8 h-8" />
            <span className="font-mono text-xl font-semibold tracking-widest uppercase text-accent-cyan">
              HoneySentinel
            </span>
          </div>

          <div className="bg-surface-800 border border-accent-green/30 rounded-xl p-8 text-center">
            <CheckCircle className="w-16 h-16 text-accent-green mx-auto mb-6" />
            <h1 className="text-2xl font-semibold text-white mb-2">Email Verified</h1>
            <p className="text-sm text-gray-400 mb-8 font-mono">
              Your account has been verified successfully.
            </p>
            <Link
              to="/login"
              className="inline-block bg-accent-cyan hover:bg-cyan-300 text-surface-900 font-semibold text-sm rounded-lg px-8 py-2.5 transition-all font-mono tracking-wider uppercase"
            >
              Sign In
            </Link>
          </div>
        </div>
      </div>
    )
  }

  if (step === 'verify') {
    return (
      <div className="min-h-screen grid-bg flex items-center justify-center px-4 py-12">
        <div className="w-full max-w-md animate-slide-up">
          <div className="flex items-center gap-3 mb-10 justify-center">
            <ShieldAlert className="text-accent-cyan w-8 h-8" />
            <span className="font-mono text-xl font-semibold tracking-widest uppercase text-accent-cyan">
              HoneySentinel
            </span>
          </div>

          <div className="bg-surface-800 border border-border rounded-xl p-8 glow-blue">
            <button
              onClick={() => setStep('register')}
              className="flex items-center gap-1 text-xs font-mono text-gray-500 hover:text-gray-300 mb-6 transition-colors"
            >
              <ArrowLeft className="w-3 h-3" /> Back
            </button>

            <div className="flex items-center gap-2 mb-1">
              <Mail className="w-5 h-5 text-accent-cyan" />
              <h1 className="text-2xl font-semibold text-white">Verify your email</h1>
            </div>
            <p className="text-sm text-gray-500 mb-6 font-mono">
              We sent a 6-digit code to <span className="text-accent-blue">{form.email}</span>
            </p>

            {successMsg && (
              <div className="mb-4 bg-accent-green/10 border border-accent-green/30 rounded-lg p-3">
                <p className="text-xs font-mono text-accent-green">{successMsg}</p>
              </div>
            )}

            <form onSubmit={handleVerify} noValidate className="space-y-5">
              <div>
                <label className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">
                  Verification Code
                </label>
                <input
                  type="text"
                  maxLength={6}
                  placeholder="000000"
                  value={otpCode}
                  onChange={(ev) => {
                    const val = ev.target.value.replace(/[^0-9]/g, '')
                    setOtpCode(val)
                    if (errors.otp) setErrors({ ...errors, otp: null })
                  }}
                  className={`w-full bg-surface-700 border rounded-lg px-4 py-3 text-center text-2xl font-mono tracking-[0.5em] text-white placeholder-gray-600 outline-none transition-all focus:ring-1 focus:ring-accent-blue ${
                    errors.otp ? 'border-accent-red' : 'border-border focus:border-accent-blue'
                  }`}
                />
                {errors.otp && (
                  <p className="mt-1.5 flex items-center gap-1 text-xs text-accent-red font-mono">
                    <AlertCircle className="w-3 h-3" /> {errors.otp}
                  </p>
                )}
              </div>

              <button
                type="submit"
                disabled={loading || otpCode.length !== 6}
                className="w-full bg-accent-cyan hover:bg-cyan-300 disabled:opacity-50 text-surface-900 font-semibold text-sm rounded-lg py-2.5 transition-all font-mono tracking-wider uppercase"
              >
                {loading ? 'Verifying...' : 'Verify Email'}
              </button>
            </form>

            <div className="mt-6 text-center">
              <p className="text-xs font-mono text-gray-500">
                Didn't receive the code?{' '}
                {resendCooldown > 0 ? (
                  <span className="text-gray-600">Resend in {resendCooldown}s</span>
                ) : (
                  <button
                    onClick={handleResend}
                    disabled={loading}
                    className="text-accent-blue hover:underline disabled:opacity-50"
                  >
                    Resend code
                  </button>
                )}
              </p>
              {errors.resend && (
                <p className="mt-1 text-xs text-accent-red font-mono">{errors.resend}</p>
              )}
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen grid-bg flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md animate-slide-up">
        <div className="flex items-center gap-3 mb-10 justify-center">
          <ShieldAlert className="text-accent-cyan w-8 h-8" />
          <span className="font-mono text-xl font-semibold tracking-widest uppercase text-accent-cyan">
            HoneySentinel
          </span>
        </div>

        <div className="bg-surface-800 border border-border rounded-xl p-8 glow-blue">
          <h1 className="text-2xl font-semibold text-white mb-1">Create account</h1>
          <p className="text-sm text-gray-500 mb-8 font-mono">
            Email verification required after registration.
          </p>

          <form onSubmit={handleRegister} noValidate className="space-y-5">
            {[
              { key: 'name',     label: 'Full Name',        type: 'text',     placeholder: 'Jane Analyst' },
              { key: 'email',    label: 'Email Address',    type: 'email',    placeholder: 'analyst@soc.internal' },
              { key: 'password', label: 'Password',         type: 'password', placeholder: '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022' },
              { key: 'confirm',  label: 'Confirm Password', type: 'password', placeholder: '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022' },
            ].map(({ key, label, type, placeholder }) => (
              <div key={key}>
                <label className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">
                  {label}
                </label>
                <input type={type} placeholder={placeholder} className={inputClass(key)} {...field(key)} />
                {errors[key] && (
                  <p className="mt-1.5 flex items-center gap-1 text-xs text-accent-red font-mono">
                    <AlertCircle className="w-3 h-3" /> {errors[key]}
                  </p>
                )}
              </div>
            ))}

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 bg-accent-cyan hover:bg-cyan-300 disabled:opacity-50 text-surface-900 font-semibold text-sm rounded-lg py-2.5 transition-all font-mono tracking-wider uppercase"
            >
              {loading ? 'Creating Account...' : 'Register'}
            </button>
          </form>

          <p className="mt-6 text-center text-xs text-gray-500 font-mono">
            Already registered?{' '}
            <Link to="/login" className="text-accent-blue hover:underline">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
