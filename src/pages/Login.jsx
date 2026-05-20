import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ShieldAlert, Eye, EyeOff, AlertCircle } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ email: '', password: '' })
  const [errors, setErrors] = useState({})
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)

  const validate = () => {
    const e = {}
    if (!form.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
      e.email = 'A valid email address is required.'
    if (!form.password || form.password.length < 6)
      e.password = 'Password must be at least 6 characters.'
    return e
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    const errs = validate()
    if (Object.keys(errs).length) { setErrors(errs); return }
    setLoading(true)
    try {
      await login(form.email, form.password)
      navigate('/')
    } catch (err) {
      setErrors({ email: err.message || 'Invalid credentials' })
    } finally {
      setLoading(false)
    }
  }

  const field = (key) => ({
    value: form[key],
    onChange: (ev) => {
      setForm({ ...form, [key]: ev.target.value })
      if (errors[key]) setErrors({ ...errors, [key]: null })
    },
  })

  return (
    <div className="min-h-screen grid-bg flex items-center justify-center px-4">
      <div className="w-full max-w-md animate-slide-up">
        <div className="flex items-center gap-3 mb-10 justify-center">
          <ShieldAlert className="text-accent-cyan w-8 h-8 text-glow-cyan" />
          <span className="font-mono text-xl font-semibold tracking-widest uppercase text-accent-cyan text-glow-cyan">
            HoneySentinel
          </span>
        </div>

        <div className="bg-surface-800 border border-border rounded-xl p-8 glow-blue">
          <h1 className="text-2xl font-semibold text-white mb-1">Sign in</h1>
          <p className="text-sm text-gray-500 mb-8 font-mono">
            Authenticated access only — credentials are verified.
          </p>

          <form onSubmit={handleSubmit} noValidate className="space-y-5">
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">
                Email Address
              </label>
              <input
                type="email"
                autoComplete="email"
                placeholder="analyst@soc.internal"
                className={`w-full bg-surface-700 border rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-600 font-mono outline-none transition-all focus:ring-1 focus:ring-accent-blue ${
                  errors.email ? 'border-accent-red' : 'border-border focus:border-accent-blue'
                }`}
                {...field('email')}
              />
              {errors.email && (
                <p className="mt-1.5 flex items-center gap-1 text-xs text-accent-red font-mono">
                  <AlertCircle className="w-3 h-3" /> {errors.email}
                </p>
              )}
            </div>

            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPw ? 'text' : 'password'}
                  autoComplete="current-password"
                  placeholder="••••••••••"
                  className={`w-full bg-surface-700 border rounded-lg px-4 py-2.5 pr-10 text-sm text-white placeholder-gray-600 font-mono outline-none transition-all focus:ring-1 focus:ring-accent-blue ${
                    errors.password ? 'border-accent-red' : 'border-border focus:border-accent-blue'
                  }`}
                  {...field('password')}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(!showPw)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {errors.password && (
                <p className="mt-1.5 flex items-center gap-1 text-xs text-accent-red font-mono">
                  <AlertCircle className="w-3 h-3" /> {errors.password}
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 bg-accent-blue hover:bg-blue-400 disabled:opacity-50 text-surface-900 font-semibold text-sm rounded-lg py-2.5 transition-all font-mono tracking-wider uppercase"
            >
              {loading ? 'Authenticating...' : 'Sign In'}
            </button>
          </form>

          <p className="mt-6 text-center text-xs text-gray-500 font-mono">
            No account?{' '}
            <Link to="/signup" className="text-accent-cyan hover:underline">
              Request access
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
