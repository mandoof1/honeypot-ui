import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ShieldAlert, AlertCircle } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function Signup() {
  const { register } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ name: '', email: '', password: '', confirm: '' })
  const [errors, setErrors] = useState({})
  const [loading, setLoading] = useState(false)

  const validate = () => {
    const e = {}
    if (!form.name.trim())
      e.name = 'Full name is required.'
    if (!form.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
      e.email = 'A valid email address is required.'
    if (!form.password || form.password.length < 8)
      e.password = 'Password must be at least 8 characters.'
    if (form.password !== form.confirm)
      e.confirm = 'Passwords do not match.'
    return e
  }

  const handleSubmit = async (ev) => {
    ev.preventDefault()
    const errs = validate()
    if (Object.keys(errs).length) { setErrors(errs); return }
    setLoading(true)
    try {
      await register({ name: form.name, email: form.email, password: form.password })
      navigate('/')
    } catch (err) {
      setErrors({ email: err.message || 'Registration failed' })
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

  const inputClass = (key) =>
    `w-full bg-surface-700 border rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-600 font-mono outline-none transition-all focus:ring-1 focus:ring-accent-blue ${
      errors[key] ? 'border-accent-red' : 'border-border focus:border-accent-blue'
    }`

  return (
    <div className="min-h-screen grid-bg flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md animate-slide-up">
        <div className="flex items-center gap-3 mb-10 justify-center">
          <ShieldAlert className="text-accent-cyan w-8 h-8 text-glow-cyan" />
          <span className="font-mono text-xl font-semibold tracking-widest uppercase text-accent-cyan text-glow-cyan">
            HoneySentinel
          </span>
        </div>

        <div className="bg-surface-800 border border-border rounded-xl p-8 glow-blue">
          <h1 className="text-2xl font-semibold text-white mb-1">Create account</h1>
          <p className="text-sm text-gray-500 mb-8 font-mono">
            New analyst registration — pending admin approval.
          </p>

          <form onSubmit={handleSubmit} noValidate className="space-y-5">
            {[
              { key: 'name',     label: 'Full Name',        type: 'text',     placeholder: 'Jane Analyst' },
              { key: 'email',    label: 'Email Address',    type: 'email',    placeholder: 'analyst@soc.internal' },
              { key: 'password', label: 'Password',         type: 'password', placeholder: '••••••••••' },
              { key: 'confirm',  label: 'Confirm Password', type: 'password', placeholder: '••••••••••' },
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
