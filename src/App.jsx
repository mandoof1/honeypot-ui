import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import Login from './pages/Login'
import Signup from './pages/Signup'
import DashboardLayout from './layouts/DashboardLayout'
import Dashboard from './pages/Dashboard'
import LiveMap from './pages/LiveMap'
import SessionLogs from './pages/SessionLogs'
import Settings from './pages/Settings'

function AuthRoutes() {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="min-h-screen grid-bg flex items-center justify-center">
        <div className="flex items-center gap-3">
          <div className="w-6 h-6 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
          <span className="font-mono text-sm text-gray-400">Loading HoneySentinel...</span>
        </div>
      </div>
    )
  }

  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <Routes>
      <Route element={<DashboardLayout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/map" element={<LiveMap />} />
        <Route path="/sessions" element={<SessionLogs />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <AuthRoutes />
    </AuthProvider>
  )
}
