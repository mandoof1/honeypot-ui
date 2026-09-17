import { lazy, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import { useAuth } from './context/useAuth'
import ErrorBoundary from './components/ErrorBoundary'
import { Spinner } from './components/Loading'
import Login from './pages/Login'
import Signup from './pages/Signup'
import ForgotPassword from './pages/ForgotPassword'
import DashboardLayout from './layouts/DashboardLayout'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const LiveMap = lazy(() => import('./pages/LiveMap'))
const SessionLogs = lazy(() => import('./pages/SessionLogs'))
const Alerts = lazy(() => import('./pages/Alerts'))
const Indicators = lazy(() => import('./pages/Indicators'))
const Payloads = lazy(() => import('./pages/Payloads'))
const Settings = lazy(() => import('./pages/Settings'))

function AuthRoutes() {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-ink-0">
        <Spinner label="Starting HoneySentinel" />
      </div>
    )
  }

  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
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
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/indicators" element={<Indicators />} />
        <Route path="/payloads" element={<Payloads />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <ErrorBoundary>
        <Suspense fallback={<Spinner label="Loading view" />}><AuthRoutes /></Suspense>
      </ErrorBoundary>
    </AuthProvider>
  )
}
