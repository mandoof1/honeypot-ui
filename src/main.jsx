import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import { readPrefs } from './lib/prefs'
import { applyTheme } from './lib/theme'
import './index.css'

// Before the first render, so a light-theme user never sees a dark flash.
// Done here rather than in an inline script: the deployment's content
// security policy allows scripts from this origin only.
let stored = null
try {
  stored = window.localStorage
} catch {
  // Storage is blocked in this browser; the default theme applies.
}
applyTheme(readPrefs(stored).theme)

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
)
