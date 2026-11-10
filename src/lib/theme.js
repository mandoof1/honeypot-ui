/** The page background of each theme, for the browser's own chrome. */
const THEME_COLOR = { dark: '#0a0a0c', light: '#ffffff' }

/**
 * Put the theme on the document. The stylesheet re-points its colour tokens
 * under `:root[data-theme='light']`, so this one attribute is the switch.
 */
export function applyTheme(theme) {
  if (typeof document === 'undefined') return
  document.documentElement.dataset.theme = theme === 'light' ? 'light' : 'dark'
  const meta = document.querySelector('meta[name="theme-color"]')
  if (meta) meta.setAttribute('content', THEME_COLOR[theme] || THEME_COLOR.dark)
}
