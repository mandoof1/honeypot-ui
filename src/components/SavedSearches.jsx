import { useEffect, useRef, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Bookmark, Link as LinkIcon, Trash2 } from 'lucide-react'
import {
  MAX_NAME_LENGTH, canonicalQuery, describeQuery, listSaved, removeSaved, saveSearch,
} from '../lib/savedSearches'
import { cleanLine } from '../lib/text'

function storage() {
  try {
    return window.localStorage
  } catch {
    return null
  }
}

/**
 * Copy the address of the current view. The filters live in the URL, so the
 * address is the view: whoever opens it (and is signed in) sees the same
 * question asked of the same data.
 */
export function ShareLink({ label = 'Copy link' }) {
  const [state, setState] = useState('idle')
  const timer = useRef(null)
  useEffect(() => () => clearTimeout(timer.current), [])

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href)
      setState('copied')
    } catch {
      setState('failed')
    }
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setState('idle'), 4000)
  }

  return (
    <span className="inline-flex items-center gap-2">
      <button type="button" className="control" onClick={copy}>
        <LinkIcon className="h-3.5 w-3.5" aria-hidden="true" />
        {label}
      </button>
      <span aria-live="polite" className="text-[12px] text-paper-3">
        {state === 'copied' && 'Link copied. Whoever opens it must sign in.'}
        {state === 'failed' && 'Copy the address from the browser bar instead.'}
      </span>
    </span>
  )
}

/**
 * Saved searches for one view.
 *
 * Kept in this browser only; the control says so, because a saved search that
 * silently fails to appear on another machine reads as lost work.
 */
export default function SavedSearches({ scope }) {
  const location = useLocation()
  const [items, setItems] = useState(() => listSaved(storage(), scope))
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [problem, setProblem] = useState(null)
  const root = useRef(null)

  const current = canonicalQuery(location.search)

  useEffect(() => {
    if (!open) return undefined
    const onKey = (event) => {
      if (event.key === 'Escape') setOpen(false)
    }
    const onPointer = (event) => {
      if (root.current && !root.current.contains(event.target)) setOpen(false)
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('pointerdown', onPointer)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('pointerdown', onPointer)
    }
  }, [open])

  const save = (event) => {
    event.preventDefault()
    const next = saveSearch(storage(), scope, name, location.search)
    if (!next) {
      setProblem(name.trim() ? 'This browser would not store it.' : 'Give the search a name.')
      return
    }
    setItems(next)
    setName('')
    setProblem(null)
  }

  return (
    <div className="relative" ref={root}>
      <button
        type="button"
        className="control"
        aria-expanded={open}
        aria-haspopup="dialog"
        onClick={() => setOpen((value) => !value)}
      >
        <Bookmark className="h-3.5 w-3.5" aria-hidden="true" />
        Saved searches
        {items.length > 0 && (
          <span className="readout rounded-full bg-ink-3 px-1.5 text-[12px] text-paper-2">{items.length}</span>
        )}
      </button>

      {open && (
        <div
          role="dialog"
          aria-label="Saved searches"
          className="panel absolute right-0 top-full z-30 mt-1 w-80 max-w-[calc(100vw-2rem)] shadow-lg"
        >
          {items.length === 0 ? (
            <p className="px-3.5 py-3 text-[13px] text-paper-3">
              Nothing saved yet. Set the filters you return to, then save them here.
            </p>
          ) : (
            <ul className="max-h-64 overflow-y-auto py-1">
              {items.map((item) => (
                <li key={item.name} className="flex items-center gap-1 px-1.5">
                  <Link
                    to={`${location.pathname}${item.query ? `?${item.query}` : ''}`}
                    onClick={() => setOpen(false)}
                    aria-current={item.query === current ? 'true' : undefined}
                    className="min-w-0 flex-1 rounded-[3px] px-2 py-1.5 transition-colors hover:bg-ink-2"
                  >
                    <span className="block truncate text-[13px] font-medium text-paper">{cleanLine(item.name)}</span>
                    <span className="readout block truncate text-[12px] text-paper-3">
                      {cleanLine(describeQuery(item.query))}
                    </span>
                  </Link>
                  <button
                    type="button"
                    onClick={() => setItems(removeSaved(storage(), scope, item.name))}
                    aria-label={`Delete saved search ${item.name}`}
                    className="shrink-0 rounded-[3px] p-1.5 text-paper-3 transition-colors hover:text-s4"
                  >
                    <Trash2 className="h-3.5 w-3.5" strokeWidth={1.75} />
                  </button>
                </li>
              ))}
            </ul>
          )}

          <form onSubmit={save} className="border-t border-line p-3">
            <label className="flex flex-col gap-1">
              <span className="eyebrow">Save the current filters as</span>
              <span className="flex gap-2">
                <input
                  type="text"
                  value={name}
                  maxLength={MAX_NAME_LENGTH}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="SSH exploitation this week"
                  className="field min-w-0 flex-1"
                />
                <button type="submit" className="control control-primary shrink-0">Save</button>
              </span>
            </label>
            {problem && <p role="alert" className="mt-1.5 text-[12px] text-s4">{problem}</p>}
            <p className="mt-2 text-[12px] leading-snug text-paper-3">
              Kept in this browser only. Use Copy link to share a view with someone else.
            </p>
          </form>
        </div>
      )}
    </div>
  )
}
