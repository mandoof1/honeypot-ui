/**
 * The heading every page opens with: what the page is, one line on what it
 * is for, and the page-level actions. Having a real <h1> on each view is also
 * what a screen-reader user lands on after a route change.
 */
export default function PageHeader({ eyebrow, title, description, children }) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        {eyebrow && <p className="eyebrow mb-1">{eyebrow}</p>}
        <h1 className="text-2xl">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-sm text-paper-2">{description}</p>}
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </header>
  )
}
