import { useState } from 'react'
import { Copy, Download, ExternalLink, X } from 'lucide-react'
import { api } from '../services/api'

/*
 * Payload detail.
 *
 * Renders one sample's static-analysis report, built to read top-down: what
 * the file is, what it can do, who it talks to, what it was built with, and
 * every session it arrived in. Every claim the analyser hedges (a family
 * hint, a forgeable build path) is shown hedged.
 */

function Block({ title, note, children }) {
  return (
    <section className="border-t border-line px-4 py-3.5">
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="eyebrow">{title}</h3>
        {note && <span className="text-[12px] text-paper-3">{note}</span>}
      </div>
      <div className="mt-2.5">{children}</div>
    </section>
  )
}

function Fact({ label, children, mono = true, title }) {
  return (
    <div className="min-w-0">
      <dt className="eyebrow">{label}</dt>
      <dd className={`mt-1 break-words text-[13px] text-paper ${mono ? 'readout' : ''}`} title={title}>
        {children}
      </dd>
    </div>
  )
}

function Hash({ label, value }) {
  const [copied, setCopied] = useState(false)
  if (!value) return null
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1200) } catch { /* selectable on screen */ }
  }
  return (
    <div className="flex items-center gap-2">
      <span className="eyebrow w-12 shrink-0">{label}</span>
      <span className="readout min-w-0 flex-1 truncate text-[12px] text-paper-2" title={value}>{value}</span>
      <button type="button" onClick={copy} aria-label={`Copy ${label}`} className="shrink-0 rounded-[3px] p-1 text-paper-3 hover:text-paper">
        <Copy className="h-3.5 w-3.5" strokeWidth={2} />
      </button>
      {copied && <span className="text-[11px] text-paper-3">copied</span>}
    </div>
  )
}

function Techniques({ items }) {
  if (!items?.length) return null
  return (
    <ul className="mt-2 space-y-1">
      {items.map((cap, i) => {
        const t = cap.technique
        return (
          <li key={cap.id || i} className="flex items-baseline gap-2 text-[13px]">
            <span className="min-w-0 flex-1 text-paper">{cap.label}</span>
            {t?.id && (
              <a href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
                target="_blank" rel="noreferrer noopener"
                className="readout shrink-0 text-[11px] text-paper-3 hover:text-paper">
                {t.id}
              </a>
            )}
          </li>
        )
      })}
    </ul>
  )
}

const IOC_GROUPS = [
  ['ips', 'Addresses', (i) => i.port ? `${i.value}:${i.port}` : i.value],
  ['domains', 'Domains', (i) => i.value],
  ['urls', 'URLs', (i) => i.value],
  ['mining_pools', 'Mining pools', (i) => i.value],
  ['wallets', 'Wallets', (i) => `${i.currency} ${i.value}`],
  ['c2_channels', 'Operator channels', (i) => i.value],
  ['ssh_keys', 'SSH keys', (i) => `${i.type} ${i.fingerprint}`],
  ['emails', 'Emails', (i) => i.value],
  ['user_agents', 'User agents', (i) => i.value],
]

function Indicators({ indicators }) {
  if (!indicators) return null
  const groups = IOC_GROUPS.filter(([key]) => indicators[key]?.length)
  if (!groups.length) return <p className="text-[13px] text-paper-3">None recovered.</p>
  return (
    <div className="space-y-3">
      {groups.map(([key, label, render]) => (
        <div key={key}>
          <p className="eyebrow mb-1 text-paper-3">{label}</p>
          <ul className="space-y-0.5">
            {indicators[key].map((item, i) => (
              <li key={i} className="readout flex items-baseline gap-2 break-all text-[12px] text-paper-2">
                <span className="min-w-0 flex-1">{render(item)}</span>
                {item.scope === 'private' && <span className="shrink-0 text-[10px] text-paper-3">private</span>}
                {item.origin && item.origin !== 'strings' && (
                  <span className="shrink-0 text-[10px] text-paper-3" title="Where in the file this was found">{item.origin}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  )
}

function Sections({ sections }) {
  const notable = (sections || []).filter((s) => s.entropy != null).slice(0, 12)
  if (!notable.length) return null
  return (
    <div className="mt-2 overflow-x-auto">
      <table className="w-full text-left text-[12px]">
        <thead><tr className="text-paper-3">
          <th className="eyebrow py-1 pr-3 font-normal">Section</th>
          <th className="eyebrow py-1 pr-3 font-normal">Size</th>
          <th className="eyebrow py-1 font-normal">Entropy</th>
        </tr></thead>
        <tbody>
          {notable.map((s, i) => (
            <tr key={i} className="border-t border-line">
              <td className="readout py-1 pr-3 text-paper-2">{s.name || '(unnamed)'}</td>
              <td className="readout py-1 pr-3 tabular-nums text-paper-3">{(s.size ?? s.raw_size ?? 0).toLocaleString()}</td>
              <td className={`readout py-1 tabular-nums ${s.entropy >= 7.2 ? 'text-s3' : 'text-paper-3'}`}>{s.entropy?.toFixed(2)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function KeyValues({ data, limit = 12 }) {
  const entries = Object.entries(data || {}).slice(0, limit)
  if (!entries.length) return null
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[12px]">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="eyebrow text-paper-3">{key}</dt>
          <dd className="readout break-words text-paper-2">{String(value)}</dd>
        </div>
      ))}
    </dl>
  )
}

export default function PayloadDetail({ detail, canDownload, onClose }) {
  const [downloading, setDownloading] = useState(false)
  const [downloadError, setDownloadError] = useState(null)
  const a = detail.analysis || {}
  const elf = a.elf
  const pe = a.pe
  const script = a.script
  const archive = a.archive

  const download = async () => {
    setDownloading(true)
    setDownloadError(null)
    try {
      const { blob, filename } = await api.payloads.download(detail.sha256)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (err) {
      setDownloadError(err.message)
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="flex h-full flex-col overflow-y-auto">
      <header className="flex items-start justify-between gap-3 px-4 pb-3 pt-4">
        <div className="min-w-0">
          <h2 className="text-[15px] font-semibold text-paper">
            {detail.summary || detail.file_type || 'Sample'}
          </h2>
          <p className="mt-1 flex flex-wrap items-center gap-1.5">
            {detail.family && <span className="tag" style={{ color: 'var(--color-s3)' }}>{detail.family}</span>}
            <span className="tag" style={{ color: 'var(--color-paper-3)' }}>{detail.analysis_status}</span>
            {detail.analysis?.file_type?.basis === 'heuristic' && (
              <span className="tag" style={{ color: 'var(--color-paper-3)' }} title="Type inferred from content, not a magic number">by content</span>
            )}
          </p>
        </div>
        {onClose && (
          <button type="button" onClick={onClose} aria-label="Close" className="shrink-0 rounded-[3px] p-1 text-paper-3 hover:text-paper lg:hidden">
            <X className="h-5 w-5" strokeWidth={1.75} />
          </button>
        )}
      </header>

      {/* This is live malware. Say so where anyone about to download it looks. */}
      {canDownload && (
        <div className="mx-4 mb-1 flex items-center justify-between gap-3">
          <button className="control" onClick={download} disabled={downloading || !detail.content_available}
            title={detail.content_available ? 'Downloads the raw sample — handle as live malware' : 'No content stored for this sample'}>
            <Download className="h-3.5 w-3.5" />{downloading ? 'Preparing…' : 'Download sample'}
          </button>
          {downloadError && <span className="text-[12px] text-s4">{downloadError}</span>}
        </div>
      )}

      <dl className="grid grid-cols-2 gap-x-4 gap-y-3 border-t border-line px-4 py-3.5">
        <Fact label="Type" mono={false}>{detail.file_type || detail.file_kind || 'Unknown'}</Fact>
        <Fact label="Size">{(detail.size ?? 0).toLocaleString()} bytes</Fact>
        <Fact label="Entropy" title="Bits per byte; ~8 means encrypted or packed">
          {typeof a.entropy === 'number' ? a.entropy.toFixed(2) : '—'}
        </Fact>
        <Fact label="Seen in">{detail.sessions_seen} session{detail.sessions_seen === 1 ? '' : 's'}</Fact>
      </dl>

      <Block title="Hashes">
        <div className="space-y-1.5">
          <Hash label="SHA-256" value={detail.sha256} />
          <Hash label="SHA-1" value={detail.sha1} />
          <Hash label="MD5" value={detail.md5} />
          {pe?.imphash && <Hash label="imphash" value={pe.imphash} />}
        </div>
      </Block>

      {detail.analysis_status === 'failed' && (
        <Block title="Analysis">
          <p className="text-[13px] text-paper-2">This sample could not be analysed: {detail.analysis_error || 'unknown error'}.</p>
        </Block>
      )}
      {detail.analysis_status === 'metadata_only' && (
        <Block title="Analysis">
          <p className="text-[13px] text-paper-2">Only this file's hash was captured — its bytes were over the forwarding budget — so there is no static report. The hash and the sessions below are still recorded.</p>
        </Block>
      )}

      {a.notable?.length > 0 && (
        <Block title="Notable">
          <ul className="space-y-1">
            {a.notable.map((note, i) => (
              <li key={i} className="flex items-baseline gap-2 text-[13px] text-paper">
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-s3" aria-hidden="true" />
                <span className="min-w-0">{note}</span>
              </li>
            ))}
          </ul>
        </Block>
      )}

      {detail.family && a.family && (
        <Block title="Family" note={`${Math.round((a.family.confidence || 0) * 100)}% · heuristic`}>
          <p className="text-[13px] text-paper-2">
            Resembles <span className="text-paper">{a.family.family}</span> ({a.family.kind}). This is a heuristic match on {a.family.evidence?.length || 0} marker(s), not a verdict:
          </p>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {(a.family.evidence || []).map((e, i) => (
              <span key={i} className="readout rounded-[3px] bg-ink-2 px-1.5 py-0.5 text-[11px] text-paper-3">{e}</span>
            ))}
          </div>
        </Block>
      )}

      {elf && !elf.error && (
        <Block title="ELF binary">
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
            <Fact label="Architecture" mono={false}>{elf.architecture}</Fact>
            <Fact label="Linking" mono={false}>{elf.linking}{elf.stripped ? ', stripped' : ''}</Fact>
          </dl>
          {elf.capabilities?.length > 0 && (
            <p className="mt-2 flex flex-wrap gap-1">
              {elf.capabilities.map((c) => <span key={c} className="tag" style={{ color: 'var(--color-s2)' }}>{c}</span>)}
            </p>
          )}
          {elf.libraries?.length > 0 && (
            <p className="mt-2 text-[12px] text-paper-3">Links: <span className="readout text-paper-2">{elf.libraries.join(', ')}</span></p>
          )}
          {elf.build && Object.keys(elf.build).length > 0 && (
            <div className="mt-2">
              <p className="eyebrow mb-1 text-paper-3">Build fingerprints <span className="normal-case">(forgeable)</span></p>
              <KeyValues data={elf.build} />
            </div>
          )}
          <Sections sections={elf.sections} />
        </Block>
      )}

      {pe && !pe.error && (
        <Block title="Windows PE">
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
            <Fact label="Architecture" mono={false}>{pe.architecture}{pe.dotnet ? ' · .NET' : ''}</Fact>
            <Fact label="Subsystem" mono={false}>{pe.subsystem}</Fact>
            {pe.compile_time && <Fact label="Compiled">{pe.compile_time.slice(0, 10)}</Fact>}
            {pe.rich_hash && <Fact label="Rich hash">{pe.rich_hash.slice(0, 16)}…</Fact>}
          </dl>
          {pe.compile_time_note && <p className="mt-1.5 text-[12px] text-s3">Compile time {pe.compile_time_note}</p>}
          {pe.pdb_path && (
            <p className="mt-2 text-[12px] text-paper-3">Build path <span className="normal-case">(forgeable)</span>: <span className="readout break-all text-paper-2">{pe.pdb_path}</span></p>
          )}
          <Techniques items={pe.capabilities} />
          {pe.version_info && Object.keys(pe.version_info).length > 0 && (
            <div className="mt-2"><p className="eyebrow mb-1 text-paper-3">Version resource</p><KeyValues data={pe.version_info} /></div>
          )}
        </Block>
      )}

      {script && (
        <Block title="Script"
          note={script.obfuscation?.layers ? `${script.obfuscation.layers} obfuscation layer(s)` : undefined}>
          {script.obfuscation?.encodings?.length > 0 && (
            <p className="mb-2 text-[12px] text-paper-3">
              Unwrapped: {script.obfuscation.encodings.join(', ')} (depth {script.obfuscation.max_depth})
            </p>
          )}
          {script.behaviours?.length > 0 ? (
            <Techniques items={script.behaviours} />
          ) : (
            <p className="text-[13px] text-paper-3">No notable behaviours matched.</p>
          )}
        </Block>
      )}

      {archive && (
        <Block title="Archive" note={`${archive.member_count || 0} file(s)`}>
          <ul className="space-y-0.5">
            {(archive.members || []).slice(0, 30).map((m, i) => (
              <li key={i} className="readout flex items-baseline justify-between gap-3 text-[12px]">
                <span className="min-w-0 truncate text-paper-2" title={m.name}>{m.name}</span>
                <span className="shrink-0 tabular-nums text-paper-3">{(m.size || 0).toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </Block>
      )}

      <Block title="Indicators" note={a.indicator_count ? String(a.indicator_count) : undefined}>
        <Indicators indicators={a.indicators} />
      </Block>

      <Block title="Sessions" note={String(detail.sessions?.length || 0)}>
        {detail.sessions?.length ? (
          <ul className="space-y-1.5">
            {detail.sessions.map((s) => (
              <li key={`${s.session_id}:${s.filename}`}>
                <a href={`/sessions?session=${s.session_id}`}
                  className="group flex items-baseline gap-2 rounded-[3px] px-1.5 py-1 -mx-1.5 transition-colors hover:bg-ink-2">
                  <span className="readout shrink-0 text-[12px] text-paper-2">{s.attacker_ip}</span>
                  <span className="min-w-0 flex-1 truncate text-[12px] text-paper-3" title={s.remote_path || s.filename}>
                    {s.source} · {s.remote_path || s.filename}
                  </span>
                  <ExternalLink className="h-3 w-3 shrink-0 text-paper-3 opacity-0 transition-opacity group-hover:opacity-100" strokeWidth={2} />
                </a>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[13px] text-paper-3">No sessions linked.</p>
        )}
      </Block>
    </div>
  )
}
