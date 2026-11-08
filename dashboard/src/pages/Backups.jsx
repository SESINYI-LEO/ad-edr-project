import { useState } from 'react'
import { errMsg, get, isAdmin, post } from '../api/client.js'
import { fmt, useLive } from '../api/hooks.js'
import Badge from '../components/Badge.jsx'
import { useAuthGate } from '../components/AuthGate.jsx'

export default function Backups() {
  const gate = useAuthGate()
  const [rows, reload] = useLive(() => (isAdmin() ? get('/api/backups') : Promise.resolve([])), 0)
  const [msg, setMsg] = useState(null)
  const run = async (fn, ok) => { try { const r = await fn(); setMsg({ ok: true, text: typeof ok === 'function' ? ok(r) : ok }); reload() } catch (e) { if (e.message !== 'cancelled') setMsg({ text: errMsg(e) }) } }
  if (!isAdmin()) return <><h1 className="page-title">Backup & restore</h1><p className="muted">Administrator access required.</p></>
  return (
    <>
      <h1 className="page-title">Backup & restore</h1>
      <p className="page-subtitle">Encrypted, checksummed logical backups of telemetry, alerts, tickets, incidents and rules. Each backup is verified on creation.</p>
      {msg && <div className={`flash ${msg.ok ? 'ok' : 'err'}`}>{msg.text}</div>}
      <button className="btn" style={{ marginBottom: 14 }} onClick={() => run(async () => post('/api/backups', {}, await gate('backup_create')), 'Backup created and verified')}>Create backup…</button>
      <div className="data-panel"><table>
        <thead><tr><th>File</th><th>Size</th><th>SHA-256</th><th>Status</th><th>Created</th><th /></tr></thead>
        <tbody>{(rows || []).map((b) => (<tr key={b.id}><td className="mono" style={{ fontSize: 11 }}>{b.filename}</td><td>{(b.size_bytes / 1024).toFixed(1)} KB</td>
          <td className="mono" style={{ fontSize: 11 }}>{b.sha256.slice(0, 16)}…</td><td><Badge level={b.status} /></td><td className="mono">{fmt(b.created_at)}</td>
          <td><div className="row-actions">
            <button className="btn sm ghost" onClick={() => run(() => post(`/api/backups/${b.id}/verify`), 'Verification finished')}>Verify</button>
            <button className="btn sm danger" onClick={() => window.confirm('Restore replaces current telemetry, alerts, tickets, incidents and rules with this backup. Continue?') &&
              run(async () => post(`/api/backups/${b.id}/restore`, {}, await gate('backup_restore')), (r) => `Restored: ${Object.entries(r.restored).map(([k, v]) => `${k}=${v}`).join(', ')}`)}>Restore…</button></div></td></tr>))}
          {!rows?.length && <tr><td colSpan={6} className="empty-state">No backups yet</td></tr>}</tbody></table></div>
    </>
  )
}
