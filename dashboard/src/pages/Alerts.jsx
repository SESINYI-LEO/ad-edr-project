import { Fragment, useState } from 'react'
import { get } from '../api/client.js'
import { fmt, useLive } from '../api/hooks.js'
import Badge from '../components/Badge.jsx'

export default function Alerts() {
  const [alerts] = useLive(() => get('/api/alerts'), 5000)
  const [open, setOpen] = useState(null)
  const [detail, setDetail] = useState(null)
  async function toggle(id) {
    if (open === id) return setOpen(null)
    setOpen(id); setDetail(null)
    setDetail(await get(`/api/alerts/${id}`))
  }
  return (
    <>
      <h1 className="page-title">Alerts</h1>
      <p className="page-subtitle">Raised when a behaviour rule matches identity-enriched telemetry. Click a row for the evidence.</p>
      <div className="data-panel"><table>
        <thead><tr><th>Alert</th><th>Host</th><th>ATT&CK</th><th>Confidence</th><th>Severity</th><th>Raised</th></tr></thead>
        <tbody>{(alerts || []).map((a) => (<Fragment key={a.id}>
          <tr className="clickable" onClick={() => toggle(a.id)}>
            <td>{a.title}</td><td className="mono">{a.hostname}</td><td className="mono">{a.mitre_technique || '—'}</td>
            <td className="mono">{Math.round(a.confidence * 100)}%</td><td><Badge level={a.severity} /></td><td className="mono">{fmt(a.created_at)}</td></tr>
          {open === a.id && <tr><td colSpan={6} style={{ background: 'var(--bg)' }}>
            <div className="muted" style={{ marginBottom: 6 }}>{a.description}</div>
            {!detail ? 'Loading…' : detail.events.map((e) => (
              <div key={e.id} className="mono" style={{ fontSize: 12, marginBottom: 4 }}>
                {fmt(e.timestamp)} · {e.event_type} · <b>{e.user ? `${e.user.username} (${e.user.privilege}, ${e.user.department || '—'})` : 'unattributed'}</b> · {e.command_line || e.registry_key || e.file_path || `${e.remote_address}:${e.remote_port}` || e.process_name}
              </div>))}
          </td></tr>}</Fragment>))}
          {!alerts?.length && <tr><td colSpan={6} className="empty-state">No alerts yet</td></tr>}</tbody></table></div>
    </>
  )
}
