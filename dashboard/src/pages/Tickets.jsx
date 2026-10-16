import { useState } from 'react'
import { Link } from 'react-router-dom'
import { errMsg, get, post } from '../api/client.js'
import { fmt, useLive } from '../api/hooks.js'
import Badge from '../components/Badge.jsx'

export default function Tickets() {
  const [tickets, reload] = useLive(() => get('/api/tickets'), 5000)
  const [msg, setMsg] = useState(null)
  async function act(fn) {
    try { const r = await fn(); setMsg(null); reload(); return r } catch (e) { setMsg(errMsg(e)) }
  }
  const move = (t, status) => act(() => post(`/api/tickets/${t.id}/transition`, { status }))
  return (
    <>
      <h1 className="page-title">Tickets</h1>
      <p className="page-subtitle">Priority Score = severity + AD privilege + asset criticality + confidence + frequency. Highest first.</p>
      {msg && <div className="flash err">{msg}</div>}
      <div className="data-panel"><table>
        <thead><tr><th>Score</th><th>Priority</th><th>Ticket</th><th>Host</th><th>Status</th><th>Assignee</th><th>Actions</th></tr></thead>
        <tbody>{(tickets || []).map((t) => (
          <tr key={t.id}>
            <td className="mono">{t.priority_score}</td><td><Badge level={t.priority} /></td>
            <td>{t.title}<div className="muted mono" style={{ fontSize: 11 }}>{t.mitre_technique} · {fmt(t.created_at)}</div></td>
            <td className="mono">{t.hostname}</td><td><Badge level={t.status} /></td><td>{t.assigned_to || '—'}</td>
            <td><div className="row-actions">
              {t.status === 'prioritised' && <button className="btn sm" onClick={() => act(() => post(`/api/tickets/${t.id}/assign`, {}))}>Take</button>}
              {t.status === 'under_investigation' && <>
                <button className="btn sm ghost" onClick={() => move(t, 'false_positive')}>False positive</button>
                <button className="btn sm ghost" onClick={() => move(t, 'resolved')}>Resolve</button>
                <button className="btn sm danger" onClick={() => act(() => post(`/api/tickets/${t.id}/escalate`))}>Escalate</button></>}
              {t.status === 'resolved' && <button className="btn sm ghost" onClick={() => move(t, 'closed')}>Close</button>}
              {t.incident_id && <Link className="btn sm ghost" to={`/incidents/${t.incident_id}`}>Incident →</Link>}
            </div></td></tr>))}
          {!tickets?.length && <tr><td colSpan={7} className="empty-state">No tickets</td></tr>}</tbody></table></div>
    </>
  )
}
