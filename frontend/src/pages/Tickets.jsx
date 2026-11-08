import React, { useState } from 'react'
import { api } from '../api.js'
import { useLoad, Badge, fmt, Err } from '../ui.jsx'

const NEXT = { Escalated: [], New: ['Assigned'], Assigned: ['Under Investigation'], 'Under Investigation': ['Resolved'], Resolved: ['Closed', 'Under Investigation'], Closed: [] }

export default function Tickets({ go }) {
  const [pri, setPri] = useState(''); const [st, setSt] = useState(''); const [msg, setMsg] = useState('')
  const [rows, err, reload] = useLoad(`/tickets?${pri ? `priority=${pri}&` : ''}${st ? `status=${encodeURIComponent(st)}` : ''}`, [], 5000)
  const move = async (t, status) => {
    setMsg('')
    try { await api(`/tickets/${t.id}/transition`, { method: 'POST', body: { status } }); reload() } catch (e) { setMsg(e.message) }
  }
  const toIncident = async (t) => {
    setMsg('')
    try { const i = await api('/incidents', { method: 'POST', body: { ticket_id: t.id } }); go('incidents', i.id) } catch (e) { setMsg(e.message) }
  }
  return (<>
    <div className="head"><div><h1>Tickets</h1><div className="sub">Risk-ranked: severity, confidence, asset criticality and user privilege</div></div></div>
    <div className="filters">
      <select aria-label="Priority" value={pri} onChange={(e) => setPri(e.target.value)}><option value="">All priorities</option>{['Critical', 'High', 'Medium', 'Low'].map((s) => <option key={s}>{s}</option>)}</select>
      <select aria-label="Status" value={st} onChange={(e) => setSt(e.target.value)}><option value="">All statuses</option>{Object.keys(NEXT).map((s) => <option key={s}>{s}</option>)}</select>
    </div>
    <Err e={err || msg} />
    <div className="card tablewrap"><table><thead><tr><th>#</th><th>Priority</th><th>Score</th><th>Status</th><th>Rule</th><th>Host</th><th>User</th><th>Assignee</th><th>Created</th><th>Actions</th></tr></thead><tbody>
      {(rows || []).map((t) => (<tr key={t.id}><td>{t.id}</td><td><Badge v={t.priority} /></td><td>{t.priority_score.toFixed(1)}</td><td>{t.status}</td><td>{t.rule_name}</td><td>{t.hostname}</td><td>{t.user || '—'}</td><td>{t.assignee || '—'}</td><td>{fmt(t.created_at)}</td>
        <td><div className="row">{NEXT[t.status].map((s) => <button key={s} className="btn sm" onClick={() => move(t, s)}>{s === 'Under Investigation' && t.status === 'Resolved' ? 'Reopen' : s}</button>)}
          {!t.incident_id && t.status !== 'Closed' && <button className="btn sm primary" onClick={() => toIncident(t)}>Open incident</button>}
          {t.incident_id && <button className="btn sm" onClick={() => go('incidents', t.incident_id)}>Incident #{t.incident_id}</button>}</div></td></tr>))}
      {rows && !rows.length && <tr><td colSpan="10" className="empty">No tickets</td></tr>}
    </tbody></table></div>
  </>)
}
