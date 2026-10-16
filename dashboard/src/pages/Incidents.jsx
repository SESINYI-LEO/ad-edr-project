import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { errMsg, get, isAdmin, patch, post } from '../api/client.js'
import { fmt, useLive } from '../api/hooks.js'
import Badge from '../components/Badge.jsx'
import { useAuthGate } from '../components/AuthGate.jsx'

export function IncidentList() {
  const [list, reload] = useLive(() => get('/api/incidents'), 6000)
  const [title, setTitle] = useState('')
  const [msg, setMsg] = useState(null)
  async function create(e) {
    e.preventDefault()
    try { await post('/api/incidents', { title }); setTitle(''); reload() } catch (x) { setMsg(errMsg(x)) }
  }
  return (
    <>
      <h1 className="page-title">Incidents</h1>
      <p className="page-subtitle">Open → Investigating → Contained (verified response) → Resolved → Closed (report required)</p>
      {msg && <div className="flash err">{msg}</div>}
      <form className="panel" onSubmit={create} style={{ display: 'flex', gap: 10 }}>
        <input className="inline-input" style={{ flex: 1 }} placeholder="New incident title (or escalate a ticket)" value={title} onChange={(e) => setTitle(e.target.value)} />
        <button className="btn" disabled={title.length < 3}>Create</button>
      </form>
      <div className="data-panel"><table>
        <thead><tr><th>Incident</th><th>Host</th><th>Status</th><th>Tickets</th><th>Reports</th><th>Opened</th></tr></thead>
        <tbody>{(list || []).map((i) => (
          <tr key={i.id} className="clickable"><td><Link to={`/incidents/${i.id}`}>{i.title}</Link></td><td className="mono">{i.hostname || '—'}</td>
            <td><Badge level={i.status} /></td><td>{i.ticket_count}</td><td>{i.report_count}</td><td className="mono">{fmt(i.created_at)}</td></tr>))}
          {!list?.length && <tr><td colSpan={6} className="empty-state">No incidents</td></tr>}</tbody></table></div>
    </>
  )
}

export function IncidentDetail() {
  const { id } = useParams()
  const gate = useAuthGate()
  const [inc, reload] = useLive(() => get(`/api/incidents/${id}`), 6000, [id])
  const [actions] = useLive(() => get('/api/response-actions'), 0)
  const [note, setNote] = useState('')
  const [action, setAction] = useState('isolate_endpoint')
  const [pid, setPid] = useState('')
  const [msg, setMsg] = useState(null)
  const [report, setReport] = useState(null)
  const ok = (m) => setMsg({ ok: true, text: m })
  const run = async (fn, success) => {
    try { await fn(); ok(success); reload() } catch (e) { if (e.message !== 'cancelled') setMsg({ text: errMsg(e) }) }
  }
  if (!inc) return <div className="muted">Loading…</div>
  const setStatus = (status) => run(() => patch(`/api/incidents/${id}`, { status }), `Status → ${status}`)
  const respond = () => run(async () => {
    const tx = await gate('response_action')
    await post(`/api/incidents/${id}/response`, { action, params: action === 'kill_process' ? { pid } : {} }, tx)
  }, 'Response executed and audited. Incident is now contained.')
  const shown = report || inc.reports[0]?.content
  const download = () => {
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([shown], { type: 'text/markdown' }))
    a.download = `incident-${id.slice(0, 8)}.md`; a.click()
  }
  return (
    <>
      <Link to="/incidents" className="muted">← Incidents</Link>
      <h1 className="page-title" style={{ marginTop: 6 }}>{inc.title} <Badge level={inc.status} /></h1>
      <p className="page-subtitle">{inc.hostname ? `Endpoint ${inc.hostname} · ` : ''}opened {fmt(inc.created_at)}</p>
      {msg && <div className={`flash ${msg.ok ? 'ok' : 'err'}`}>{msg.text}</div>}

      <div className="panel"><h3>Workflow</h3><div className="row-actions">
        {inc.status === 'open' && <button className="btn sm" onClick={() => setStatus('investigating')}>Start investigating</button>}
        {inc.status === 'contained' && <button className="btn sm" onClick={() => setStatus('resolved')}>Mark resolved (threat eradicated)</button>}
        {inc.status === 'resolved' && <button className="btn sm" onClick={() => setStatus('closed')}>Close incident</button>}
        {['open', 'investigating'].includes(inc.status) && <button className="btn sm ghost" onClick={() => setStatus('closed')}>Close as false positive</button>}
        <button className="btn sm ghost" onClick={() => run(async () => setReport((await post(`/api/incidents/${id}/report`)).content), 'Report generated')}>Generate report</button>
      </div></div>

      {inc.status === 'investigating' && (
        <div className="panel"><h3>Response action (Administrator + QR/biometric verification)</h3>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <select value={action} onChange={(e) => setAction(e.target.value)}>{Object.keys(actions || {}).map((a) => <option key={a}>{a}</option>)}</select>
            {action === 'kill_process' && <input className="inline-input" placeholder="PID" value={pid} onChange={(e) => setPid(e.target.value)} style={{ width: 90 }} />}
            <button className="btn danger" disabled={!isAdmin()} onClick={respond}>Execute…</button>
            {!isAdmin() && <span className="muted">Only an Administrator can execute response actions</span>}
          </div>
          <div className="muted" style={{ marginTop: 8, fontSize: 12 }}>{actions?.[action]}</div></div>)}

      <div className="grid2">
        <div className="panel"><h3>Linked tickets</h3><table><tbody>{inc.tickets.map((t) => (
          <tr key={t.id}><td>{t.title}</td><td className="mono">{t.priority_score}</td><td><Badge level={t.status} /></td></tr>))}
          {!inc.tickets.length && <tr><td className="muted">None</td></tr>}</tbody></table></div>
        <div className="panel"><h3>Investigation notes</h3>
          <pre className="report" style={{ maxHeight: 160 }}>{inc.notes || 'No notes yet.'}</pre>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <input className="inline-input" style={{ flex: 1 }} placeholder="Add a note" value={note} onChange={(e) => setNote(e.target.value)} />
            <button className="btn sm" disabled={!note} onClick={() => run(async () => { await patch(`/api/incidents/${id}`, { notes: note }); setNote('') }, 'Note added')}>Add</button></div></div>
      </div>

      {shown && <div className="panel"><h3>Incident report</h3><pre className="report">{shown}</pre>
        <button className="btn sm ghost" style={{ marginTop: 8 }} onClick={download}>Download .md</button></div>}
    </>
  )
}
