import React, { useState } from 'react'
import { api } from '../api.js'
import { useLoad, Badge, fmt, Modal, Err } from '../ui.jsx'

function Detail({ id, onClose, onChange }) {
  const [a, err, reload] = useLoad(`/alerts/${id}`)
  const [e2, setE2] = useState('')
  const ack = async () => { try { await api(`/alerts/${id}/acknowledge`, { method: 'POST' }); reload(); onChange() } catch (x) { setE2(x.message) } }
  return (
    <Modal onClose={onClose}>
      {!a ? <Err e={err} /> : (<div style={{ maxHeight: '80vh', overflow: 'auto', paddingRight: 6 }}>
        <div className="row" style={{ justifyContent: 'space-between' }}><h2>{a.rule_name}</h2><Badge v={a.severity} /></div>
        <p style={{ color: 'var(--ink2)' }}>{a.description}</p>
        <dl className="kv">
          <dt>Summary</dt><dd>{a.summary}</dd>
          <dt>ATT&amp;CK</dt><dd>{a.technique} · {a.tactic}</dd>
          <dt>Host</dt><dd>{a.hostname}</dd>
          <dt>Confidence</dt><dd>{Math.round(a.confidence)}%</dd>
          <dt>Status</dt><dd>{a.status}</dd>
          <dt>Ticket</dt><dd>{a.ticket_id ? <>#{a.ticket_id} <Badge v={a.priority} /></> : '—'}</dd>
        </dl>
        <h3 style={{ margin: '12px 0 6px' }}>Responsible identity (Active Directory)</h3>
        {a.identity ? <dl className="kv">
          <dt>Account</dt><dd className="mono">LAB\{a.identity.sam_account_name}</dd><dt>Name</dt><dd>{a.identity.display_name}</dd>
          <dt>Department</dt><dd>{a.identity.department}</dd><dt>Privilege</dt><dd><Badge v={a.identity.privilege_level} kind="neutral" /></dd>
          <dt>Groups</dt><dd>{(a.identity.groups || []).join(', ') || '—'}</dd><dt>SID</dt><dd className="mono">{a.identity.sid}</dd>
        </dl> : <div className="sub" style={{ color: 'var(--muted)' }}>Not attributed (no matching AD account).</div>}
        <h3 style={{ margin: '12px 0 6px' }}>Evidence ({a.events.length} events)</h3>
        <div className="timeline">{a.events.map((e) => (
          <div className="tl" key={e.id}><div className="when">{fmt(e.timestamp)} · {e.event_type}</div>
            <div>{e.process_name || e.details?.target_filename || e.details?.dest_ip || ''}</div>
            {e.command_line && <div className="mono" style={{ wordBreak: 'break-all' }}>{e.command_line}</div>}
          </div>))}</div>
        <Err e={e2} />
        <div className="row" style={{ justifyContent: 'flex-end', marginTop: 10 }}>
          {a.status === 'new' && <button className="btn primary" onClick={ack}>Acknowledge</button>}
          <button className="btn" onClick={onClose}>Close</button></div>
      </div>)}
    </Modal>)
}

export default function Alerts({ param }) {
  const [sev, setSev] = useState(''); const [st, setSt] = useState(''); const [open, setOpen] = useState(param)
  const q = `/alerts?limit=200${sev ? `&severity=${sev}` : ''}${st ? `&status=${st}` : ''}`
  const [rows, err, reload] = useLoad(q, [], 5000)
  return (<>
    <div className="head"><div><h1>Alerts</h1><div className="sub">Detections correlated with Active Directory identity</div></div></div>
    <div className="filters">
      <select aria-label="Severity" value={sev} onChange={(e) => setSev(e.target.value)}><option value="">All severities</option>{['critical', 'high', 'medium', 'low'].map((s) => <option key={s}>{s}</option>)}</select>
      <select aria-label="Status" value={st} onChange={(e) => setSt(e.target.value)}><option value="">All statuses</option>{['new', 'acknowledged', 'closed'].map((s) => <option key={s}>{s}</option>)}</select>
    </div>
    <Err e={err} />
    <div className="card tablewrap"><table><thead><tr><th>#</th><th>Time</th><th>Severity</th><th>Rule</th><th>Technique</th><th>Host</th><th>User</th><th>Priority</th><th>Status</th></tr></thead><tbody>
      {(rows || []).map((r) => (<tr key={r.id} className="click" onClick={() => setOpen(r.id)}><td>{r.id}</td><td>{fmt(r.created_at)}</td><td><Badge v={r.severity} /></td><td>{r.rule_name}{r.event_count > 1 ? ` ×${r.event_count}` : ''}</td><td className="mono">{r.technique}</td><td>{r.hostname}</td><td>{r.user || '—'}</td><td>{r.priority ? <Badge v={r.priority} /> : '—'}</td><td>{r.status}</td></tr>))}
      {rows && !rows.length && <tr><td colSpan="9" className="empty">No alerts match</td></tr>}
    </tbody></table></div>
    {open && <Detail id={open} onClose={() => setOpen(null)} onChange={reload} />}
  </>)
}
