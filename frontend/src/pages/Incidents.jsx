import React, { useState } from 'react'
import { api } from '../api.js'
import { useLoad, Badge, fmt, Err, useVerified } from '../ui.jsx'

function Report({ id, user }) {
  const [r, err, reload] = useLoad(`/incidents/${id}/report`, [id])
  const [note, setNote] = useState(''); const [msg, setMsg] = useState('')
  const [ask, modal] = useVerified()
  if (!r) return <Err e={err} />
  const inc = r.incident, closed = inc.status === 'closed'
  const act = (action_type, target) => ask(`response_action:${id}:${action_type}`, async (vid) => {
    setMsg('')
    try { await api(`/incidents/${id}/actions`, { method: 'POST', body: { action_type, target, verification_id: vid } }); reload() } catch (e) { setMsg(e.message) }
  })
  const addNote = async () => { try { await api(`/incidents/${id}/notes`, { method: 'POST', body: { text: note } }); setNote(''); reload() } catch (e) { setMsg(e.message) } }
  const close = async () => { try { await api(`/incidents/${id}/close`, { method: 'POST' }); reload() } catch (e) { setMsg(e.message) } }
  return (<>
    <div className="card" style={{ marginBottom: 14 }}>
      <div className="row" style={{ justifyContent: 'space-between' }}><h2>Incident #{inc.id} — {inc.title}</h2><Badge v={inc.status} kind={closed ? 'ok' : 'neutral'} /></div>
      <div className="grid cols2">
        <div><h3>Who</h3>{r.who.length ? r.who.map((w) => <dl className="kv" key={w.user}><dt>Account</dt><dd className="mono">LAB\{w.user}</dd><dt>Name</dt><dd>{w.name}</dd><dt>Department</dt><dd>{w.department}</dd><dt>Privilege</dt><dd>{w.privilege_level}</dd></dl>) : <div className="sub">Unattributed</div>}</div>
        <div><h3>What</h3>{r.what.map((w) => <div key={w.technique}><span className="mono">{w.technique}</span> {w.name} <span style={{ color: 'var(--muted)' }}>({w.tactic})</span></div>)}
          <h3 style={{ marginTop: 10 }}>Where</h3>{r.where.join(', ')}
          <h3 style={{ marginTop: 10 }}>When</h3><div>First event {fmt(r.when.first_event)}<br />Last event {fmt(r.when.last_event)}<br />Opened {fmt(r.when.opened)}</div></div>
      </div>
      <Err e={msg} />
      {!closed && user.role === 'admin' && (<div className="row" style={{ marginTop: 12 }}>
        {r.where.map((h) => <button key={h} className="btn danger" onClick={() => act('isolate_endpoint', h)}>Isolate {h}</button>)}
        {r.where.map((h) => <button key={'r' + h} className="btn" onClick={() => act('release_endpoint', h)}>Release {h}</button>)}
        {r.who.map((w) => <button key={w.user} className="btn" onClick={() => act('flag_account', w.user)}>Flag account {w.user}</button>)}
        <button className="btn primary" onClick={close}>Close incident</button></div>)}
      {!closed && user.role !== 'admin' && <div className="row" style={{ marginTop: 12 }}><span className="sub" style={{ color: 'var(--muted)' }}>Response actions require an administrator.</span><button className="btn primary" onClick={close}>Close incident</button></div>}
    </div>
    <div className="grid cols2">
      <div className="card"><h2>Timeline (identity-correlated)</h2><div className="timeline">{r.timeline.map((e) => (
        <div className="tl" key={e.id}><div className="when">{fmt(e.timestamp)} · {e.hostname} · {e.event_type}</div>
          <div><b>{e.identity ? e.identity.sam_account_name : e.user_name || '?'}</b> — {e.rule}</div>
          {e.command_line && <div className="mono" style={{ wordBreak: 'break-all' }}>{e.command_line}</div>}</div>))}
        {!r.timeline.length && <div className="empty">No events</div>}</div></div>
      <div><div className="card" style={{ marginBottom: 14 }}><h2>Response actions</h2>
        {inc.actions.map((a) => <div key={a.id} style={{ marginBottom: 8 }}><b>{a.action_type}</b> → {a.target}<div style={{ color: 'var(--muted)', fontSize: 12 }}>{fmt(a.executed_at)} · verified #{a.verification_id} · {a.outcome}</div></div>)}
        {!inc.actions.length && <div className="empty">None yet</div>}</div>
        <div className="card"><h2>Notes</h2>
          {(inc.notes || []).map((n, i) => <div key={i} style={{ marginBottom: 8 }}><div style={{ color: 'var(--muted)', fontSize: 12 }}>{n.by} · {fmt(n.at)}</div>{n.text}</div>)}
          {!closed && <><textarea aria-label="New note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add an investigation note" /><button className="btn" disabled={!note.trim()} onClick={addNote} style={{ marginTop: 6 }}>Add note</button></>}</div></div>
    </div>
    {modal}
  </>)
}

export default function Incidents({ user, param }) {
  const [sel, setSel] = useState(param)
  const [rows, err] = useLoad('/incidents', [sel], 5000)
  return (<>
    <div className="head"><div><h1>Incidents</h1><div className="sub">Investigation and biometrically-verified response</div></div>{sel && <button className="btn" onClick={() => setSel(null)}>← All incidents</button>}</div>
    <Err e={err} />
    {sel ? <Report id={sel} user={user} /> :
      <div className="card tablewrap"><table><thead><tr><th>#</th><th>Title</th><th>Status</th><th>Owner</th><th>Tickets</th><th>Actions</th><th>Opened</th></tr></thead><tbody>
        {(rows || []).map((i) => <tr key={i.id} className="click" onClick={() => setSel(i.id)}><td>{i.id}</td><td>{i.title}</td><td>{i.status}</td><td>{i.owner}</td><td>{i.ticket_count}</td><td>{i.action_count}</td><td>{fmt(i.opened_at)}</td></tr>)}
        {rows && !rows.length && <tr><td colSpan="7" className="empty">No incidents. Open one from a ticket.</td></tr>}</tbody></table></div>}
  </>)
}
