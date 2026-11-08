import React, { useState } from 'react'
import { api } from '../api.js'
import { useLoad, fmt, Err, useVerified, DeviceSetup, Badge } from '../ui.jsx'
import { phoneDeviceId } from '../phone.js'

function Backups() {
  const [rows, err, reload] = useLoad('/backups'); const [msg, setMsg] = useState(''); const [ok, setOk] = useState('')
  const [ask, modal] = useVerified()
  const run = (fn) => async () => { setMsg(''); setOk(''); try { await fn() ; reload() } catch (e) { setMsg(e.message) } }
  const create = () => ask('backup:create', (vid) => run(async () => { await api('/backups', { method: 'POST', body: { verification_id: vid } }); setOk('Backup created') })())
  const verify = (b) => run(async () => { const r = await api(`/backups/${b.id}/verify`, { method: 'POST' }); setOk(`Backup #${b.id}: ${r.ok ? `checksum and contents valid (${r.rows} rows)` : 'INVALID'}`) })()
  const restore = (b) => ask(`backup:restore:${b.id}`, (vid) => run(async () => { const r = await api(`/backups/${b.id}/restore`, { method: 'POST', body: { verification_id: vid } }); setOk(`Restored backup #${b.id}`) })())
  return (<div className="card"><div className="row" style={{ justifyContent: 'space-between' }}><h2>Backups (encrypted, checksummed)</h2><button className="btn primary" onClick={create}>Create backup</button></div>
    <Err e={err || msg} />{ok && <div className="okmsg">{ok}</div>}
    <div className="tablewrap"><table><thead><tr><th>#</th><th>Created</th><th>Size</th><th>Checksum</th><th>Status</th><th></th></tr></thead><tbody>
      {(rows || []).map((b) => <tr key={b.id}><td>{b.id}</td><td>{fmt(b.created_at)}</td><td>{b.size_bytes} B</td><td className="mono">{b.checksum}…</td><td>{b.status}</td><td><div className="row"><button className="btn sm" onClick={() => verify(b)}>Verify</button><button className="btn sm danger" onClick={() => restore(b)}>Restore</button></div></td></tr>)}
      {rows && !rows.length && <tr><td colSpan="6" className="empty">No backups</td></tr>}</tbody></table></div>{modal}</div>)
}

function Terminal() {
  const [tools] = useLoad('/tools'); const [name, setName] = useState('system_stats'); const [arg, setArg] = useState('')
  const [out, setOut] = useState(''); const [err, setErr] = useState(''); const [ask, modal] = useVerified()
  const go = () => ask(`tool:${name}`, async (vid) => {
    setErr('')
    let args = {}
    if (arg.trim()) { try { args = JSON.parse(arg) } catch { setErr('Arguments must be JSON, e.g. {"sam":"tkgosi"} or {"host":"127.0.0.1","port":8000}'); return } }
    try { const r = await api('/tools/run', { method: 'POST', body: { name, args, verification_id: vid } }); setOut(JSON.stringify(r.result, null, 2)) } catch (e) { setErr(e.message) }
  })
  const cur = (tools || []).find((t) => t.name === name)
  return (<div className="card"><h2>Security tool terminal</h2>
    <p style={{ color: 'var(--muted)', margin: '0 0 8px' }}>Allow-listed diagnostic tools only — there is no shell. Each run needs biometric verification and is audited.</p>
    <div className="row"><select aria-label="Tool" value={name} onChange={(e) => setName(e.target.value)}>{(tools || []).map((t) => <option key={t.name}>{t.name}</option>)}</select>
      <input aria-label="Arguments (JSON)" style={{ flex: 1, minWidth: 220 }} placeholder='args JSON, e.g. {"sam":"tkgosi"}' value={arg} onChange={(e) => setArg(e.target.value)} />
      <button className="btn primary" onClick={go}>Run</button></div>
    {cur && <div style={{ color: 'var(--muted)', fontSize: 12.5, marginTop: 6 }}>{cur.description}</div>}
    <Err e={err} />{out && <pre className="mono" aria-label="Tool output">{out}</pre>}{modal}</div>)
}

function Users() {
  const [rows, err, reload] = useLoad('/users'); const [f, setF] = useState({ username: '', password: '', role: 'analyst', full_name: '' }); const [m, setM] = useState('')
  const add = async () => { setM(''); try { await api('/users', { method: 'POST', body: f }); setF({ ...f, username: '', password: '' }); reload() } catch (e) { setM(e.message) } }
  return (<div className="card"><h2>System users</h2><Err e={err || m} />
    <div className="tablewrap"><table><thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Source</th><th>Status</th></tr></thead><tbody>{(rows || []).map((u) => <tr key={u.id}><td>{u.username}</td><td>{u.full_name}</td><td>{u.role}</td><td>{u.auth_source}</td><td>{u.status}</td></tr>)}</tbody></table></div>
    <div className="row" style={{ marginTop: 10 }}><input placeholder="username" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /><input placeholder="full name" value={f.full_name} onChange={(e) => setF({ ...f, full_name: e.target.value })} />
      <input type="password" placeholder="password (min 10)" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} />
      <select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}><option>analyst</option><option>admin</option></select><button className="btn primary" onClick={add}>Add user</button></div></div>)
}

export default function Admin() {
  const [tab, setTab] = useState('device')
  const [devs, , reload] = useLoad('/devices')
  return (<>
    <div className="head"><div><h1>Administration</h1><div className="sub">Authenticator device, backups, tool terminal and accounts</div></div></div>
    <div className="tabs">{[['device', 'Authenticator device'], ['backups', 'Backup & restore'], ['tools', 'Tool terminal'], ['users', 'Users']].map(([k, l]) => <button key={k} className={tab === k ? 'on' : ''} onClick={() => setTab(k)}>{l}</button>)}</div>
    {tab === 'device' && <div className="card"><h2>Authenticator devices</h2>
      <p>Enrolled for your account: {(devs || []).map((d) => <Badge key={d.id} v={`#${d.id} ${d.name}`} kind="neutral" />)} {devs && !devs.length && 'none'}</p>
      <p style={{ color: 'var(--muted)' }}>This browser is {phoneDeviceId() ? `enrolled as device #${phoneDeviceId()}` : 'not enrolled'}.</p>
      <DeviceSetup onDone={reload} /></div>}
    {tab === 'backups' && <Backups />}{tab === 'tools' && <Terminal />}{tab === 'users' && <Users />}
  </>)
}
