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

function Users({ me }) {
  const [rows, err, reload] = useLoad('/users'); const [ask, modal] = useVerified()
  const [f, setF] = useState({ username: '', password: '', role: 'analyst', full_name: '', must_change_password: true })
  const [m, setM] = useState(''); const [ok, setOk] = useState(''); const [temp, setTemp] = useState(null); const [edit, setEdit] = useState(null)
  const act = async (fn, done) => { setM(''); setOk(''); try { const r = await fn(); if (done) setOk(done); reload(); return r } catch (e) { setM(e.message) } }
  const add = () => act(async () => { await api('/users', { method: 'POST', body: f }); setF({ ...f, username: '', password: '', full_name: '' }) }, 'User created')
  const patch = (u, body, done) => act(() => api(`/users/${u.id}`, { method: 'PATCH', body }), done)
  const save = async (u) => { const body = { full_name: edit.full_name }; if (edit.role !== u.role) body.role = edit.role; await patch(u, body, 'User updated'); setEdit(null) }
  const resetPw = (u) => window.confirm(`Reset the password for ${u.username}? They are signed out and must choose a new password at next sign-in.`) &&
    ask(`user:reset_password:${u.id}`, (vid) => act(async () => setTemp(await api(`/users/${u.id}/reset-password`, { method: 'POST', body: { verification_id: vid } })), 'Password reset'))
  const resetMfa = (u) => window.confirm(`Remove ${u.username}'s authenticator app? They link a new one from My account.`) &&
    ask(`user:reset_authenticator:${u.id}`, (vid) => act(() => api(`/users/${u.id}/reset-authenticator`, { method: 'POST', body: { verification_id: vid } }), 'Authenticator removed'))
  return (<div className="card"><h2>System users</h2><Err e={err || m} />{ok && <div className="okmsg">{ok}</div>}
    {temp && <div className="card" style={{ background: 'var(--surface2)', margin: '8px 0' }}><b>Temporary password for {temp.username}:</b> <span className="mono" style={{ userSelect: 'all', fontSize: 15 }}>{temp.temporary_password}</span>
      <div style={{ color: 'var(--muted)', margin: '6px 0' }}>Shown once. Give it to the user in person or over a trusted channel; they must change it at next sign-in.</div><button className="btn sm" onClick={() => setTemp(null)}>Done</button></div>}
    <div className="tablewrap"><table><thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Source</th><th>Status</th><th>Authenticator</th><th></th></tr></thead><tbody>{(rows || []).map((u) => {
      const ed = edit?.id === u.id; const self = u.id === me.id
      return (<tr key={u.id}><td>{u.username}{u.must_change_password && <span style={{ color: 'var(--muted)' }}> (must change password)</span>}</td>
        <td>{ed ? <input aria-label="Full name" value={edit.full_name} onChange={(e) => setEdit({ ...edit, full_name: e.target.value })} /> : u.full_name}</td>
        <td>{ed && !self ? <select aria-label="Role" value={edit.role} onChange={(e) => setEdit({ ...edit, role: e.target.value })}><option>analyst</option><option>admin</option></select> : u.role}</td>
        <td>{u.auth_source}</td><td>{u.status}</td><td>{u.totp_enrolled ? '✔ linked' : '—'}</td>
        <td><div className="row">{ed ? (<><button className="btn sm primary" onClick={() => save(u)}>Save</button><button className="btn sm" onClick={() => setEdit(null)}>Cancel</button></>) : (<>
          <button className="btn sm" onClick={() => setEdit({ id: u.id, full_name: u.full_name || '', role: u.role })}>Edit</button>
          {!self && <button className="btn sm" onClick={() => patch(u, { status: u.status === 'active' ? 'disabled' : 'active' }, u.status === 'active' ? 'User disabled' : 'User enabled')}>{u.status === 'active' ? 'Disable' : 'Enable'}</button>}
          {!self && u.auth_source === 'local' && <button className="btn sm" onClick={() => resetPw(u)}>Reset password…</button>}
          {!self && u.totp_enrolled && <button className="btn sm danger" onClick={() => resetMfa(u)}>Reset authenticator…</button>}</>)}</div></td></tr>)
    })}</tbody></table></div>
    <h3 style={{ marginTop: 14 }}>Add user</h3>
    <div className="row" style={{ marginTop: 6 }}><input placeholder="username" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /><input placeholder="full name" value={f.full_name} onChange={(e) => setF({ ...f, full_name: e.target.value })} />
      <input type="password" placeholder="first password (min 10)" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} />
      <select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}><option>analyst</option><option>admin</option></select>
      <label><input type="checkbox" checked={f.must_change_password} onChange={(e) => setF({ ...f, must_change_password: e.target.checked })} /> must change at first sign-in</label>
      <button className="btn primary" onClick={add}>Add user</button></div>{modal}</div>)
}

export default function Admin({ user }) {
  const [tab, setTab] = useState('device')
  const [devs, , reload] = useLoad('/devices')
  return (<>
    <div className="head"><div><h1>Administration</h1><div className="sub">Authenticator device, backups, tool terminal and accounts</div></div></div>
    <div className="tabs">{[['device', 'Authenticator device'], ['backups', 'Backup & restore'], ['tools', 'Tool terminal'], ['users', 'Users']].map(([k, l]) => <button key={k} className={tab === k ? 'on' : ''} onClick={() => setTab(k)}>{l}</button>)}</div>
    {tab === 'device' && <div className="card"><h2>Authenticator devices</h2>
      <p>Enrolled for your account: {(devs || []).map((d) => <Badge key={d.id} v={`#${d.id} ${d.name}`} kind="neutral" />)} {devs && !devs.length && 'none'}</p>
      <p style={{ color: 'var(--muted)' }}>This browser is {phoneDeviceId() ? `enrolled as device #${phoneDeviceId()}` : 'not enrolled'}. To use a real phone (Microsoft Authenticator, Google Authenticator…), link it under <b>My account</b>.</p>
      <DeviceSetup onDone={reload} /></div>}
    {tab === 'backups' && <Backups />}{tab === 'tools' && <Terminal />}{tab === 'users' && <Users me={user} />}
  </>)
}
