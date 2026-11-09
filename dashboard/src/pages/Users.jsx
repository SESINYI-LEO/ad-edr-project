import { useState } from 'react'
import { currentUser, errMsg, get, isAdmin, patch, post } from '../api/client.js'
import { useLive } from '../api/hooks.js'
import Badge from '../components/Badge.jsx'
import { useAuthGate } from '../components/AuthGate.jsx'

export default function Users() {
  const gate = useAuthGate()
  const me = currentUser()
  const [rows, reload] = useLive(() => (isAdmin() ? get('/api/users') : Promise.resolve([])), 0)
  const [msg, setMsg] = useState(null)
  const [temp, setTemp] = useState(null)   // { username, password } shown once after an admin reset
  const [edit, setEdit] = useState(null)   // { id, email, role }
  const [f, setF] = useState({ username: '', email: '', role: 'analyst', password: '', must_change_password: true })
  const set = (k) => (e) => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })

  const run = async (fn, ok) => {
    try { const r = await fn(); setMsg({ ok: true, text: typeof ok === 'function' ? ok(r) : ok }); reload() }
    catch (e) { if (e.message !== 'cancelled') setMsg({ text: errMsg(e) }) }
  }

  if (!isAdmin()) return <><h1 className="page-title">Users</h1><p className="muted">Administrator access required.</p></>

  const create = (e) => { e.preventDefault(); run(async () => { await post('/api/users', f); setF({ ...f, username: '', email: '', password: '' }) }, 'User created') }
  const save = (u) => run(async () => {
    const body = { email: edit.email }
    if (edit.role !== u.role) body.role = edit.role
    await patch(`/api/users/${u.id}`, body, body.role ? await gate('user_admin') : undefined)
    setEdit(null)
  }, 'User updated')
  const toggle = (u) => run(async () => patch(`/api/users/${u.id}`, { is_active: !u.is_active }, await gate('user_admin')), u.is_active ? 'User deactivated' : 'User activated')
  const resetPw = (u) => window.confirm(`Reset the password for ${u.username}? Their current sessions will be signed out.`) &&
    run(async () => { const r = await post(`/api/users/${u.id}/reset-password`, {}, await gate('user_admin')); setTemp({ username: r.username, password: r.temporary_password }) }, 'Password reset')
  const resetAuth = (u) => window.confirm(`Remove the authenticator for ${u.username}? They will need to set up a new one.`) &&
    run(async () => post(`/api/users/${u.id}/reset-authenticator`, {}, await gate('user_admin')), 'Authenticator removed')

  return (
    <>
      <h1 className="page-title">Users</h1>
      <p className="page-subtitle">Manage accounts. Changing a role, deactivating an account, or resetting a password or authenticator needs QR + biometric verification.</p>
      {msg && <div className={`flash ${msg.ok ? 'ok' : 'err'}`}>{msg.text}</div>}
      {temp && (
        <div className="panel">
          <h3>Temporary password for {temp.username}</h3>
          <div className="temp-pass">{temp.password}</div>
          <p className="muted" style={{ fontSize: 12 }}>Shown once. Give it to the user privately; they must choose their own password at next sign-in.</p>
          <button className="btn ghost sm" onClick={() => setTemp(null)}>Done</button>
        </div>
      )}
      <div className="data-panel" style={{ marginBottom: 16 }}><table>
        <thead><tr><th>User</th><th>Email</th><th>Role</th><th>Status</th><th>Authenticator</th><th /></tr></thead>
        <tbody>{(rows || []).map((u) => {
          const self = u.id === me?.id
          const editing = edit?.id === u.id
          return (
            <tr key={u.id}>
              <td>{u.username}{self && <span className="muted"> (you)</span>}{u.must_change_password && <div className="muted" style={{ fontSize: 11 }}>must change password</div>}</td>
              <td>{editing ? <input className="inline-input" value={edit.email} onChange={(e) => setEdit({ ...edit, email: e.target.value })} /> : (u.email || '—')}</td>
              <td>{editing && !self
                ? <select value={edit.role} onChange={(e) => setEdit({ ...edit, role: e.target.value })}><option>analyst</option><option>administrator</option></select>
                : <Badge level={u.role === 'administrator' ? 'high' : 'medium'}>{u.role}</Badge>}</td>
              <td><Badge level={u.is_active ? 'ok' : 'dim'}>{u.is_active ? 'active' : 'disabled'}</Badge></td>
              <td><Badge level={u.authenticator_enrolled ? 'ok' : 'dim'}>{u.authenticator_enrolled ? 'enrolled' : u.biometric_enrolled ? 'dev reference' : 'none'}</Badge></td>
              <td><div className="row-actions">
                {editing ? (<><button className="btn sm" onClick={() => save(u)}>Save</button><button className="btn sm ghost" onClick={() => setEdit(null)}>Cancel</button></>) : (
                  <>
                    <button className="btn sm ghost" onClick={() => setEdit({ id: u.id, email: u.email || '', role: u.role })}>Edit</button>
                    {!self && <button className="btn sm ghost" onClick={() => resetPw(u)}>Reset password…</button>}
                    {u.authenticator_enrolled && <button className="btn sm ghost" onClick={() => resetAuth(u)}>Reset authenticator…</button>}
                    {!self && <button className={`btn sm ${u.is_active ? 'danger' : ''}`} onClick={() => toggle(u)}>{u.is_active ? 'Deactivate…' : 'Activate…'}</button>}
                  </>
                )}
              </div></td>
            </tr>
          )
        })}
        {!rows?.length && <tr><td colSpan={6} className="empty-state">No users</td></tr>}</tbody></table></div>

      <form className="panel" onSubmit={create}><h3>New user</h3>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
          <input className="inline-input" placeholder="Username" value={f.username} onChange={set('username')} minLength={3} required />
          <input className="inline-input" placeholder="Email" value={f.email} onChange={set('email')} />
          <select value={f.role} onChange={set('role')}><option>analyst</option><option>administrator</option></select>
          <input className="inline-input" type="password" placeholder="Initial password (8+)" value={f.password} onChange={set('password')} minLength={8} autoComplete="new-password" required />
        </div>
        <label className="muted" style={{ fontSize: 12, display: 'block', marginBottom: 8 }}>
          <input type="checkbox" checked={f.must_change_password} onChange={set('must_change_password')} /> They must choose their own password at first sign-in
        </label>
        <button className="btn">Create user</button>
      </form>
    </>
  )
}
