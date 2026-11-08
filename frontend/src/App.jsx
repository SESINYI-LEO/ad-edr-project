import React, { useState, useEffect } from 'react'
import { api, getToken, setToken, setUnauthorizedHandler } from './api.js'
import { Err } from './ui.jsx'
import Overview from './pages/Overview.jsx'
import Alerts from './pages/Alerts.jsx'
import Tickets from './pages/Tickets.jsx'
import Incidents from './pages/Incidents.jsx'
import Endpoints from './pages/Endpoints.jsx'
import Rules from './pages/Rules.jsx'
import Audit from './pages/Audit.jsx'
import Admin from './pages/Admin.jsx'

const PAGES = [
  ['overview', 'Overview', Overview], ['alerts', 'Alerts', Alerts], ['tickets', 'Tickets', Tickets],
  ['incidents', 'Incidents', Incidents], ['endpoints', 'Endpoints', Endpoints], ['rules', 'Detection rules', Rules],
  ['audit', 'Audit log', Audit], ['admin', 'Administration', Admin],
]

function Login({ onLogin }) {
  const [u, setU] = useState(''); const [p, setP] = useState(''); const [e, setE] = useState(''); const [busy, setBusy] = useState(false)
  const submit = async (ev) => {
    ev.preventDefault(); setBusy(true); setE('')
    try { const r = await api('/auth/login', { method: 'POST', body: { username: u, password: p } }); setToken(r.access_token); onLogin(r.user) }
    catch (x) { setE(x.message) } finally { setBusy(false) }
  }
  return (
    <form className="card login" onSubmit={submit}>
      <h1>AD-Integrated EDR</h1>
      <p style={{ color: 'var(--muted)', marginTop: 4 }}>Security operations console</p>
      <label className="f">Username<input autoFocus value={u} onChange={(x) => setU(x.target.value)} autoComplete="username" /></label>
      <label className="f">Password<input type="password" value={p} onChange={(x) => setP(x.target.value)} autoComplete="current-password" /></label>
      <Err e={e} />
      <button className="btn primary" disabled={busy || !u || !p} style={{ width: '100%' }}>{busy ? 'Signing in…' : 'Sign in'}</button>
    </form>
  )
}

export default function App() {
  const [user, setUser] = useState(null)
  const [ready, setReady] = useState(false)
  const [page, setPage] = useState(() => location.hash.slice(1) || 'overview')
  const [param, setParam] = useState(null)

  useEffect(() => {
    setUnauthorizedHandler(() => { setToken(null); setUser(null) })
    if (getToken()) api('/auth/me').then(setUser).catch(() => setToken(null)).finally(() => setReady(true))
    else setReady(true)
  }, [])
  useEffect(() => { location.hash = page }, [page])

  if (!ready) return null
  if (!user) return <Login onLogin={setUser} />
  const go = (p, prm = null) => { setParam(prm); setPage(p) }
  const allowed = PAGES.filter(([k]) => k !== 'admin' || user.role === 'admin')
  const Cur = (allowed.find((x) => x[0] === page) || PAGES[0])[2]
  return (
    <div className="app">
      <nav className="side" aria-label="Main">
        <div className="brand">◈ <div>EDR Console<small>domain: lab.local</small></div></div>
        {PAGES.filter(([k]) => k !== 'admin' || user.role === 'admin').map(([k, label]) => (
          <a key={k} className={page === k ? 'on' : ''} onClick={() => go(k)} href={`#${k}`}>{label}</a>
        ))}
        <div className="foot">
          {user.full_name || user.username}<br />{user.role}<br />
          <a style={{ cursor: 'pointer', color: 'var(--accent)' }} onClick={() => { setToken(null); setUser(null) }}>Sign out</a>
        </div>
      </nav>
      <main><Cur user={user} go={go} param={param} /></main>
    </div>
  )
}
