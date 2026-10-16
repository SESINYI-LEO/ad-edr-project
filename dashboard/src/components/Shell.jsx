import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { currentUser } from '../api/client.js'
import Ticker from './Ticker.jsx'

const NAV = [
  ['/', 'Overview', true], ['/alerts', 'Alerts'], ['/tickets', 'Tickets'], ['/incidents', 'Incidents'], ['/endpoints', 'Endpoints'],
  ['/events', 'Event timeline'], ['/identity', 'AD identity'], ['/rules', 'Detection rules'], ['/audit', 'Audit trail'],
  ['/backups', 'Backup & restore'], ['/terminal', 'Security terminal'],
]

export default function Shell() {
  const nav = useNavigate()
  const u = currentUser()
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">SENTRY<span>_</span>EDR</div>
        <nav style={{ flex: 1 }}>
          {NAV.map(([to, label, end]) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}>{label}</NavLink>
          ))}
        </nav>
        <div style={{ padding: '0 20px' }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 8 }}>{u?.username} · {u?.role}</div>
          <button className="btn ghost" style={{ width: '100%' }} onClick={() => { localStorage.clear(); nav('/login') }}>Log out</button>
        </div>
      </aside>
      <main className="main"><Ticker /><Outlet /></main>
    </div>
  )
}
