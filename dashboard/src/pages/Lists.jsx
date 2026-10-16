import { useState } from 'react'
import { get } from '../api/client.js'
import { fmt, useLive } from '../api/hooks.js'
import Badge from '../components/Badge.jsx'

export function Events() {
  const [host, setHost] = useState('')
  const [rows] = useLive(() => get('/api/events', { limit: 200, hostname: host || undefined }), 5000, [host])
  return (
    <>
      <h1 className="page-title">Event timeline</h1>
      <p className="page-subtitle">Identity-correlated forensic record: who, what, where, when</p>
      <input className="inline-input" placeholder="Filter by hostname" value={host} onChange={(e) => setHost(e.target.value)} style={{ marginBottom: 12 }} />
      <div className="data-panel"><table>
        <thead><tr><th>When</th><th>Host</th><th>Type</th><th>User (AD)</th><th>Activity</th></tr></thead>
        <tbody>{(rows || []).map((e) => (<tr key={e.id}><td className="mono">{fmt(e.timestamp)}</td><td className="mono">{e.hostname}</td><td>{e.event_type}</td>
          <td>{e.user ? <>{e.user.username} <Badge level={e.user.privilege === 'domain_admin' ? 'critical' : e.user.privilege === 'admin' ? 'high' : 'dim'}>{e.user.privilege}</Badge></> : <span className="muted">{e.raw_username || '—'}</span>}</td>
          <td className="mono" style={{ fontSize: 12 }}>{e.command_line || e.registry_key || e.file_path || (e.remote_address && `${e.remote_address}:${e.remote_port}`) || e.process_name}</td></tr>))}
          {!rows?.length && <tr><td colSpan={5} className="empty-state">No events</td></tr>}</tbody></table></div>
    </>
  )
}

export function Identity() {
  const [rows] = useLive(() => get('/api/ad/users'), 10000)
  return (
    <>
      <h1 className="page-title">AD identity</h1>
      <p className="page-subtitle">Directory identities seen in telemetry (SID → user → groups → privilege tier). Read-only; the EDR never writes to AD.</p>
      <div className="data-panel"><table>
        <thead><tr><th>User</th><th>SID</th><th>Department</th><th>Groups</th><th>Privilege</th></tr></thead>
        <tbody>{(rows || []).map((u) => (<tr key={u.id}><td>{u.username}</td><td className="mono" style={{ fontSize: 11 }}>{u.sid}</td><td>{u.department || '—'}</td>
          <td>{u.groups.join(', ')}</td><td><Badge level={u.privilege === 'domain_admin' ? 'critical' : u.privilege === 'admin' ? 'high' : u.privilege === 'elevated' ? 'medium' : 'dim'}>{u.privilege}</Badge></td></tr>))}
          {!rows?.length && <tr><td colSpan={5} className="empty-state">No identities resolved yet</td></tr>}</tbody></table></div>
    </>
  )
}

export function Audit() {
  const [rows] = useLive(() => get('/api/audit', { limit: 300 }), 6000)
  return (
    <>
      <h1 className="page-title">Audit trail</h1>
      <p className="page-subtitle">Every authentication, response, rule, backup and terminal action, attributed and timestamped</p>
      <div className="data-panel"><table>
        <thead><tr><th>When</th><th>User</th><th>Action</th><th>Outcome</th><th>Details</th></tr></thead>
        <tbody>{(rows || []).map((a) => (<tr key={a.id}><td className="mono">{fmt(a.timestamp)}</td><td>{a.username || '—'}</td><td className="mono">{a.action}</td>
          <td><Badge level={a.outcome} /></td><td className="mono" style={{ fontSize: 11 }}>{a.details}</td></tr>))}</tbody></table></div>
    </>
  )
}
