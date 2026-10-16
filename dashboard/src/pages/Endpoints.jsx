import { useState } from 'react'
import { errMsg, get, isAdmin, post } from '../api/client.js'
import { fmt, useLive } from '../api/hooks.js'
import Badge from '../components/Badge.jsx'
import { useAuthGate } from '../components/AuthGate.jsx'

export default function Endpoints() {
  const [eps, reload] = useLive(() => get('/api/endpoints'), 5000)
  const gate = useAuthGate()
  const [msg, setMsg] = useState(null)
  async function release(e) {
    try { const tx = await gate('release_endpoint'); await post(`/api/endpoints/${e.id}/release`, {}, tx); setMsg(null); reload() }
    catch (x) { if (x.message !== 'cancelled') setMsg(errMsg(x)) }
  }
  return (
    <>
      <h1 className="page-title">Endpoints</h1>
      <p className="page-subtitle">Windows hosts reporting telemetry through the endpoint agent</p>
      {msg && <div className="flash err">{msg}</div>}
      <div className="data-panel"><table>
        <thead><tr><th>Host</th><th>IP</th><th>OS</th><th>Criticality</th><th>Status</th><th>Last seen</th><th /></tr></thead>
        <tbody>{(eps || []).map((e) => (<tr key={e.id}><td className="mono">{e.hostname}</td><td className="mono">{e.ip_address || '—'}</td><td>{e.os_version || '—'}</td>
          <td style={{ textTransform: 'capitalize' }}>{e.criticality}</td><td><Badge level={e.status} /></td><td className="mono">{fmt(e.last_seen)}</td>
          <td>{e.status === 'isolated' && isAdmin() && <button className="btn sm" onClick={() => release(e)}>Release…</button>}</td></tr>))}
          {!eps?.length && <tr><td colSpan={7} className="empty-state">No endpoints have reported yet</td></tr>}</tbody></table></div>
    </>
  )
}
