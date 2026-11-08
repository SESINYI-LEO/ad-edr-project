import React, { useState } from 'react'
import { useLoad, Badge, fmt, Err } from '../ui.jsx'

export default function Endpoints() {
  const [rows, err] = useLoad('/endpoints', [], 5000)
  const [sel, setSel] = useState(null)
  const [ev] = useLoad(sel ? `/endpoints/${sel.id}/events?limit=50` : '/health', [sel])
  const kind = { online: 'ok', isolated: 'Critical', offline: 'neutral' }
  return (<>
    <div className="head"><div><h1>Endpoints</h1><div className="sub">Enrolled agents and recent telemetry</div></div></div>
    <Err e={err} />
    <div className="card tablewrap" style={{ marginBottom: 14 }}><table><thead><tr><th>Host</th><th>IP</th><th>OS</th><th>Agent</th><th>Criticality</th><th>State</th><th>Last seen</th></tr></thead><tbody>
      {(rows || []).map((e) => <tr key={e.id} className="click" onClick={() => setSel(e)}><td>{e.hostname}</td><td className="mono">{e.ip_address}</td><td>{e.os_version}</td><td>{e.agent_version}</td><td>{e.criticality}/5</td><td><Badge v={e.state} kind={kind[e.state]} /></td><td>{fmt(e.last_seen)}</td></tr>)}
      {rows && !rows.length && <tr><td colSpan="7" className="empty">No endpoints enrolled yet. Run the agent (see README).</td></tr>}</tbody></table></div>
    {sel && Array.isArray(ev) && <div className="card tablewrap"><h2>Recent events on {sel.hostname}</h2><table><thead><tr><th>Time</th><th>Type</th><th>Process</th><th>User → AD identity</th><th>Command / detail</th></tr></thead><tbody>
      {ev.map((e) => <tr key={e.id}><td>{fmt(e.timestamp)}</td><td>{e.event_type}</td><td>{e.process_name}</td><td>{e.user_name}{e.identity ? ` → ${e.identity.sam_account_name} (${e.identity.department})` : ''}</td><td className="mono" style={{ wordBreak: 'break-all' }}>{e.command_line || JSON.stringify(e.details)}</td></tr>)}
      {!ev.length && <tr><td colSpan="5" className="empty">No events</td></tr>}</tbody></table></div>}
  </>)
}
