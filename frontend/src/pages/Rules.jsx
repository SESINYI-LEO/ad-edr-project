import React, { useState } from 'react'
import { api } from '../api.js'
import { useLoad, Badge, Err, useVerified } from '../ui.jsx'

export default function Rules({ user }) {
  const [rows, err, reload] = useLoad('/rules')
  const [msg, setMsg] = useState('')
  const [ask, modal] = useVerified()
  const toggle = (r) => ask(`rule:${r.rule_id}:${r.enabled ? 'disable' : 'enable'}`, async (vid) => {
    setMsg('')
    try { await api(`/rules/${r.rule_id}`, { method: 'PATCH', body: { enabled: !r.enabled, verification_id: vid } }); reload() } catch (e) { setMsg(e.message) }
  })
  return (<>
    <div className="head"><div><h1>Detection rules</h1><div className="sub">Behaviour rules mapped to MITRE ATT&amp;CK · enabling or disabling requires biometric verification</div></div></div>
    <Err e={err || msg} />
    <div className="card tablewrap"><table><thead><tr><th>ID</th><th>Name</th><th>Technique</th><th>Tactic</th><th>Severity</th><th>Conf.</th><th>Alerts</th><th>State</th>{user.role === 'admin' && <th></th>}</tr></thead><tbody>
      {(rows || []).map((r) => <tr key={r.rule_id}><td className="mono">{r.rule_id}</td><td><b>{r.name}</b><div style={{ color: 'var(--muted)', fontSize: 12.5 }}>{r.description}</div></td><td className="mono">{r.technique}</td><td>{r.tactic}</td><td><Badge v={r.severity} /></td><td>{Math.round(r.confidence)}%</td><td>{r.alerts}</td><td><Badge v={r.enabled ? 'enabled' : 'disabled'} kind={r.enabled ? 'ok' : 'neutral'} /></td>
        {user.role === 'admin' && <td><button className="btn sm" onClick={() => toggle(r)}>{r.enabled ? 'Disable' : 'Enable'}</button></td>}</tr>)}</tbody></table></div>
    {modal}
  </>)
}
