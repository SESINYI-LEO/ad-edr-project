import React, { useState } from 'react'
import { api } from '../api.js'
import { useLoad, fmt, Err, Badge } from '../ui.jsx'

export default function Audit() {
  const [rows, err] = useLoad('/audit?limit=200', [], 5000)
  const [v, setV] = useState(null); const [e2, setE2] = useState('')
  const verify = async () => { setE2(''); try { setV(await api('/audit/verify')) } catch (e) { setE2(e.message) } }
  return (<>
    <div className="head"><div><h1>Audit log</h1><div className="sub">Append-only, hash-chained record of every security-relevant action</div></div>
      <div className="row">{v && <Badge v={v.ok ? `Chain intact · ${v.checked} entries` : `TAMPERING at entry ${v.broken_at}`} kind={v.ok ? 'ok' : 'Critical'} />}<button className="btn primary" onClick={verify}>Verify integrity</button></div></div>
    <Err e={err || e2} />
    <div className="card tablewrap"><table><thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Outcome</th><th>Details</th><th>Hash</th></tr></thead><tbody>
      {(rows || []).map((a) => <tr key={a.id}><td>{a.id}</td><td>{fmt(a.timestamp)}</td><td>{a.actor}</td><td className="mono">{a.action}</td><td>{a.outcome}</td><td className="mono" style={{ wordBreak: 'break-all' }}>{JSON.stringify(a.details)}</td><td className="mono">{a.hash}</td></tr>)}</tbody></table></div>
  </>)
}
