import { useState } from 'react'
import { errMsg, isAdmin, post } from '../api/client.js'
import { useAuthGate } from '../components/AuthGate.jsx'

export default function Terminal() {
  const gate = useAuthGate()
  const [tool, setTool] = useState('ping')
  const [target, setTarget] = useState('')
  const [out, setOut] = useState(null)
  const [msg, setMsg] = useState(null)
  async function run(e) {
    e.preventDefault()
    try { const tx = await gate('terminal'); setOut(await post('/api/terminal/run', { tool, target }, tx)); setMsg(null) }
    catch (x) { if (x.message !== 'cancelled') setMsg(errMsg(x)) }
  }
  if (!isAdmin()) return <><h1 className="page-title">Security terminal</h1><p className="muted">Administrator access required.</p></>
  return (
    <>
      <h1 className="page-title">Security terminal</h1>
      <p className="page-subtitle">Allow-listed diagnostics only (no shell). Every run needs QR/biometric verification and is audited.</p>
      {msg && <div className="flash err">{msg}</div>}
      <form className="panel" onSubmit={run} style={{ display: 'flex', gap: 10 }}>
        <select value={tool} onChange={(e) => setTool(e.target.value)}><option>ping</option><option>dns_lookup</option><option>traceroute</option></select>
        <input className="inline-input" style={{ flex: 1 }} placeholder="Host or IP, e.g. 10.0.0.5" value={target} onChange={(e) => setTarget(e.target.value)} />
        <button className="btn" disabled={!target}>Run…</button>
      </form>
      {out && <div className="panel"><div className="muted mono" style={{ marginBottom: 6 }}>exit code {out.returncode}</div>
        <pre className="report">{out.stdout}{out.stderr && `\n${out.stderr}`}</pre></div>}
    </>
  )
}
