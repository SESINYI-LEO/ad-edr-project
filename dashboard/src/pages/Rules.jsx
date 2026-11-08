import { useState } from 'react'
import { errMsg, get, isAdmin, patch, post } from '../api/client.js'
import { useLive } from '../api/hooks.js'
import Badge from '../components/Badge.jsx'
import { useAuthGate } from '../components/AuthGate.jsx'

const SAMPLE = JSON.stringify({ all: [{ field: 'event_type', op: 'eq', value: 'file' }, { field: 'file_path', op: 'contains', value: '.locked' }] }, null, 2)

export default function Rules() {
  const [rules, reload] = useLive(() => get('/api/rules'), 0)
  const gate = useAuthGate()
  const [msg, setMsg] = useState(null)
  const [f, setF] = useState({ name: '', event_type: 'file', severity: 'medium', mitre_technique: '', logic: SAMPLE, threshold_count: 1, window_seconds: 0 })
  const run = async (fn, ok) => { try { await fn(); setMsg({ ok: true, text: ok }); reload() } catch (e) { if (e.message !== 'cancelled') setMsg({ text: errMsg(e) }) } }
  const toggle = (r) => run(async () => patch(`/api/rules/${r.id}`, { enabled: !r.enabled }, await gate('rule_change')), 'Rule updated')
  const create = (e) => { e.preventDefault(); run(async () => {
    const logic = JSON.parse(f.logic)
    await post('/api/rules', { ...f, logic, threshold_count: +f.threshold_count, window_seconds: +f.window_seconds, mitre_technique: f.mitre_technique || null }, await gate('rule_change'))
  }, 'Rule created and live') }
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  return (
    <>
      <h1 className="page-title">Detection rules</h1>
      <p className="page-subtitle">Transparent rule-based detection mapped to MITRE ATT&CK. Changes need Administrator + QR/biometric verification.</p>
      {msg && <div className={`flash ${msg.ok ? 'ok' : 'err'}`}>{msg.text}</div>}
      <div className="data-panel" style={{ marginBottom: 16 }}><table>
        <thead><tr><th>Rule</th><th>Event</th><th>ATT&CK</th><th>Severity</th><th>Correlation</th><th>Enabled</th></tr></thead>
        <tbody>{(rules || []).map((r) => (<tr key={r.id}><td>{r.name}<div className="muted" style={{ fontSize: 11 }}>{r.description}</div></td><td>{r.event_type}</td>
          <td className="mono">{r.mitre_technique || '—'}</td><td><Badge level={r.severity} /></td>
          <td className="mono" style={{ fontSize: 11 }}>{r.threshold_count > 1 ? `≥${r.threshold_count} in ${r.window_seconds}s` : '—'}</td>
          <td><button className={`btn sm ${r.enabled ? '' : 'ghost'}`} disabled={!isAdmin()} onClick={() => toggle(r)}>{r.enabled ? 'On' : 'Off'}</button></td></tr>))}</tbody></table></div>
      {isAdmin() && <form className="panel" onSubmit={create}><h3>New rule</h3>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
          <input className="inline-input" placeholder="Name" value={f.name} onChange={set('name')} required />
          <select value={f.event_type} onChange={set('event_type')}>{['process', 'file', 'registry', 'network', 'powershell', 'auth', 'sysmon'].map((x) => <option key={x}>{x}</option>)}</select>
          <select value={f.severity} onChange={set('severity')}>{['low', 'medium', 'high', 'critical'].map((x) => <option key={x}>{x}</option>)}</select>
          <input className="inline-input" placeholder="ATT&CK e.g. T1486" value={f.mitre_technique} onChange={set('mitre_technique')} style={{ width: 140 }} />
          <input className="inline-input" type="number" min="1" title="threshold count" value={f.threshold_count} onChange={set('threshold_count')} style={{ width: 70 }} />
          <input className="inline-input" type="number" min="0" title="window seconds" value={f.window_seconds} onChange={set('window_seconds')} style={{ width: 80 }} />
        </div>
        <textarea value={f.logic} onChange={set('logic')} spellCheck={false} />
        <button className="btn" style={{ marginTop: 8 }}>Create rule…</button></form>}
    </>
  )
}
