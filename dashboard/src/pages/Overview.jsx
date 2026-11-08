import { Link } from 'react-router-dom'
import { get } from '../api/client.js'
import { dur, fmt, useLive } from '../api/hooks.js'
import Badge from '../components/Badge.jsx'

const COLORS = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)' }

export default function Overview() {
  const [m] = useLive(() => get('/api/metrics'), 5000)
  const [alerts] = useLive(() => get('/api/alerts', { limit: 6 }), 5000)
  const [tickets] = useLive(() => get('/api/tickets'), 5000)
  const sev = m?.alerts_by_severity || {}
  const total = Math.max(1, m?.alerts_total || 0)
  const cards = m ? [
    ['Endpoints online', `${m.endpoints_online} / ${m.endpoints_total}`], ['Isolated', m.endpoints_isolated],
    ['Events stored', m.events_total], ['Alerts', m.alerts_total], ['Open tickets', m.tickets_open],
    ['Active incidents', m.incidents_active], ['MTTD', dur(m.mttd_seconds)], ['MTTR', dur(m.mttr_seconds)],
  ] : []
  return (
    <>
      <h1 className="page-title">Overview</h1>
      <p className="page-subtitle">Live view of endpoints, detections and response performance</p>
      <div className="stat-grid">{cards.map(([l, v]) => <div className="stat-card" key={l}><div className="stat-value">{v}</div><div className="stat-label">{l}</div></div>)}</div>
      <div className="grid2">
        <div className="panel"><h3>Alerts by severity</h3>
          {['critical', 'high', 'medium', 'low'].map((s) => (
            <div key={s}><div style={{ display: 'flex', justifyContent: 'space-between' }}><Badge level={s} /><span className="mono">{sev[s] || 0}</span></div>
              <div className="bar"><div style={{ width: `${((sev[s] || 0) / total) * 100}%`, background: COLORS[s] }} /></div></div>
          ))}
        </div>
        <div className="panel"><h3>Priority queue (top 6)</h3>
          <table><tbody>{(tickets || []).slice(0, 6).map((t) => (
            <tr key={t.id}><td>{t.title}<div className="muted mono" style={{ fontSize: 11 }}>{t.hostname}</div></td>
              <td className="mono">{t.priority_score}</td><td><Badge level={t.priority} /></td></tr>))}
            {!tickets?.length && <tr><td className="empty-state">No tickets yet</td></tr>}</tbody></table>
          <Link to="/tickets" className="muted" style={{ fontSize: 12 }}>Open ticket queue →</Link>
        </div>
      </div>
      <div className="panel"><h3>Recent alerts</h3>
        <table><tbody>{(alerts || []).map((a) => (
          <tr key={a.id}><td>{a.title}</td><td className="mono">{a.hostname}</td><td className="mono">{a.mitre_technique || '—'}</td>
            <td><Badge level={a.severity} /></td><td className="mono">{fmt(a.created_at)}</td></tr>))}
          {!alerts?.length && <tr><td className="empty-state">No alerts yet — start an agent (see README)</td></tr>}</tbody></table>
      </div>
    </>
  )
}
