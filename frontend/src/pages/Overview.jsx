import React from 'react'
import { useLoad, Badge, Bars, Stack, fmt } from '../ui.jsx'

export default function Overview({ go }) {
  const [d, err] = useLoad('/dashboard/summary', [], 5000)
  if (err) return <div className="err">{err}</div>
  if (!d) return <div className="empty">Loading…</div>
  const a = d.alerts_24h, t = d.open_tickets, e = d.endpoints
  const attributed = d.events_total ? Math.round((d.events_attributed / d.events_total) * 100) : 0
  return (<>
    <div className="head"><div><h1>Overview</h1><div className="sub">Live state of the monitored estate · refreshes every 5 s</div></div></div>
    <div className="grid kpis">
      <div className="card kpi"><h3>Endpoints</h3><div className="v">{e.total}</div><div className="s">{e.online} online · {e.isolated} isolated · {e.offline} offline</div></div>
      <div className="card kpi"><h3>Alerts (24 h)</h3><div className="v">{a.critical + a.high + a.medium + a.low}</div><div className="s">{a.critical} critical · {a.high} high</div></div>
      <div className="card kpi"><h3>Open tickets</h3><div className="v">{t.Critical + t.High + t.Medium + t.Low}</div><div className="s">{t.Critical} critical · {t.High} high</div></div>
      <div className="card kpi"><h3>Open incidents</h3><div className="v">{d.open_incidents}</div><div className="s">under response</div></div>
      <div className="card kpi"><h3>Events ingested</h3><div className="v">{d.events_total}</div><div className="s">{attributed}% attributed to an AD identity</div></div>
    </div>
    <div className="grid cols2" style={{ marginBottom: 14 }}>
      <div className="card"><h2>Alerts by severity (24 h)</h2>
        <Stack parts={[{ name: 'Critical', icon: '⬣', n: a.critical, color: 'var(--crit)' }, { name: 'High', icon: '▲', n: a.high, color: 'var(--high)' }, { name: 'Medium', icon: '◆', n: a.medium, color: 'var(--med)' }, { name: 'Low', icon: '●', n: a.low, color: 'var(--low)' }]} /></div>
      <div className="card"><h2>Open tickets by priority</h2>
        <Stack parts={[{ name: 'Critical', icon: '⬣', n: t.Critical, color: 'var(--crit)' }, { name: 'High', icon: '▲', n: t.High, color: 'var(--high)' }, { name: 'Medium', icon: '◆', n: t.Medium, color: 'var(--med)' }, { name: 'Low', icon: '●', n: t.Low, color: 'var(--low)' }]} /></div>
    </div>
    <div className="grid cols2" style={{ marginBottom: 14 }}>
      <div className="card"><h2>Alerts by ATT&amp;CK tactic</h2><Bars rows={d.tactics} label="tactic" value="alerts" /></div>
      <div className="card"><h2>Alerts by user (AD identity)</h2><Bars rows={d.top_users.map((u) => ({ ...u, user: `${u.user} · ${u.department || '—'}` }))} label="user" value="alerts" /></div>
      <div className="card"><h2>Alerts by host</h2><Bars rows={d.top_hosts} label="hostname" value="alerts" /></div>
    </div>
    <div className="card"><h2>Most recent alerts</h2>
      <div className="tablewrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Host</th><th>User</th><th>Priority</th></tr></thead><tbody>
        {d.recent_alerts.map((r) => (<tr key={r.id} className="click" onClick={() => go('alerts', r.id)}><td>{fmt(r.created_at)}</td><td><Badge v={r.severity} /></td><td>{r.rule_name}</td><td>{r.hostname}</td><td>{r.user || '—'}</td><td>{r.priority ? <Badge v={r.priority} /> : '—'}</td></tr>))}
        {!d.recent_alerts.length && <tr><td colSpan="6" className="empty">No alerts yet</td></tr>}
      </tbody></table></div></div>
  </>)
}
