import { get } from '../api/client.js'
import { useLive } from '../api/hooks.js'

const COLOR = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)' }

export default function Ticker() {
  const [alerts] = useLive(() => get('/api/alerts', { limit: 15 }), 8000)
  const items = alerts || []
  const loop = [...items, ...items]
  return (
    <div className="ticker">
      <div className="ticker-label">LIVE FEED</div>
      <div className="ticker-track">
        {loop.length === 0 ? <span className="ticker-item">No alerts yet — awaiting endpoint telemetry</span> : loop.map((a, i) => (
          <span className="ticker-item" key={`${a.id}-${i}`}>
            <span className="ticker-dot" style={{ background: COLOR[a.severity] }} />
            {a.hostname}: {a.title}{a.mitre_technique ? ` [${a.mitre_technique}]` : ''}
          </span>
        ))}
      </div>
    </div>
  )
}
