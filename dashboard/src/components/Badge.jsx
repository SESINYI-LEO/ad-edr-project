const MAP = {
  critical: 'critical', high: 'high', medium: 'medium', low: 'low',
  open: 'medium', investigating: 'high', contained: 'low', resolved: 'ok', closed: 'dim',
  new: 'dim', prioritised: 'medium', under_investigation: 'high', escalated: 'critical', false_positive: 'dim',
  online: 'ok', offline: 'dim', isolated: 'critical',
  verified: 'ok', corrupt: 'critical', unverified: 'medium', success: 'ok', denied: 'critical', failed: 'critical',
}
export default function Badge({ level, children }) {
  return <span className={`badge ${MAP[level] || 'dim'}`}>{(children ?? level ?? '').toString().replace('_', ' ')}</span>
}
