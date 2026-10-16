import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { errMsg, get, post } from '../api/client.js'

const Ctx = createContext(null)
export const useAuthGate = () => useContext(Ctx)

const LABELS = {
  response_action: 'execute a response action', rule_change: 'change detection rules', terminal: 'run a security tool',
  backup_create: 'create a backup', backup_restore: 'restore a backup', release_endpoint: 'release an isolated endpoint',
}

/** requireAuth(purpose) -> Promise<transactionId>. Opens the QR + biometric modal; rejects if cancelled/failed. */
export function AuthGateProvider({ children }) {
  const [req, setReq] = useState(null)
  const requireAuth = useCallback((purpose) => new Promise((resolve, reject) => setReq({ purpose, resolve, reject })), [])
  const done = (fn) => (v) => { setReq(null); fn(v) }
  return (
    <Ctx.Provider value={requireAuth}>
      {children}
      {req && <AuthModal purpose={req.purpose} onVerified={done(req.resolve)} onCancel={done(() => req.reject(new Error('cancelled')))} />}
    </Ctx.Provider>
  )
}

function AuthModal({ purpose, onVerified, onCancel }) {
  const [tx, setTx] = useState(null)
  const [status, setStatus] = useState('starting')
  const [error, setError] = useState('')
  const [cred, setCred] = useState('')
  const [left, setLeft] = useState(0)
  const started = useRef(false)

  useEffect(() => {
    if (started.current) return
    started.current = true
    post('/api/auth/transactions', { purpose }).then((t) => { setTx(t); setStatus('pending') }).catch((e) => { setError(errMsg(e)); setStatus('error') })
  }, [purpose])

  useEffect(() => {
    if (!tx || status !== 'pending') return
    const t = setInterval(async () => {
      setLeft(Math.max(0, Math.round((new Date(tx.expires_at + 'Z') - Date.now()) / 1000)))
      try {
        const s = await get(`/api/auth/transactions/${tx.id}`)
        if (s.status === 'verified') onVerified(tx.id)
        else if (s.status !== 'pending') setStatus(s.status)
      } catch { /* keep polling */ }
    }, 1200)
    return () => clearInterval(t)
  }, [tx, status])

  async function simulatePhone(e) {
    e.preventDefault()
    try {
      const r = await post(`/api/auth/transactions/${tx.id}/verify`, { credential: cred })
      if (r.status === 'verified') onVerified(tx.id)
      else if (r.status === 'failed') setStatus('failed')
      else setError(`Biometric did not match (attempt ${r.attempts} of 3)`)
    } catch (e2) { setError(errMsg(e2)) }
  }

  return (
    <div className="modal-back">
      <div className="modal">
        <h3 style={{ marginTop: 0 }}>Verify identity</h3>
        <p className="muted">To {LABELS[purpose] || purpose}, scan the QR code with your enrolled device and complete the biometric check.</p>
        {status === 'pending' && tx && (
          <>
            <img alt="QR" className="qr" src={`data:image/png;base64,${tx.qr_png_base64}`} />
            <div className="mono muted" style={{ fontSize: 11, wordBreak: 'break-all' }}>{tx.verify_url}</div>
            <div className="muted" style={{ margin: '8px 0' }}>Waiting for verification… expires in {left || '…'}s</div>
            <form onSubmit={simulatePhone} className="sim">
              <div className="muted" style={{ fontSize: 11, marginBottom: 6 }}>DEV SIMULATOR: stands in for the phone's fingerprint/face check</div>
              <div style={{ display: 'flex', gap: 8 }}>
                <input type="password" placeholder="biometric reference" value={cred} onChange={(e) => setCred(e.target.value)} />
                <button className="btn" type="submit">Verify</button>
              </div>
            </form>
          </>
        )}
        {status === 'starting' && <div className="muted">Creating transaction…</div>}
        {['failed', 'expired', 'error'].includes(status) && <div className="error-text">Verification {status}. {error}</div>}
        {error && status === 'pending' && <div className="error-text">{error}</div>}
        <div style={{ marginTop: 14, textAlign: 'right' }}><button className="btn ghost" onClick={onCancel}>Cancel</button></div>
      </div>
    </div>
  )
}
