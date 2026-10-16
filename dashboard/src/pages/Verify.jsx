import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { errMsg, get, post } from '../api/client.js'

/** Opened on the second device after scanning the QR code. */
export default function Verify() {
  const { id } = useParams()
  const [tx, setTx] = useState(null)
  const [cred, setCred] = useState('')
  const [msg, setMsg] = useState('')
  useEffect(() => { get(`/api/auth/transactions/${id}`).then(setTx).catch((e) => setMsg(errMsg(e))) }, [id])
  async function go(e) {
    e.preventDefault()
    try {
      const r = await post(`/api/auth/transactions/${id}/verify`, { credential: cred })
      setTx({ ...tx, status: r.status })
      setMsg(r.status === 'verified' ? 'Verified. Return to your computer.' : `Not recognised (attempt ${r.attempts}/3)`)
    } catch (x) { setMsg(errMsg(x)) }
  }
  return (
    <div className="login-wrap">
      <form className="login-box" onSubmit={go}>
        <div className="brand">SENTRY<span style={{ color: 'var(--accent)' }}>_</span>EDR</div>
        <p className="muted">Approve: <b>{tx?.purpose?.replace('_', ' ') || '…'}</b> ({tx?.status || '…'})</p>
        {tx?.status === 'pending' && (<>
          <div className="field"><label>Biometric check (dev simulator)</label><input type="password" value={cred} onChange={(e) => setCred(e.target.value)} /></div>
          <button className="btn-primary" type="submit">Verify</button>
        </>)}
        {msg && <div className={tx?.status === 'verified' ? 'flash ok' : 'error-text'} style={{ marginTop: 10 }}>{msg}</div>}
      </form>
    </div>
  )
}
