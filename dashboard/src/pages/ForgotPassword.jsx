import { useState } from 'react'
import { Link } from 'react-router-dom'
import { errMsg, post } from '../api/client.js'

/** Self-service reset for someone who cannot sign in: a current code from their enrolled authenticator proves who they are. */
export default function ForgotPassword() {
  const [f, setF] = useState({ username: '', code: '', next: '', again: '' })
  const [err, setErr] = useState('')
  const [done, setDone] = useState(false)
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  async function submit(e) {
    e.preventDefault()
    if (f.next !== f.again) return setErr('The new passwords do not match')
    try {
      await post('/api/auth/password/forgot', { username: f.username, code: f.code, new_password: f.next })
      setDone(true)
    } catch (x) { setErr(errMsg(x)) }
  }
  return (
    <div className="login-wrap">
      <form className="login-box" onSubmit={submit}>
        <div className="brand">SENTRY<span style={{ color: 'var(--accent)' }}>_</span>EDR</div>
        {done ? (
          <>
            <div className="flash ok">Password reset. You can sign in with your new password.</div>
            <Link to="/login" className="link">Back to sign in</Link>
          </>
        ) : (
          <>
            <p className="muted" style={{ marginTop: 0, fontSize: 12 }}>
              Enter the 6-digit code from your authenticator app to set a new password. No authenticator set up? Ask an administrator to reset it for you.
            </p>
            <div className="field"><label>Username</label><input value={f.username} onChange={set('username')} autoFocus required /></div>
            <div className="field"><label>Authenticator code</label><input value={f.code} onChange={set('code')} inputMode="numeric" autoComplete="one-time-code" maxLength={7} required /></div>
            <div className="field"><label>New password (8+ characters)</label><input type="password" value={f.next} onChange={set('next')} autoComplete="new-password" minLength={8} required /></div>
            <div className="field"><label>Repeat new password</label><input type="password" value={f.again} onChange={set('again')} autoComplete="new-password" minLength={8} required /></div>
            <button className="btn-primary" type="submit">Reset password</button>
            {err && <div className="error-text">{err}</div>}
            <div style={{ marginTop: 14, textAlign: 'center' }}><Link to="/login" className="link">Back to sign in</Link></div>
          </>
        )}
      </form>
    </div>
  )
}
