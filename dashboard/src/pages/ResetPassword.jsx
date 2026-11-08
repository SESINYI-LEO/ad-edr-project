import { useState } from 'react'
import { Link } from 'react-router-dom'
import { errMsg, post } from '../api/client.js'

/** Forgot-password without e-mail: proved with the code from the account's authenticator app. */
export default function ResetPassword() {
  const [f, setF] = useState({ username: '', code: '', pw: '', pw2: '' })
  const [msg, setMsg] = useState(null)
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  async function submit(e) {
    e.preventDefault()
    if (f.pw.length < 8) return setMsg({ text: 'New password must be at least 8 characters' })
    if (f.pw !== f.pw2) return setMsg({ text: 'The two passwords do not match' })
    try {
      await post('/api/auth/password/reset', { username: f.username, code: f.code, new_password: f.pw })
      setMsg({ ok: true, text: 'Password reset. You can sign in now.' })
      setF({ username: '', code: '', pw: '', pw2: '' })
    } catch (x) { setMsg({ text: errMsg(x) }) }
  }
  return (
    <div className="login-wrap">
      <form className="login-box" onSubmit={submit}>
        <div className="brand">SENTRY<span style={{ color: 'var(--accent)' }}>_</span>EDR</div>
        <p className="muted">Reset your password with the 6-digit code from your authenticator app. Lost your phone? Ask an administrator to reset your account.</p>
        <div className="field"><label>Username</label><input value={f.username} onChange={set('username')} autoFocus /></div>
        <div className="field"><label>Authenticator code</label><input inputMode="numeric" autoComplete="one-time-code" value={f.code} onChange={set('code')} /></div>
        <div className="field"><label>New password</label><input type="password" autoComplete="new-password" value={f.pw} onChange={set('pw')} /></div>
        <div className="field"><label>Repeat new password</label><input type="password" autoComplete="new-password" value={f.pw2} onChange={set('pw2')} /></div>
        <button className="btn-primary" type="submit">Reset password</button>
        {msg && <div className={msg.ok ? 'flash ok' : 'error-text'} style={{ marginTop: 10 }}>{msg.text}</div>}
        <div className="muted" style={{ marginTop: 12, fontSize: 12 }}><Link to="/login" style={{ color: 'var(--accent)' }}>Back to sign in</Link></div>
      </form>
    </div>
  )
}
