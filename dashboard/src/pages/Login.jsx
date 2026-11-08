import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { errMsg, login } from '../api/client.js'

export default function Login() {
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [err, setErr] = useState('')
  const nav = useNavigate()
  async function submit(e) {
    e.preventDefault()
    try { const user = await login(u, p); nav(user.must_change_password ? '/account' : '/') } catch (x) { setErr(errMsg(x)) }
  }
  return (
    <div className="login-wrap">
      <form className="login-box" onSubmit={submit}>
        <div className="brand">SENTRY<span style={{ color: 'var(--accent)' }}>_</span>EDR</div>
        <div className="field"><label>Username</label><input value={u} onChange={(e) => setU(e.target.value)} autoFocus /></div>
        <div className="field"><label>Password</label><input type="password" value={p} onChange={(e) => setP(e.target.value)} /></div>
        <button className="btn-primary" type="submit">Sign in</button>
        {err && <div className="error-text">{err}</div>}
        <div style={{ marginTop: 14, textAlign: 'center' }}><Link to="/forgot" className="link">Forgot password?</Link></div>
      </form>
    </div>
  )
}
