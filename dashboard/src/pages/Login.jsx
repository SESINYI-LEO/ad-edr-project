import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { errMsg, login } from '../api/client.js'

export default function Login() {
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [err, setErr] = useState('')
  const nav = useNavigate()
  async function submit(e) {
    e.preventDefault()
    try { await login(u, p); nav('/') } catch (x) { setErr(errMsg(x)) }
  }
  return (
    <div className="login-wrap">
      <form className="login-box" onSubmit={submit}>
        <div className="brand">SENTRY<span style={{ color: 'var(--accent)' }}>_</span>EDR</div>
        <div className="field"><label>Username</label><input value={u} onChange={(e) => setU(e.target.value)} autoFocus /></div>
        <div className="field"><label>Password</label><input type="password" value={p} onChange={(e) => setP(e.target.value)} /></div>
        <button className="btn-primary" type="submit">Sign in</button>
        {err && <div className="error-text">{err}</div>}
      </form>
    </div>
  )
}
