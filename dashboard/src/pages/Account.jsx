import { useEffect, useState } from 'react'
import { currentUser, errMsg, get, post, saveSession, saveUser } from '../api/client.js'

export default function Account() {
  const [me, setMe] = useState(currentUser())
  useEffect(() => { get('/api/auth/me').then((u) => { setMe(u); saveUser(u) }).catch(() => {}) }, [])
  const update = (u) => { setMe(u); saveUser(u) }
  return (
    <>
      <h1 className="page-title">My account</h1>
      <p className="page-subtitle">{me?.username} · {me?.role}</p>
      <div className="grid2">
        <ChangePassword forced={me?.must_change_password} />
        <Authenticator me={me} onChange={update} />
      </div>
    </>
  )
}

function ChangePassword({ forced }) {
  const [f, setF] = useState({ current: '', next: '', again: '' })
  const [msg, setMsg] = useState(null)
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  async function submit(e) {
    e.preventDefault()
    if (f.next !== f.again) return setMsg({ text: 'The new passwords do not match' })
    try {
      const r = await post('/api/auth/password/change', { current_password: f.current, new_password: f.next })
      saveSession(r) // fresh token: every other session for this account has just been signed out
      setF({ current: '', next: '', again: '' })
      if (forced) { window.location.href = '/'; return }
      setMsg({ ok: true, text: 'Password changed. Your other sessions were signed out.' })
    } catch (x) { setMsg({ text: errMsg(x) }) }
  }
  return (
    <form className="panel" onSubmit={submit}>
      <h3>Change password</h3>
      {forced && <div className="flash err">Your administrator set a temporary password. Choose your own to continue.</div>}
      {msg && <div className={`flash ${msg.ok ? 'ok' : 'err'}`}>{msg.text}</div>}
      <div className="field"><label>{forced ? 'Temporary password' : 'Current password'}</label><input type="password" value={f.current} onChange={set('current')} autoComplete="current-password" required /></div>
      <div className="field"><label>New password (8+ characters)</label><input type="password" value={f.next} onChange={set('next')} autoComplete="new-password" minLength={8} required /></div>
      <div className="field"><label>Repeat new password</label><input type="password" value={f.again} onChange={set('again')} autoComplete="new-password" minLength={8} required /></div>
      <button className="btn">Change password</button>
    </form>
  )
}

const groups = (s) => s.match(/.{1,4}/g)?.join(' ') || s

function Authenticator({ me, onChange }) {
  const enrolled = !!me?.authenticator_enrolled
  const [mode, setMode] = useState('idle') // idle | verify | scan | remove
  const [pw, setPw] = useState('')
  const [code, setCode] = useState('')
  const [setup, setSetup] = useState(null)
  const [msg, setMsg] = useState(null)
  const reset = () => { setMode('idle'); setPw(''); setCode(''); setSetup(null) }
  const fail = (x) => setMsg({ text: errMsg(x) })

  async function start(e) {
    e.preventDefault()
    try {
      setSetup(await post('/api/auth/totp/enroll/start', { current_password: pw, current_code: enrolled ? code : undefined }))
      setMode('scan'); setPw(''); setCode(''); setMsg(null)
    } catch (x) { fail(x) }
  }
  async function confirm(e) {
    e.preventDefault()
    try {
      onChange(await post('/api/auth/totp/enroll/confirm', { code }))
      reset(); setMsg({ ok: true, text: 'Authenticator enrolled. You will use it to approve sensitive actions.' })
    } catch (x) { fail(x) }
  }
  async function remove(e) {
    e.preventDefault()
    try {
      onChange(await post('/api/auth/totp/remove', { current_password: pw, code }))
      reset(); setMsg({ ok: true, text: 'Authenticator removed.' })
    } catch (x) { fail(x) }
  }

  return (
    <div className="panel">
      <h3>Authenticator app (biometric approval)</h3>
      {msg && <div className={`flash ${msg.ok ? 'ok' : 'err'}`}>{msg.text}</div>}
      <p className="muted" style={{ marginTop: 0 }}>
        Status: {enrolled ? <span className="badge ok">enrolled</span> : <span className="badge dim">not set up</span>}
      </p>
      <p className="muted" style={{ fontSize: 12 }}>
        Works with Microsoft Authenticator, Google Authenticator, Authy, 1Password and any other app that scans a standard QR code.
        Turn on the app&apos;s own lock so opening it needs your fingerprint or face.
      </p>

      {mode === 'idle' && (
        <div className="row-actions">
          <button className="btn" onClick={() => setMode('verify')}>{enrolled ? 'Replace authenticator' : 'Set up authenticator'}</button>
          {enrolled && <button className="btn ghost" onClick={() => setMode('remove')}>Remove</button>}
        </div>
      )}

      {mode === 'verify' && (
        <form onSubmit={start} className="form-narrow">
          <div className="field"><label>Your password</label><input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" required /></div>
          {enrolled && <div className="field"><label>Current code from your existing authenticator</label><input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required /></div>}
          <div className="row-actions"><button className="btn">Continue</button><button type="button" className="btn ghost" onClick={reset}>Cancel</button></div>
        </form>
      )}

      {mode === 'scan' && setup && (
        <form onSubmit={confirm}>
          <ol className="steps">
            <li>Open your authenticator app and add an account. In Microsoft Authenticator: <b>+</b> → <b>Other account (Google, Facebook, etc.)</b> → scan.</li>
            <li>Scan this QR code, or choose &quot;enter code manually&quot; and type the key below.</li>
            <li>Type the 6-digit code the app now shows, to finish.</li>
          </ol>
          <div className="setup-row">
            <img alt="Authenticator QR code" className="qr" src={`data:image/png;base64,${setup.qr_png_base64}`} />
            <div style={{ flex: 1, minWidth: 200 }}>
              <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}>Manual key ({setup.issuer} · {setup.account})</div>
              <div className="secret-key">{groups(setup.secret)}</div>
              <div className="field" style={{ marginTop: 16 }}><label>6-digit code</label><input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={7} autoFocus required /></div>
              <div className="row-actions"><button className="btn">Confirm</button><button type="button" className="btn ghost" onClick={reset}>Cancel</button></div>
            </div>
          </div>
        </form>
      )}

      {mode === 'remove' && (
        <form onSubmit={remove} className="form-narrow">
          <p className="muted" style={{ fontSize: 12 }}>Without an authenticator you cannot approve sensitive actions until you set one up again.</p>
          <div className="field"><label>Your password</label><input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" required /></div>
          <div className="field"><label>Current 6-digit code</label><input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required /></div>
          <div className="row-actions"><button className="btn danger">Remove authenticator</button><button type="button" className="btn ghost" onClick={reset}>Cancel</button></div>
        </form>
      )}
    </div>
  )
}
