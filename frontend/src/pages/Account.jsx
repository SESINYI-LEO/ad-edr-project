import React, { useState } from 'react'
import { api, setToken } from '../api.js'
import { Err } from '../ui.jsx'

export function PasswordForm({ forced, user, onChanged }) {
  const [cur, setCur] = useState(''); const [pw, setPw] = useState(''); const [pw2, setPw2] = useState('')
  const [err, setErr] = useState(''); const [ok, setOk] = useState('')
  const submit = async (e) => {
    e.preventDefault(); setErr(''); setOk('')
    if (pw !== pw2) return setErr('The two new passwords do not match')
    try {
      const r = await api('/auth/password/change', { method: 'POST', body: { current_password: cur, new_password: pw } })
      setToken(r.access_token)            // this browser stays signed in; every other session is signed out
      setCur(''); setPw(''); setPw2(''); setOk('Password changed. Your other sessions were signed out.')
      onChanged && onChanged(r.user)
    } catch (x) { setErr(x.message) }
  }
  if (user.auth_source !== 'local') return <div className="card"><h2>Password</h2><p>This account signs in with Active Directory. Change the password in Windows / AD.</p></div>
  return (
    <form className="card" onSubmit={submit}>
      <h2>{forced ? 'Choose a new password' : 'Change password'}</h2>
      {forced && <p style={{ color: 'var(--muted)' }}>An administrator set or reset your password. Choose your own before continuing.</p>}
      <label className="f">Current password<input type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} /></label>
      <label className="f">New password (10+ characters, upper-case, lower-case and a digit)<input type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} /></label>
      <label className="f">Repeat new password<input type="password" autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} /></label>
      <Err e={err} />{ok && <div className="okmsg">{ok}</div>}
      <button className="btn primary" disabled={!cur || !pw || !pw2}>{forced ? 'Save and continue' : 'Change password'}</button>
    </form>
  )
}

function AuthenticatorApp({ user, onChanged }) {
  const [setup, setSetup] = useState(null); const [code, setCode] = useState('')
  const [curPw, setCurPw] = useState(''); const [curCode, setCurCode] = useState('')
  const [err, setErr] = useState(''); const [ok, setOk] = useState('')
  const start = async (e) => {
    e?.preventDefault(); setErr(''); setOk('')
    try { setSetup(await api('/auth/totp/setup', { method: 'POST', body: user.totp_enrolled ? { current_password: curPw || null, current_code: curCode } : {} })) }
    catch (x) { setErr(x.message) }
  }
  const confirm = async (e) => {
    e.preventDefault(); setErr('')
    try {
      const u = await api('/auth/totp/confirm', { method: 'POST', body: { setup_token: setup.setup_token, code } })
      setSetup(null); setCode(''); setCurPw(''); setCurCode(''); setOk('Authenticator linked. It now approves verifications.'); onChanged(u)
    } catch (x) { setErr(x.message) }
  }
  return (
    <div className="card">
      <h2>Authenticator app</h2>
      <p>Status: <b>{user.totp_enrolled ? '✔ linked' : 'not linked'}</b></p>
      {!setup && (
        <form onSubmit={start}>
          {user.totp_enrolled && (<>
            <p style={{ color: 'var(--muted)' }}>To replace it, confirm with {user.auth_source === 'local' ? 'your password and ' : ''}a current code from the old one.</p>
            {user.auth_source === 'local' && <label className="f">Current password<input type="password" value={curPw} onChange={(e) => setCurPw(e.target.value)} /></label>}
            <label className="f">Current 6-digit code<input inputMode="numeric" value={curCode} onChange={(e) => setCurCode(e.target.value)} /></label>
          </>)}
          <button className="btn primary">{user.totp_enrolled ? 'Replace authenticator…' : 'Set up authenticator…'}</button>
        </form>
      )}
      {setup && (
        <form onSubmit={confirm}>
          <ol style={{ paddingLeft: 18, lineHeight: 1.6 }}>
            <li><b>Microsoft Authenticator:</b> tap <b>+</b> → <b>Other account (Google, Facebook, etc.)</b> → scan this QR. Do <u>not</u> choose "Work or school account".</li>
            <li><b>Google Authenticator, Authy, 1Password, Aegis</b> or any other authenticator app also works.</li>
            <li>Turn on the app's fingerprint / face lock so the code needs your biometric.</li>
          </ol>
          <img className="qr" alt="Authenticator QR code" src={setup.qr_png} />
          <p className="mono" style={{ fontSize: 12 }}>Can't scan? Enter this key manually (time-based, 6 digits): <b>{setup.manual_key}</b></p>
          <label className="f">Enter the 6-digit code the app now shows<input inputMode="numeric" autoComplete="one-time-code" autoFocus value={code} onChange={(e) => setCode(e.target.value)} /></label>
          <div className="row"><button className="btn primary" disabled={code.replace(/\D/g, '').length !== 6}>Verify and link</button>
            <button type="button" className="btn" onClick={() => { setSetup(null); setCode('') }}>Cancel</button></div>
        </form>
      )}
      <Err e={err} />{ok && <div className="okmsg">{ok}</div>}
    </div>
  )
}

export default function Account({ user, onUser }) {
  return (<>
    <div className="head"><div><h1>My account</h1><div className="sub">{user.username} · {user.role}</div></div></div>
    <div style={{ display: 'grid', gap: 16, gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))' }}>
      <PasswordForm user={user} onChanged={onUser} />
      <AuthenticatorApp user={user} onChanged={onUser} />
    </div>
  </>)
}
