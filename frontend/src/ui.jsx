import React, { useState, useEffect, useRef } from 'react'
import { api } from './api.js'
import { phoneDeviceId, respond, phoneSupported, publicKeyPem, rememberDevice } from './phone.js'

export const SEV_ICON = { critical: '⬣', high: '▲', medium: '◆', low: '●', Critical: '⬣', High: '▲', Medium: '◆', Low: '●' }
export const Badge = ({ v, kind }) => <span className={`badge ${kind || v}`}>{SEV_ICON[v] ? SEV_ICON[v] + ' ' : ''}{v}</span>
export const fmt = (iso) => (iso ? new Date(iso).toLocaleString([], { hour12: false }) : '—')
export const Err = ({ e }) => (e ? <div className="err" role="alert">{e}</div> : null)

export function useLoad(path, deps = [], every) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [tick, setTick] = useState(0)
  useEffect(() => {
    let live = true
    api(path).then((d) => live && (setData(d), setError(''))).catch((e) => live && setError(e.message))
    const t = every ? setInterval(() => setTick((x) => x + 1), every) : null
    return () => { live = false; t && clearInterval(t) }
  }, [path, tick, ...deps])
  return [data, error, () => setTick((x) => x + 1)]
}

// Horizontal bar list with hover tooltip (native title + fixed tip) — single series, one hue.
export function Bars({ rows, label, value, color, suffix = '' }) {
  const [tip, setTip] = useState(null)
  const max = Math.max(1, ...rows.map((r) => r[value]))
  if (!rows.length) return <div className="empty">No data yet</div>
  return (
    <div>
      {rows.map((r) => (
        <div className="hbar" key={r[label]} onMouseMove={(e) => setTip({ x: e.clientX + 12, y: e.clientY + 12, t: `${r[label]}: ${r[value]}${suffix}` })} onMouseLeave={() => setTip(null)}>
          <div className="l" title={r[label]}>{r[label]}</div>
          <div className="t"><div className="f" style={{ width: `${(r[value] / max) * 100}%`, ...(color ? { background: color } : {}) }} /></div>
          <div className="n">{r[value]}</div>
        </div>
      ))}
      {tip && <div className="tip" style={{ left: tip.x, top: tip.y }}>{tip.t}</div>}
    </div>
  )
}

// Stacked proportion bar with a legend (always shown for >= 2 series; status colours always paired with label+icon).
export function Stack({ parts }) {
  const total = parts.reduce((a, p) => a + p.n, 0)
  return (
    <div>
      <div className="stack" role="img" aria-label={parts.map((p) => `${p.name} ${p.n}`).join(', ')}>
        {parts.filter((p) => p.n).map((p) => <div key={p.name} title={`${p.name}: ${p.n}`} style={{ flex: p.n, background: p.color }} />)}
        {!total && <div style={{ flex: 1 }} />}
      </div>
      <div className="legend">{parts.map((p) => <span key={p.name}><i className="sw" style={{ background: p.color }} />{p.icon} {p.name} <b>{p.n}</b></span>)}</div>
    </div>
  )
}

export function Modal({ children, onClose }) {
  return <div className="modalbg" onMouseDown={(e) => e.target === e.currentTarget && onClose()}><div className="modal" role="dialog" aria-modal="true">{children}</div></div>
}

// QR-assisted biometric verification. Shows a QR (for a real phone) and, for lab use, an in-browser simulated authenticator.
export function VerifyModal({ purpose, onVerified, onClose }) {
  const [ver, setVer] = useState(null)
  const [state, setState] = useState('starting')
  const [error, setError] = useState('')
  const [left, setLeft] = useState(0)
  const [code, setCode] = useState('')
  const done = useRef(false)

  useEffect(() => {
    api('/verify/initiate', { method: 'POST', body: { purpose } })
      .then((v) => { setVer(v); setState('pending'); setLeft(Math.max(0, Math.round((new Date(v.expires_at) - Date.now()) / 1000))) })
      .catch((e) => { setError(e.message); setState('error') })
  }, [])

  useEffect(() => {
    if (!ver || state !== 'pending') return
    const t = setInterval(async () => {
      setLeft((l) => Math.max(0, l - 1))
      try {
        const s = await api(`/verify/${ver.id}`)
        if (s.status === 'verified' && !done.current) { done.current = true; setState('verified'); onVerified(ver.id) }
        else if (['failed', 'expired'].includes(s.status)) { setState(s.status) }
      } catch (e) { setError(e.message) }
    }, 1000)
    return () => clearInterval(t)
  }, [ver, state])

  const simulate = async (match) => {
    setError('')
    try { const r = await respond(ver.qr_payload, match); if (r === 'failed') setState('failed') } catch (e) { setError(e.message) }
  }

  const submitCode = async (e) => {
    e.preventDefault(); setError('')
    try {
      const r = await api(`/verify/${ver.id}/totp`, { method: 'POST', body: { code } })
      setCode('')
      if (r.status === 'failed') setState('failed')
      else if (r.status === 'verified' && !done.current) { done.current = true; setState('verified'); onVerified(ver.id) }
      else setError(`Code not accepted (attempt ${r.attempts} of 3)`)
    } catch (x) { setError(x.message) }
  }
  const m = ver?.methods || { device: true, totp: false }

  return (
    <Modal onClose={onClose}>
      <h2>Biometric verification required</h2>
      <p className="sub" style={{ color: 'var(--muted)' }}>
        {m.totp ? 'Open your authenticator app (Microsoft Authenticator, Google Authenticator, …), unlock it with your fingerprint / face and enter the 6-digit code.' : ''}
        {m.totp && m.device ? ' Or scan the QR with your enrolled device.' : ''}
        {!m.totp ? 'Scan with your enrolled authenticator device and confirm with your fingerprint.' : ''}
      </p>
      {ver && state === 'pending' && m.totp && (
        <form className="card" onSubmit={submitCode} style={{ marginBottom: 12 }}>
          <label className="f">Authenticator code
            <input inputMode="numeric" autoComplete="one-time-code" autoFocus maxLength={7} placeholder="123456" value={code} onChange={(x) => setCode(x.target.value)} /></label>
          <button className="btn primary" disabled={code.replace(/\D/g, '').length !== 6}>Verify code</button>
          <span style={{ color: 'var(--muted)', marginLeft: 10 }}>Expires in {left}s · <span className="mono">{purpose}</span></span>
        </form>
      )}
      {ver && state === 'pending' && m.device && (<>
        <img className="qr" alt="Verification QR code" src={ver.qr_png} />
        <div style={{ textAlign: 'center', color: 'var(--muted)' }}>Expires in {left}s · <span className="mono">{purpose}</span></div>
        <div className="card" style={{ marginTop: 12, background: 'var(--surface2)' }}>
          <h3>Lab authenticator (simulated device)</h3>
          <p style={{ margin: '6px 0', fontSize: 13 }}>No phone? This browser acts as the enrolled device.</p>
          <div className="row">
            <button className="btn primary" onClick={() => simulate(true)}>Scan + fingerprint matches</button>
            <button className="btn danger" onClick={() => simulate(false)}>Fingerprint does not match</button>
          </div>
        </div>
      </>)}
      {state === 'verified' && <div className="okmsg">✔ Verified. Proceeding…</div>}
      {state === 'failed' && <div className="err">✖ Verification failed (wrong code or biometric rejected). Nothing was executed.</div>}
      {state === 'expired' && <div className="err">Verification expired. Close and try again.</div>}
      <Err e={error} />
      <div className="row" style={{ justifyContent: 'flex-end', marginTop: 12 }}><button className="btn" onClick={onClose}>{state === 'verified' ? 'Close' : 'Cancel'}</button></div>
    </Modal>
  )
}

// Hook: ask for verification, then run the protected action with the verification id.
export function useVerified() {
  const [req, setReq] = useState(null)
  const ask = (purpose, action) => setReq({ purpose, action })
  const modal = req && (
    <VerifyModal purpose={req.purpose} onClose={() => setReq(null)}
      onVerified={(id) => { const a = req.action; setTimeout(() => { setReq(null); a(id) }, 600) }} />
  )
  return [ask, modal]
}

export function DeviceSetup({ onDone }) {
  const [msg, setMsg] = useState(''); const [err, setErr] = useState(''); const [ok, setOk] = useState(null)
  useEffect(() => { phoneSupported().then(setOk) }, [])
  const enrol = async () => {
    setErr('')
    try {
      const d = await api('/devices', { method: 'POST', body: { name: 'Lab browser authenticator', public_key_pem: await publicKeyPem() } })
      rememberDevice(d.id); setMsg(`Enrolled device #${d.id}`); onDone && onDone()
    } catch (e) { setErr(e.message) }
  }
  return (
    <div>
      <p>Enrol this browser as a simulated authenticator device (an Ed25519 key pair is generated locally; only the public key is sent to the server).</p>
      {ok === false && <Err e="This browser does not support Ed25519 WebCrypto. Use a recent Chrome, Edge or Firefox, or the Python authenticator in device/authenticator.py." />}
      <button className="btn primary" disabled={ok === false} onClick={enrol}>Enrol this browser</button>
      {msg && <div className="okmsg">{msg}{phoneDeviceId() ? '' : ''}</div>}
      <Err e={err} />
    </div>
  )
}
