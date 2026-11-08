// Simulated authenticator "phone" running in the browser (lab use).
// A real deployment would use a mobile app: scan QR -> OS biometric prompt -> sign challenge with a hardware-backed key.
// Here an Ed25519 key pair lives in localStorage and the "fingerprint" is a button. The server only ever sees the
// public key and signatures, exactly as in production.
const K = 'edr_phone_key', D = 'edr_phone_device'
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
const pem = (spki) => `-----BEGIN PUBLIC KEY-----\n${b64(spki).match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`

export const phoneSupported = async () => {
  try { await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']); return true } catch { return false }
}
export const phoneDeviceId = () => { const v = localStorage.getItem(D); return v ? Number(v) : null }
export const forgetPhone = () => { localStorage.removeItem(K); localStorage.removeItem(D) }

async function keyPair() {
  const stored = localStorage.getItem(K)
  if (stored) {
    const { priv, pub } = JSON.parse(stored)
    return {
      privateKey: await crypto.subtle.importKey('pkcs8', unb64(priv), { name: 'Ed25519' }, true, ['sign']),
      spki: unb64(pub),
    }
  }
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const priv = b64(await crypto.subtle.exportKey('pkcs8', kp.privateKey))
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey))
  localStorage.setItem(K, JSON.stringify({ priv, pub: b64(spki) }))
  return { privateKey: kp.privateKey, spki }
}

export async function publicKeyPem() { return pem((await keyPair()).spki) }
export const rememberDevice = (id) => localStorage.setItem(D, String(id))

async function post(path, body) {
  const r = await fetch(`/api/v1${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { status: r.status, data: await r.json().catch(() => ({})) }
}

// Scan the QR payload, run the (simulated) biometric check, answer the server.
export async function respond(qrPayload, biometricMatches) {
  const m = /^edr:\/\/verify\?id=(\d+)&n=([A-Za-z0-9_-]+)$/.exec(qrPayload)
  if (!m) throw new Error('Not an EDR verification QR code')
  const [id, nonce, deviceId] = [Number(m[1]), m[2], phoneDeviceId()]
  if (!deviceId) throw new Error('This browser has not been enrolled as an authenticator device')
  const scan = await post(`/verify/${id}/scan`, { nonce, device_id: deviceId })
  if (scan.status !== 200) throw new Error(scan.data.detail || 'Scan rejected')
  if (!biometricMatches) { await post(`/verify/${id}/reject`, { device_id: deviceId }); return 'failed' }
  const { privateKey } = await keyPair()
  const msg = new TextEncoder().encode(`EDR-VERIFY|${id}|${scan.data.challenge}|${scan.data.purpose}|${scan.data.user_id}`)
  const signature = b64(await crypto.subtle.sign('Ed25519', privateKey, msg))
  const done = await post(`/verify/${id}/complete`, { device_id: deviceId, signature })
  return done.data.status
}
