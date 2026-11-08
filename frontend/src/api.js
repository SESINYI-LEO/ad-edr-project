// Thin fetch wrapper: bearer token in sessionStorage, JSON in/out, errors surface the server's "detail".
const KEY = 'edr_token'
export const getToken = () => sessionStorage.getItem(KEY)
export const setToken = (t) => (t ? sessionStorage.setItem(KEY, t) : sessionStorage.removeItem(KEY))

let onUnauthorized = () => {}
export const setUnauthorizedHandler = (fn) => (onUnauthorized = fn)

export async function api(path, { method = 'GET', body } = {}) {
  const headers = { 'Content-Type': 'application/json' }
  const t = getToken()
  if (t) headers.Authorization = `Bearer ${t}`
  const res = await fetch(`/api/v1${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined })
  let data = null
  try { data = await res.json() } catch { /* empty body */ }
  if (res.status === 401 && path !== '/auth/login') onUnauthorized()
  if (!res.ok) {
    const d = data?.detail
    throw new Error(typeof d === 'string' ? d : Array.isArray(d) ? d.map((x) => x.msg).join('; ') : `Request failed (${res.status})`)
  }
  return data
}
