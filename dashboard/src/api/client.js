import axios from 'axios'

const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const api = axios.create({ baseURL: BASE })

api.interceptors.request.use((cfg) => {
  const t = localStorage.getItem('edr_token')
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  return cfg
})
api.interceptors.response.use(
  (r) => r,
  (e) => {
    if (e.response?.status === 401 && !e.config.url.includes('/auth/login')) {
      localStorage.removeItem('edr_token')
      window.location.href = '/login'
    }
    // signed in with an admin-issued temporary password: nothing else works until it is changed
    if (e.response?.status === 403 && e.response?.data?.detail === 'Password change required' && !window.location.pathname.startsWith('/account')) {
      window.location.href = '/account'
    }
    return Promise.reject(e)
  }
)

const txHeaders = (tx) => (tx ? { headers: { 'X-Auth-Transaction': tx } } : undefined)
export const get = (url, params) => api.get(url, { params }).then((r) => r.data)
export const post = (url, body = {}, tx) => api.post(url, body, txHeaders(tx)).then((r) => r.data)
export const patch = (url, body = {}, tx) => api.patch(url, body, txHeaders(tx)).then((r) => r.data)

export function errMsg(e) {
  const d = e?.response?.data?.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d)) return d.map((x) => x.msg).join('; ')
  return e?.message || 'Request failed'
}

export function saveSession(data) {
  localStorage.setItem('edr_token', data.access_token)
  localStorage.setItem('edr_user', JSON.stringify(data.user))
}
export const saveUser = (u) => localStorage.setItem('edr_user', JSON.stringify(u))

export async function login(username, password) {
  const f = new URLSearchParams({ username, password })
  const { data } = await api.post('/api/auth/login', f)
  saveSession(data)
  return data.user
}

export const currentUser = () => JSON.parse(localStorage.getItem('edr_user') || 'null')
export const isAdmin = () => currentUser()?.role === 'administrator'
