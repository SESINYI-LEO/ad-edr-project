import { useCallback, useEffect, useState } from 'react'

/** Fetch on mount and refresh every `ms` (live SOC view). Returns [data, reload, error]. */
export function useLive(fetcher, ms = 5000, deps = []) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const load = useCallback(() => fetcher().then((d) => { setData(d); setError(null) }).catch(setError), deps) // eslint-disable-line
  useEffect(() => {
    load()
    if (!ms) return
    const t = setInterval(load, ms)
    return () => clearInterval(t)
  }, [load, ms])
  return [data, load, error]
}

export const fmt = (iso) => (iso ? new Date(iso + (iso.endsWith('Z') ? '' : 'Z')).toLocaleString() : '—')
export const dur = (s) => (s == null ? '—' : s < 60 ? `${s.toFixed(2)} s` : `${(s / 60).toFixed(1)} min`)
