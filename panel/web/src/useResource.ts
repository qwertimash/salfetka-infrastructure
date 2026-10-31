import { useCallback, useEffect, useRef, useState } from 'react'

export type Resource<T> = { data?: T; error?: unknown; loading: boolean; updatedAt?: Date; refresh: () => void }

// One request at a time; refresh during a request is coalesced. Aborted/stale
// responses cannot overwrite a newer identity or route. Last good data survives.
export function useResource<T>(load: (signal: AbortSignal) => Promise<T>, interval = 0): Resource<T> {
  const [state, setState] = useState<Omit<Resource<T>, 'refresh'>>({ loading: true })
  const refreshRef = useRef<() => void>(() => {})
  const refresh = useCallback(() => refreshRef.current(), [])
  useEffect(() => {
    let alive = true
    let running = false
    let queued = false
    let controller: AbortController | undefined
    let timer: ReturnType<typeof setTimeout> | undefined
    setState({ loading: true })
    const run = async () => {
      if (!alive) return
      if (running) { queued = true; return }
      clearTimeout(timer)
      running = true
      controller = new AbortController()
      setState(previous => ({ ...previous, loading: true }))
      try {
        const data = await load(controller.signal)
        if (alive) setState({ data, updatedAt: new Date(), loading: false })
      } catch (error) {
        if (alive && !controller.signal.aborted) setState(previous => ({ ...previous, error, loading: false }))
      } finally {
        running = false
        if (alive) {
          if (queued) { queued = false; void run() }
          else if (interval) timer = setTimeout(() => void run(), interval)
        }
      }
    }
    refreshRef.current = () => void run()
    void run()
    return () => { alive = false; clearTimeout(timer); controller?.abort(); refreshRef.current = () => {} }
  }, [load, interval])
  return { ...state, refresh }
}
