import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiClient, ApiError, OperationIntent, parseSession, safeError, validateNewPassword } from './api'

const session = { user: { id: 'owner', username: 'owner', role: 'owner' as const }, csrf_token: 'synthetic_csrf' }
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers() })

describe('API security and ambiguous outcomes', () => {
  it('uses only the session cookie and memory CSRF, clears it on logout', async () => {
    const fetcher = vi.fn().mockImplementation(() => Promise.resolve(new Response('{}')))
    vi.stubGlobal('fetch', fetcher)
    const api = new ApiClient(); api.setSession(session)
    await api.request('/operations', { method: 'POST', body: { kind: 'system.check' }, headers: { 'Idempotency-Key': 'same' } })
    const options = fetcher.mock.calls[0][1]
    expect(options.credentials).toBe('same-origin')
    expect(options.headers['X-CSRF-Token']).toBe('synthetic_csrf')
    expect(options.headers.Authorization).toBeUndefined()
    expect(localStorage.length).toBe(0)
    api.clear()
    await api.request('/auth/logout', { method: 'POST', body: {} })
    expect(fetcher.mock.calls[1][1].headers['X-CSRF-Token']).toBe('')
  })
  it('never renders unknown backend errors, raw SQL or unsafe request ids', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: 'SELECT password FROM private', request_id: '<secret>' }, message: 'PRIVATE' }), { status: 500 })))
    const api = new ApiClient()
    try { await api.request('/overview'); throw new Error('unexpected success') }
    catch (error) {
      expect(error).toBeInstanceOf(ApiError)
      expect(safeError(error)).not.toMatch(/SELECT|private|PRIVATE|secret/)
      expect((error as ApiError).outcomeUnknown).toBe(true)
    }
  })
  it('exposes a bounded timeout and aborts the request', async () => {
    vi.useFakeTimers()
    let signal: AbortSignal | undefined
    vi.stubGlobal('fetch', vi.fn((_url, options) => new Promise((_resolve, reject) => { signal = options.signal; signal?.addEventListener('abort', () => reject(new DOMException('abort', 'AbortError'))) })))
    const request = new ApiClient().request('/overview')
    const assertion = expect(request).rejects.toMatchObject({ code: 'request_timeout' })
    await vi.advanceTimersByTimeAsync(12_001)
    await assertion
    expect(signal?.aborted).toBe(true)
  })
  it('notifies expired authenticated sessions but not incorrect login', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation(() => Promise.resolve(new Response('{"error":{"code":"unauthenticated"}}', { status: 401 }))))
    const api = new ApiClient(); api.onUnauthorized = vi.fn()
    await expect(api.request('/auth/login', { method: 'POST', body: {} })).rejects.toBeInstanceOf(ApiError)
    expect(api.onUnauthorized).not.toHaveBeenCalled()
    await expect(api.request('/overview')).rejects.toBeInstanceOf(ApiError)
    expect(api.onUnauthorized).toHaveBeenCalledOnce()
  })
  it('keeps an idempotency key until a definitive outcome', () => {
    const intent = new OperationIntent()
    const key = intent.key()
    expect(intent.key()).toBe(key)
    expect(intent.uncertain).toBe(true)
    intent.finish()
    expect(intent.uncertain).toBe(false)
    expect(intent.key()).not.toBe(key)
  })
  it('rejects malformed sessions and enforces UTF8 password byte limits', () => {
    expect(() => parseSession({ ...session, user: { ...session.user, role: 'superuser' } })).toThrow(ApiError)
    expect(() => validateNewPassword('a'.repeat(12))).not.toThrow()
    expect(() => validateNewPassword('a'.repeat(11))).toThrow(ApiError)
    expect(() => validateNewPassword('я'.repeat(65))).toThrow(ApiError)
  })
  it('a late duplicate response cannot clear a newer operation intent', () => {
    const intent = new OperationIntent()
    const oldKey = intent.key()
    intent.finish(oldKey)
    const newKey = intent.key()
    intent.finish(oldKey)
    expect(intent.key()).toBe(newKey)
    expect(intent.uncertain).toBe(true)
  })
})
