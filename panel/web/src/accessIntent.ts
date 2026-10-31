import { ApiError } from './api'

export type AccessRequest = { path: string; method: 'POST' | 'PATCH'; body: unknown; revision?: number; label: string }
export type PendingAccessIntent = AccessRequest & { key: string; unknown: boolean }

// The shell owns this memory-only store. The scope is the actual target user,
// never the selected row or visible form. Retries use the original whole request.
export class AccessIntents {
  private pending = new Map<string, PendingAccessIntent>()
  get(scope: string) { return this.pending.get(scope) }
  begin(scope: string, request: AccessRequest) {
    const existing = this.pending.get(scope)
    if (existing) return existing
    const intent = { ...request, body: structuredClone(request.body), key: crypto.randomUUID(), unknown: false }
    this.pending.set(scope, intent)
    return intent
  }
  failed(scope: string, key: string, error: unknown) {
    const intent = this.pending.get(scope)
    if (!intent || intent.key !== key) return
    const unknown = !(error instanceof ApiError) || error.outcomeUnknown
    if (unknown) intent.unknown = true
    // A rate limit does not answer whether a preceding response was lost. Keep
    // its request even on the first rejection, so retry never changes intent.
    if (!intent.unknown && !(error instanceof ApiError && error.status === 429)) this.pending.delete(scope)
  }
  finish(scope: string, key: string) {
    if (this.pending.get(scope)?.key === key) this.pending.delete(scope)
  }
}
