import { ApiError } from './api'
import { AccessIntents } from './accessIntent'
import { emptyDocument, parseDraft, uuid } from './constructorModel'
import type { Document, Draft } from './constructorModel'

export type SetRecord = Draft & { published_id: string | null }
export type SetSummary = { id: string; title: string; revision: number; updated_at: string }
export type Assignment = { id: string; user_id: string; set_id: string; state: 'active' | 'revoked'; revision: number; updated_at: string }
export type Publication = { id: string; set_id: string; revision: number; current: boolean; created_at: string; expected_devices: number; users_without_device: number; published_devices: number; pending_devices: number; retry_devices: number; cancelled_devices: number }
export type Target = { assignment_id: string; assignment_revision: number; user_id: string; device_id: string; state: string; code: string; attempts: number }
export type SetPage<T> = { items: T[]; next_cursor: string }
export class SetSession extends AccessIntents {
  busy = false
  saved?: SetRecord
  document?: Document
  json?: string
  selected?: string
  pendingScope?: string
  fresh() { this.saved = undefined; this.document = emptyDocument(); this.document.title = 'Новая подписка'; this.selected = 'new' }
}
export function setRecord(v: SetRecord, id?: string) {
  parseDraft(v)
  if (id && v.id !== id || v.published_id !== null && !uuid.test(v.published_id)) throw new ApiError('invalid_response')
  return v
}
export function setPage<T>(v: SetPage<T>, check: (v: T) => void) {
  if (!v || !Array.isArray(v.items) || typeof v.next_cursor !== 'string' || v.next_cursor.length > 120 || !/^[a-zA-Z0-9_:-]*$/.test(v.next_cursor)) throw new ApiError('invalid_response')
  v.items.forEach(check); return v
}
export function summary(v: SetSummary) {
  if (!v || !uuid.test(v.id) || typeof v.title !== 'string' || !Number.isSafeInteger(v.revision) || v.revision < 1) throw new ApiError('invalid_response')
}
export function assignment(v: Assignment, user?: string, set?: string) {
  if (!v || ![v.id, v.user_id, v.set_id].every(id => uuid.test(id)) || user && v.user_id !== user || set && v.set_id !== set || !['active', 'revoked'].includes(v.state) || !Number.isSafeInteger(v.revision) || v.revision < 1) throw new ApiError('invalid_response')
  return v
}
export function publication(v: Publication, set: string) {
  if (!v || !uuid.test(v.id) || v.set_id !== set || !Number.isSafeInteger(v.revision) || v.revision < 1 || typeof v.current !== 'boolean' || !Number.isFinite(Date.parse(v.created_at)) || [v.expected_devices, v.users_without_device, v.published_devices, v.pending_devices, v.retry_devices, v.cancelled_devices].some(n => !Number.isSafeInteger(n) || n < 0)) throw new ApiError('invalid_response')
  return v
}
export function personalURL(v: { url: string }, kind: 'a' | 's' | 'i') {
  let url: URL
  try { url = new URL(v.url) } catch { throw new ApiError('invalid_response') }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !new RegExp(`^/${kind}/[A-Za-z0-9_-]+$`).test(url.pathname)) throw new ApiError('invalid_response')
  return v.url
}
