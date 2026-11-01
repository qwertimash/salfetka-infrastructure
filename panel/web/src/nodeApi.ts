import { ApiError } from './api'
import type { Page, Role } from './api'

export type Node = {
  id: string; name: string; state: 'pending' | 'active' | 'revoked'; revision: number
  serial: string | null; certificate_expires_at: string | null; last_seen_at: string | null
  inventory: null | { site?: {domain:string;state:'ready'|'unavailable';expires_at:string;certificate_pem?:string}; schema_version: number; node_id: string; boot_id: string; sequence: number; version: string; platform: string; arch: string; capabilities: string[] }
  contact_state: 'unknown' | 'stale' | 'fresh'; engine_state: 'not_configured'; created_at: string; updated_at: string
}
export type Config = { heartbeat_interval_seconds: number }
export type Command = { schema_version: number; node_id: string; operation_id: string; authority_epoch: number; generation: number; created_at: string; deadline_at: string; kind: string; payload_sha256: string; payload: Config }
export type SignedCommand = { body: string; signature: string }
export type Receipt = { schema_version: number; node_id: string; operation_id: string; authority_epoch: number; generation: number; command_sha256: string; status: 'applied' | 'failed'; config: Config | null; error_code?: string; completed_at: string }
export type Control = { node_id: string; node_revision: number; desired: SignedCommand | null; observed: Receipt | null }
export type Enrollment = { node_id: string; token: string; expires_at: string }
export const canWriteNodes = (role: Role) => role === 'owner' || role === 'infrastructure_operator'
const revision = (n: unknown) => typeof n === 'number' && Number.isSafeInteger(n) && n > 0
const date = (n: unknown) => typeof n === 'string' && Number.isFinite(Date.parse(n))
const id = (n: unknown) => typeof n === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(n)
const hash = (n: unknown) => typeof n === 'string' && /^[0-9a-f]{64}$/.test(n)
const config = (c: Config | null) => c && Number.isInteger(c.heartbeat_interval_seconds) && c.heartbeat_interval_seconds >= 5 && c.heartbeat_interval_seconds <= 30
function check(ok: unknown): asserts ok { if (!ok) throw new ApiError('invalid_response') }
export function node(value: Node, expected?: string): Node {
  check(value && id(value.id) && (!expected || value.id === expected) && typeof value.name === 'string' && ['pending', 'active', 'revoked'].includes(value.state) && revision(value.revision) && ['unknown', 'stale', 'fresh'].includes(value.contact_state) && value.engine_state === 'not_configured' && date(value.created_at) && date(value.updated_at))
  check((value.serial === null || typeof value.serial === 'string') && (value.certificate_expires_at === null || date(value.certificate_expires_at)) && (value.last_seen_at === null || date(value.last_seen_at)))
  const i = value.inventory
  check(i === null || i && i.schema_version === 1 && i.node_id === value.id && id(i.boot_id) && revision(i.sequence) && typeof i.version === 'string' && typeof i.platform === 'string' && typeof i.arch === 'string' && Array.isArray(i.capabilities) && i.capabilities.every(c => typeof c === 'string'))
  if(i?.site)check(/^[a-z0-9.-]+$/.test(i.site.domain)&&i.site.domain.includes('.')&&['ready','unavailable'].includes(i.site.state)&&date(i.site.expires_at))
  return value
}
export function nodesPage(value: Page<Node>) {
  check(value && Array.isArray(value.items) && (value.next_cursor == null || typeof value.next_cursor === 'string'))
  value.items.forEach(n => node(n)); return value
}
// Presentation validates the authenticated server's DTO. Signature verification
// and read-back are performed by the agent/server, never asserted by the UI.
export function command(value: SignedCommand, expected: string): Command {
  check(value && typeof value.body === 'string' && typeof value.signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(value.signature))
  let c: Command
  try { c = JSON.parse(value.body) } catch { throw new ApiError('invalid_response') }
  check(c && c.schema_version === 1 && c.node_id === expected && id(c.operation_id) && c.authority_epoch === 1 && revision(c.generation) && c.kind === 'agent.config.set' && hash(c.payload_sha256) && config(c.payload) && date(c.created_at) && date(c.deadline_at) && Date.parse(c.deadline_at) > Date.parse(c.created_at))
  return c
}
export const receiptErrors: Record<string, string> = { deadline_exceeded: 'Истёк срок первого применения', clock_rollback: 'Агент обнаружил откат часов', apply_failed: 'Агент не смог применить настройку', readback_mismatch: 'Проверка сохранённой настройки не совпала' }
export function control(value: Control, expected: string) {
  check(value && value.node_id === expected && revision(value.node_revision))
  const c = value.desired === null ? null : command(value.desired, expected)
  const r = value.observed
  check(r === null || r && r.schema_version === 1 && r.node_id === expected && id(r.operation_id) && r.authority_epoch === 1 && revision(r.generation) && hash(r.command_sha256) && date(r.completed_at) && (r.status === 'applied' && config(r.config) && !r.error_code || r.status === 'failed' && r.config === null && !!r.error_code && Object.hasOwn(receiptErrors, r.error_code)))
  if (r) {
    check(c && r.generation <= c.generation)
    if (r.generation === c.generation) check(r.operation_id === c.operation_id && (r.status !== 'applied' || r.config!.heartbeat_interval_seconds === c.payload.heartbeat_interval_seconds))
  }
  return value
}
export function enrollment(value: { node: Node; enrollment: Enrollment }, expected: string) {
  node(value?.node, expected)
  const e = value.enrollment
  check(e && e.node_id === expected && typeof e.token === 'string' && /^[A-Za-z0-9_-]{32,128}$/.test(e.token) && date(e.expires_at))
  return e
}
export function contact(n: Node, now: number, staleSnapshot = false) {
  if (n.state === 'revoked') return { label: 'Доступ отозван', tone: 'bad' }
  if (n.certificate_expires_at && now >= Date.parse(n.certificate_expires_at)) return { label: 'Сертификат истёк', tone: 'bad' }
  const elapsed = n.last_seen_at ? now - Date.parse(n.last_seen_at) : NaN
  if (staleSnapshot) return { label: 'Связь не подтверждена', tone: 'neutral' }
  if (n.contact_state === 'fresh' && elapsed >= 0 && elapsed < 60_000) return { label: 'На связи', tone: 'good' }
  if (n.last_seen_at) return { label: 'Нет свежих данных', tone: 'pending' }
  return { label: n.state === 'pending' ? 'Ещё не подключён' : 'Нет данных о связи', tone: 'neutral' }
}
