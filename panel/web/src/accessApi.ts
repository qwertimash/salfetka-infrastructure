import { ApiError } from './api'
import type { Page, Role } from './api'

export type AccessUser = { id: string; name: string; state: 'active' | 'suspended' | 'deleted'; revision: number; policy_epoch: number; created_at: string; updated_at: string }
export type Decision = { allowed: boolean; reason: string; node_state: 'not_provisioned' }
export type Entitlement = { id?: string; state: 'active' | 'expired' | 'revoked' | 'refunded'; expires_at: string; device_limit: number; group_id: string; quota_bytes: number | null; revision: number }
export type Device = { id: string; user_id: string; name: string; state: 'registered' | 'revoked'; public_key: string; revision: number; credential: null | { id: string; version: number; state: 'active' | 'revoked' }; decision: Decision }
export type Block = { id: string; scope: 'user' | 'device'; device_id: string | null; reason: string; active: boolean; created_at: string }
export type UserDetail = { user: AccessUser; entitlement: Entitlement | null; devices: Device[]; blocks: Block[]; decision: Decision; outbox_pending: number }
export type AccessGroup = { id: string; name: string; enabled: boolean }
export const canReadAccess = (role: Role) => role !== 'infrastructure_operator'
export const canWriteAccess = (role: Role) => role === 'owner' || role === 'access_operator'
const validRevision = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 1
const validUser = (u: AccessUser) => u && typeof u.id === 'string' && typeof u.name === 'string' && ['active', 'suspended', 'deleted'].includes(u.state) && validRevision(u.revision)
const validDecision = (d: Decision) => d && typeof d.allowed === 'boolean' && typeof d.reason === 'string' && d.node_state === 'not_provisioned'

export function accessUsers(value: Page<AccessUser>): Page<AccessUser> {
  if (!value || !Array.isArray(value.items) || value.items.some(u => !validUser(u)) || value.next_cursor != null && typeof value.next_cursor !== 'string') throw new ApiError('invalid_response')
  return value
}
export function accessGroups(value: { items: AccessGroup[] }) {
  if (!value || !Array.isArray(value.items) || value.items.some(g => !g || typeof g.id !== 'string' || typeof g.name !== 'string' || typeof g.enabled !== 'boolean')) throw new ApiError('invalid_response')
  return value
}
export function userDetail(value: UserDetail, expectedID?: string): UserDetail {
  if (!value || !validUser(value.user) || expectedID && value.user.id !== expectedID || !validDecision(value.decision) || !Number.isSafeInteger(value.outbox_pending) || value.outbox_pending < 0 || !Array.isArray(value.devices) || !Array.isArray(value.blocks)) throw new ApiError('invalid_response')
  const e = value.entitlement
  if (e !== null && (!e || e.id != null && typeof e.id !== 'string' || !['active', 'expired', 'revoked', 'refunded'].includes(e.state) || !Number.isFinite(Date.parse(e.expires_at)) || !validRevision(e.revision) || !Number.isSafeInteger(e.device_limit) || e.device_limit < 1 || typeof e.group_id !== 'string' || e.quota_bytes !== null && (!Number.isSafeInteger(e.quota_bytes) || e.quota_bytes < 0))) throw new ApiError('invalid_response')
  if (value.devices.some(d => !d || typeof d.id !== 'string' || typeof d.name !== 'string' || d.user_id !== value.user.id || !['registered', 'revoked'].includes(d.state) || !validRevision(d.revision) || !validDecision(d.decision) || d.credential !== null && (!d.credential || typeof d.credential.id !== 'string' || !validRevision(d.credential.version) || !['active', 'revoked'].includes(d.credential.state)))) throw new ApiError('invalid_response')
  if (value.blocks.some(b => !b || typeof b.id !== 'string' || !['user', 'device'].includes(b.scope) || typeof b.active !== 'boolean' || typeof b.reason !== 'string' || b.scope === 'device' && !value.devices.some(d => d.id === b.device_id))) throw new ApiError('invalid_response')
  return value
}

const reasons: Record<string, string> = {
  eligible: 'Условия доступа выполнены', no_eligible_device: 'Нет устройства, отвечающего всем условиям доступа', allowed: 'Условия доступа выполнены', active: 'Условия доступа выполнены',
  user_suspended: 'Пользователь приостановлен', user_deleted: 'Пользователь удалён', user_inactive: 'Пользователь не активен',
  no_entitlement: 'Право доступа ещё не выдано', entitlement_missing: 'Право доступа ещё не выдано',
  entitlement_expired: 'Срок права доступа истёк', expired: 'Срок права доступа истёк',
  entitlement_revoked: 'Право доступа отозвано', entitlement_refunded: 'Возврат по праву доступа', entitlement_inactive: 'Право доступа не активно',
  user_blocked: 'Действует блокировка пользователя', device_blocked: 'Действует блокировка устройства', policy_blocked: 'Действует блокировка',
  device_revoked: 'Устройство отозвано', device_missing: 'Устройство ещё не зарегистрировано',
  credential_revoked: 'Ключ доступа отозван', credential_missing: 'Ключ доступа отсутствует',
  group_disabled: 'Группа отключена', group_missing: 'Группа недоступна', group_not_allowed: 'Группа не разрешена',
  quota_unknown: 'Нет достоверных данных о расходе квоты', quota_exceeded: 'Квота исчерпана',
}
export function decisionReason(reason: string) { return reasons[reason] ?? 'Решение требует проверки оператором' }
export const userStates = { active: 'Активен', suspended: 'Приостановлен', deleted: 'Удалён' }
export const entitlementStates = { active: 'Действует', expired: 'Истёк срок', revoked: 'Отозвано', refunded: 'Возврат' }
export const blockReasons: Record<string, string> = { manual: 'Решение оператора', policy: 'Правила доступа', abuse: 'Нарушение правил', security: 'Безопасность' }
