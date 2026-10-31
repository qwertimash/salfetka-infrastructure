import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Users } from './access'
import { ApiClient, ApiError } from './api'
import { userDetail } from './accessApi'
import type { UserDetail } from './accessApi'
import { AccessIntents } from './accessIntent'

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status })
const groups = { items: [{ id: 'default', name: 'Основная группа', enabled: true }] }
const detail = (id = 'alice', name = 'Алиса'): UserDetail => ({
  user: { id, name, state: 'active', revision: 1, policy_epoch: 1, created_at: '2026-10-14T00:00:00Z', updated_at: '2026-10-14T00:00:00Z' },
  entitlement: { id: `${id}-entitlement`, state: 'active', expires_at: '2031-01-01T12:00:00Z', device_limit: 2, group_id: 'default', quota_bytes: null, revision: 1 },
  devices: [{ id: `${id}-phone`, user_id: id, name: 'Тестовый телефон', state: 'registered', public_key: 'synthetic', revision: 1, credential: { id: `${id}-credential`, version: 1, state: 'active' }, decision: { allowed: true, reason: 'eligible', node_state: 'not_provisioned' } }],
  blocks: [], decision: { allowed: true, reason: 'eligible', node_state: 'not_provisioned' }, outbox_pending: 1,
})
const clickUser = async (name = 'Алиса') => { fireEvent.click(await screen.findByRole('button', { name: new RegExp(`^${name}`) })); await screen.findByRole('heading', { name }) }
function read(url: string, users: UserDetail[]) {
  if (url.includes('/nodes?')) return json({ items: [], next_cursor: null })
  if (url.includes('/access/groups')) return json(groups)
  if (url.includes('/access/users?')) return json({ items: users.map(d => d.user), next_cursor: null })
  return json(users.find(d => url.endsWith(`/users/${d.user.id}`)))
}
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); localStorage.clear() })

describe('scoped access intents', () => {
  it('freezes the full request and retains it through lost response and 429', () => {
    const intents = new AccessIntents()
    const body = { state: 'suspended' }
    const request = { path: '/access/users/alice/state', method: 'POST' as const, body, revision: 1, label: 'Приостановить' }
    const pending = intents.begin('alice', request)
    body.state = 'active'
    intents.failed('alice', pending.key, new ApiError('network_error'))
    intents.failed('alice', pending.key, new ApiError('rate_limited', 429))
    expect(intents.get('alice')?.unknown).toBe(true)
    expect(intents.begin('alice', { ...request, path: '/access/users/bob/state', revision: 3 }).body).toEqual({ state: 'suspended' })
    expect(intents.get('alice')?.revision).toBe(1)
    expect(intents.get('bob')).toBeUndefined()
    intents.finish('alice', 'late_other_key')
    expect(intents.get('alice')?.key).toBe(pending.key)
    intents.finish('alice', pending.key)
    expect(intents.get('alice')).toBeUndefined()
  })
  it('allows correction after a definitive conflict without a prior lost response', () => {
    const intents = new AccessIntents()
    const request = { path: '/access/users/alice/state', method: 'POST' as const, body: { state: 'suspended' }, revision: 1, label: 'Приостановить' }
    const old = intents.begin('alice', request)
    intents.failed('alice', old.key, new ApiError('revision_conflict', 412))
    expect(intents.get('alice')).toBeUndefined()
    expect(intents.begin('alice', { ...request, revision: 2 }).key).not.toBe(old.key)
  })
  it('rejects invalid data instead of changing unknown state into allowed access', () => {
    expect(() => userDetail({ ...detail(), decision: { allowed: true, reason: 'eligible', node_state: 'active' } } as unknown as UserDetail)).toThrow(ApiError)
    expect(() => userDetail(detail(), 'other-user')).toThrow(ApiError)
    const value = detail(); value.devices[0].user_id = 'other-user'
    expect(() => userDetail(value)).toThrow(ApiError)
  })
})

it('keeps access data after failed refresh and disables mutations until refreshed', async () => {
  const data = detail(); let fail = false
  vi.stubGlobal('fetch', vi.fn(async (url: string) => url.endsWith('/users/alice') && fail ? Promise.reject(new TypeError('offline')) : read(url, [data])))
  render(<Users api={new ApiClient()} canWrite intents={new AccessIntents()} />)
  await clickUser()
  expect(screen.getByText('Основная группа')).toBeTruthy()
  fail = true
  fireEvent.click(within(screen.getByRole('region', { name: 'Карточка пользователя' })).getByRole('button', { name: 'Обновить' }))
  await screen.findByRole('alert')
  expect(screen.getByText(/Не обновлено/)).toBeTruthy()
  expect(screen.getByText('Основная группа')).toBeTruthy()
  expect((screen.getByRole('button', { name: 'Продлить' }) as HTMLButtonElement).disabled).toBe(true)
  fail = false
  fireEvent.click(within(screen.getByRole('region', { name: 'Карточка пользователя' })).getByRole('button', { name: 'Обновить' }))
  await waitFor(() => expect((screen.getByRole('button', { name: 'Продлить' }) as HTMLButtonElement).disabled).toBe(false))
})

it('block survives renewal and only explicit clear removes it', async () => {
  const data = detail(); const requests: { path: string; body: Record<string, unknown>; revision: string }[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, options) => {
    if (options.method !== 'POST') return read(url, [data])
    const body = JSON.parse(options.body); requests.push({ path: url, body, revision: options.headers['If-Match'] })
    if (url.endsWith('/blocks')) { data.blocks = [{ id: 'block1', scope: 'user', device_id: null, reason: body.reason, active: true, created_at: '2026-10-14T00:00:00Z' }]; data.decision.allowed = false; data.decision.reason = 'user_blocked' }
    if (url.endsWith('/entitlement')) data.entitlement!.expires_at = body.expires_at
    if (url.endsWith('/clear')) { data.blocks[0].active = false; data.decision.allowed = true; data.decision.reason = 'eligible' }
    data.user.revision++
    return json(data)
  }))
  render(<Users api={new ApiClient()} canWrite intents={new AccessIntents()} />)
  await clickUser()
  fireEvent.click(screen.getByRole('button', { name: 'Заблокировать пользователя' }))
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить блокировку' }))
  await screen.findByText('Действует блокировка пользователя')
  fireEvent.click(screen.getByRole('button', { name: 'Продлить' }))
  fireEvent.change(screen.getByLabelText(/^Срок доступа до/), { target: { value: '2032-01-01T12:00' } })
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить право' }))
  await waitFor(() => expect(requests).toHaveLength(2))
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Сохранить право' })).toBeNull())
  expect(screen.getByText('Действует блокировка пользователя')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Снять блокировку' }))
  fireEvent.click(screen.getByRole('button', { name: 'Подтвердить действие' }))
  await screen.findByText('Активных блокировок нет.')
  expect(requests.map(r => r.revision)).toEqual(['"1"', '"2"', '"3"'])
  expect(requests[1].body.action).toBe('renew')
  expect(screen.getByText('Смотрите выбранный VPN-узел ниже')).toBeTruthy()
})

it('retries the original target after selecting another user and after rate limiting', async () => {
  const alice = detail(); const bob = detail('bob', 'Борис'); const calls: { path: string; key: string; body: string; revision: string }[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, options) => {
    if (options.method !== 'POST') return read(url, [alice, bob])
    calls.push({ path: url, key: options.headers['Idempotency-Key'], body: options.body, revision: options.headers['If-Match'] })
    if (calls.length === 1) { alice.user.state = 'suspended'; alice.user.revision++; throw new TypeError('lost commit response') }
    if (calls.length === 2) return json({ error: { code: 'rate_limited' } }, 429)
    return json(alice)
  }))
  const intents = new AccessIntents()
  render(<Users api={new ApiClient()} canWrite intents={intents} />)
  await clickUser()
  fireEvent.click(screen.getByRole('button', { name: 'Приостановить' }))
  fireEvent.click(screen.getByRole('button', { name: 'Подтвердить действие' }))
  await screen.findByText(/Исход изменения пока неизвестен/)
  await clickUser('Борис')
  expect(screen.queryByRole('button', { name: 'Повторить изменение' })).toBeNull()
  await clickUser()
  fireEvent.click(screen.getByRole('button', { name: 'Повторить изменение' }))
  await screen.findByText(/Слишком много попыток/)
  expect(screen.getByText(/Исход изменения пока неизвестен/)).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Повторить изменение' }))
  await screen.findByText(/Изменение сохранено в панели/)
  expect(calls).toHaveLength(3)
  expect(new Set(calls.map(c => JSON.stringify(c))).size).toBe(1)
  expect(calls[0].path).toBe('/api/v1/access/users/alice/state')
  expect(bob.user.state).toBe('active')
  expect(localStorage.length).toBe(0)
})

it('read-only roles can inspect devices without registration or mutation actions', async () => {
  const data = detail()
  vi.stubGlobal('fetch', vi.fn(async (url: string) => read(url, [data])))
  render(<Users api={new ApiClient()} canWrite={false} intents={new AccessIntents()} />)
  await clickUser()
  expect(within(screen.getByRole('article', { name: 'Устройство Тестовый телефон' })).getByText('Тестовый телефон')).toBeTruthy()
  for (const name of ['Добавить пользователя', 'Продлить', 'Заблокировать пользователя', 'Обновить ключ', 'Отозвать устройство', 'Удалить пользователя']) expect(screen.queryByRole('button', { name })).toBeNull()
  expect(screen.queryByRole('button', { name: /Зарегистрировать/ })).toBeNull()
})

it('terminal entitlement requires explicit restoration and revoked devices stay revoked', async () => {
  const data = detail(); data.entitlement!.state = 'refunded'; data.devices[0].state = 'revoked'; data.devices[0].credential!.state = 'revoked'; data.decision = { allowed: false, reason: 'entitlement_refunded', node_state: 'not_provisioned' }
  vi.stubGlobal('fetch', vi.fn(async (url: string) => read(url, [data])))
  render(<Users api={new ApiClient()} canWrite intents={new AccessIntents()} />)
  await clickUser()
  expect(screen.queryByRole('button', { name: 'Продлить' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Обновить ключ' })).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Восстановить право' }))
  expect(screen.getByText(/Блокировки и отозванные устройства остаются в силе/)).toBeTruthy()
})


it('expires the visible allowed snapshot at its deadline even when refresh fails, then recovers by polling', async () => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-10-14T00:00:00Z'))
  const data = detail(); data.entitlement!.expires_at = new Date(Date.now() + 1000).toISOString()
  let failed = false
  let detailReads = 0
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url.endsWith('/users/alice')) {
      detailReads++
      if (failed) throw new TypeError('offline')
    }
    return read(url, [data])
  }))
  await act(async () => { render(<Users api={new ApiClient()} canWrite intents={new AccessIntents()} />) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /^Алиса/ })) })
  expect(screen.getAllByText('Разрешено по правилам')).toHaveLength(2)
  failed = true
  await act(async () => { await vi.advanceTimersByTimeAsync(1001) })
  expect(detailReads).toBe(2)
  expect(screen.queryByText('Разрешено по правилам')).toBeNull()
  expect(screen.getAllByText('Нет актуального разрешения')).toHaveLength(2)
  expect(screen.getByText('Не обновлено · показаны последние данные')).toBeTruthy()
  expect(screen.getByText('Основная группа')).toBeTruthy()
  expect(within(screen.getByRole('article', { name: 'Устройство Тестовый телефон' })).getByText('Тестовый телефон')).toBeTruthy()
  expect((screen.getByRole('button', { name: 'Обновить ключ' }) as HTMLButtonElement).disabled).toBe(true)
  data.entitlement!.state = 'expired'; data.decision = { allowed: false, reason: 'entitlement_expired', node_state: 'not_provisioned' }; data.devices[0].decision = data.decision
  failed = false
  await act(async () => { await vi.advanceTimersByTimeAsync(15_001) })
  expect(screen.queryByText('Нет актуального разрешения')).toBeNull()
  expect(screen.getAllByText('Запрещено по правилам')).toHaveLength(2)
  expect(screen.queryByText('Не обновлено · показаны последние данные')).toBeNull()
})

it('polling keeps editor values and original If-Match instead of overwriting another operator', async () => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-10-14T00:00:00Z'))
  const data = detail(); let sentRevision = ''
  vi.stubGlobal('fetch', vi.fn(async (url: string, options) => {
    if (options.method === 'POST') { sentRevision = options.headers['If-Match']; return json({ error: { code: 'revision_conflict' } }, 412) }
    return read(url, [data])
  }))
  await act(async () => { render(<Users api={new ApiClient()} canWrite intents={new AccessIntents()} />) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /^Алиса/ })) })
  fireEvent.click(screen.getByRole('button', { name: 'Изменить условия' }))
  fireEvent.change(screen.getByLabelText('Лимит устройств'), { target: { value: '7' } })
  data.user.revision = 2; data.entitlement!.device_limit = 4
  await act(async () => { await vi.advanceTimersByTimeAsync(15_001) })
  expect((screen.getByLabelText('Лимит устройств') as HTMLInputElement).value).toBe('7')
  expect(screen.getByText(/Запись изменилась после открытия формы/)).toBeTruthy()
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Сохранить право' })) })
  expect(sentRevision).toBe('"1"')
  expect(screen.getByRole('alert').textContent).toMatch(/Запись уже изменена/)
  expect((screen.getByLabelText('Лимит устройств') as HTMLInputElement).value).toBe('7')
})
