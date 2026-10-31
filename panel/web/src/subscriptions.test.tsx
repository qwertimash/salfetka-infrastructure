import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { ApiClient, ApiError } from './api'
import { Subscriptions, SubscriptionIntents, publicationReadiness, subscriptionDetail, subscriptionLink } from './subscriptions'
const user = '11111111-1111-4111-8111-111111111111', device = '22222222-2222-4222-8222-222222222222', sub = '33333333-3333-4333-8333-333333333333', release = '44444444-4444-4444-8444-444444444444'
const decision = { allowed: true, reason: 'active', node_state: 'not_provisioned' }
const u = { id: user, name: 'Получатель теста', revision: 1, policy_epoch: 1, state: 'active', created_at: new Date().toISOString(), updated_at: new Date().toISOString() }
const profile = { content_digest: 'a'.repeat(64), id: 'xray', engine: 'xray', mode: 'vpn', native: true, auto: false, source_dns: false }
const fixture = () => ({ subscription: { id: sub, user_id: user, device_id: device, revision: 2, active_release: null, token_active: false, token_revision: 0 }, releases: [{ id: release, number: 1, state: 'staged', digest: 'a'.repeat(64), preview: { format: 'manifest', digest: 'a'.repeat(64), profiles: [profile], valid_until: new Date(Date.now() + 86400000).toISOString(), subscription_expires_at: null, publication_ready: false }, provenance: { external_credentials: true }, checks: [], created_at: new Date().toISOString() }] })
const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status })
afterEach(() => vi.unstubAllGlobals())
it('accepts a separate HTTPS delivery origin and rejects unsafe or noncanonical links', () => {
  const path = '/s/' + 'x'.repeat(43)
  for (const host of ['https://localhost:18463', 'https://subscriptions.example.com']) {
    expect(subscriptionLink(host + path)).toBe(host + path)
  }
  for (const value of [undefined, {}, '/s/relative', 'http://host.test' + path,
    'https://user@host.test' + path, 'https://host.test/../' + path.slice(1),
    'https://host.test' + path + '?', 'https://host.test' + path + '#',
    'https://host.test' + path + '\n', 'https://host.test/s/short',
    'javascript:alert(1)', 'https://host.test/api/v1/subscriptions']) {
    expect(() => subscriptionLink(value)).toThrow(ApiError)
  }
})
it('rejects wrong device and false publication projections', () => {
  const d = fixture()
  expect(() => subscriptionDetail(d as never, user, sub)).toThrow(ApiError)
  d.subscription.active_release = release as never
  expect(() => subscriptionDetail(d as never, user, device)).toThrow(ApiError)
})
it('preserves publish intent after lost response and does not claim a first publication on partial readiness', async () => {
  let fail = true; const writes: RequestInit[] = []; const d = fixture()
  vi.stubGlobal('fetch', vi.fn(async (url: string, options: RequestInit) => {
    if (url.endsWith('/subscriptions/mutate')) { writes.push(options); if (fail) throw new TypeError('offline'); d.releases[0].state = 'partial'; return json(d) }
    if (url.includes('/subscriptions/')) return json(d)
    if (url.includes('/access/users?')) return json({ items: [u], next_cursor: null })
    if (url.endsWith(`/access/users/${user}`)) return json({ user: u, entitlement: null, devices: [{ id: device, user_id: user, name: 'Телефон теста', state: 'registered', revision: 1, public_key: 'public', credential: null, decision }], blocks: [], decision, outbox_pending: 0 })
    return json({ items: [], next_cursor: null })
  }))
  const api = new ApiClient(); const intents = new SubscriptionIntents()
  const choose = async () => { fireEvent.click(await screen.findByRole('button', { name: 'Получатель теста' })); await screen.findByRole('option', { name: 'Телефон теста' }); fireEvent.change(screen.getByLabelText('Устройство'), { target: { value: device } }); await screen.findByRole('heading', { name: 'Версия 1' }) }
  const first = render(<Subscriptions api={api} canWrite intents={intents} />); await choose()
  await waitFor(() => expect((screen.getByRole('button', { name: 'Опубликовать версию 1' }) as HTMLButtonElement).disabled).toBe(false))
  fireEvent.click(screen.getByRole('button', { name: 'Опубликовать версию 1' })); await screen.findByText(/Результат изменения пока неизвестен/)
  first.unmount(); fail = false
  render(<Subscriptions api={api} canWrite intents={intents} />); await choose()
  fireEvent.click(screen.getByRole('button', { name: 'Повторить изменение' }))
  await screen.findByText(/Первая версия ещё не опубликована/)
  expect(writes).toHaveLength(2); expect(writes[0].body).toEqual(writes[1].body); expect(writes[0].headers).toEqual(writes[1].headers)
  expect(screen.queryByText('Выдаётся сейчас')).toBeNull()
  expect((screen.getByRole('button', { name: 'Создать ссылку' }) as HTMLButtonElement).disabled).toBe(true)
  expect(localStorage.length + sessionStorage.length).toBe(0)
})

it('distinguishes pending keys, unhealthy nodes and an active previous release', () => {
  const d = fixture(); d.releases[0].state = 'partial'
  const r = d.releases[0]; r.checks = [{ node_id: device, state: 'grant_pending' }] as never
  expect(publicationReadiness(d as never, r as never)).toContain('Серверы ещё применяют ключ')
  expect(publicationReadiness(d as never, r as never)).toContain('Первая версия ещё не опубликована')
  d.subscription.active_release = sub as never
  expect(publicationReadiness(d as never, r as never)).toContain('Прежняя версия продолжает выдаваться')
  r.checks = [{ node_id: device, state: 'unreachable' }] as never
  expect(publicationReadiness(d as never, r as never)).toContain('Не все серверы подтвердили')
  r.state = 'healthy'
  expect(publicationReadiness(d as never, r as never)).toContain('Нажмите «Опубликовать»')
  r.state = 'published'
  expect(publicationReadiness(d as never, r as never)).not.toContain('Эта версия опубликована')
  d.subscription.active_release = release as never
  expect(publicationReadiness(d as never, r as never)).toBe('Эта версия опубликована и выдаётся устройству.')
})
