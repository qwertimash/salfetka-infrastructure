import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { ApiClient, ApiError } from './api'
import { Sources, SourceIntents, preview } from './sources'
import type { Preview, Source } from './sources'

const id = '11111111-1111-4111-8111-111111111111'
const versionId = '22222222-2222-4222-8222-222222222222'
const candidateId = '33333333-3333-4333-8333-333333333333'
const summary = (): Preview => ({ format: 'uri', digest: 'a'.repeat(64), profiles: [{ id: 'record-1', engine: 'xray', mode: 'vpn', native: false, auto: false, source_dns: false }], valid_until: null, subscription_expires_at: null, publication_ready: false })
const fixture = (): Source => ({ id, name: 'Тестовый источник', kind: 'url', revision: 1, paused: false, error_code: null, next_fetch_at: new Date(Date.now() + 3600000).toISOString(), current: { id: versionId, preview: summary(), created_at: new Date().toISOString() }, candidate: null, updated_at: new Date().toISOString() })
const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status })
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals() })
it('rejects false publication and keeps missing expiry unknown', () => {
  expect(preview(summary()).subscription_expires_at).toBeNull()
  expect(() => preview({ ...summary(), publication_ready: true } as unknown as Preview)).toThrow(ApiError)
  expect(() => preview({ ...summary(), profiles: [summary().profiles[0], summary().profiles[0]] })).toThrow(ApiError)
})
it('checks before saving and retries an unknown outcome across navigation with the exact draft', async () => {
  const n = fixture(); const requests: RequestInit[] = []; let fail = true
  vi.stubGlobal('fetch', vi.fn(async (url: string, options: RequestInit) => {
    if (url.endsWith('/preview')) return json({ id, preview: summary(), expires_at: new Date(Date.now() + 600000).toISOString() }, 201)
    if (url.endsWith('/mutate')) { requests.push(options); if (fail) throw new TypeError('network'); return json(n) }
    return json({ items: [] })
  }))
  const api = new ApiClient(); const intents = new SourceIntents()
  const first = render(<Sources api={api} canWrite intents={intents} />)
  fireEvent.click(screen.getByRole('button', { name: 'Добавить источник' }))
  fireEvent.change(screen.getByLabelText('Название источника'), { target: { value: 'Тестовый источник' } })
  fireEvent.change(screen.getByLabelText('Или вставьте настройки'), { target: { value: 'private-source-text' } })
  expect(screen.queryByRole('button', { name: 'Сохранить источник' })).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Проверить источник' }))
  await screen.findByText('Предварительный просмотр')
  expect(screen.queryByDisplayValue('private-source-text')).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить источник' }))
  await screen.findByText(/Результат изменения пока неизвестен/)
  first.unmount(); fail = false
  render(<Sources api={api} canWrite intents={intents} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Повторить изменение' }))
  await waitFor(() => expect(intents.get('create')).toBeUndefined())
  expect(requests).toHaveLength(2); expect(requests[0].body).toEqual(requests[1].body); expect(requests[0].headers).toEqual(requests[1].headers)
  expect(String(requests[0].body)).not.toContain('private-source-text')
})
it('keeps last good data on failure and requires review before replacing it', async () => {
  const n = fixture(); n.candidate = { id: candidateId, preview: { ...summary(), profiles: [{ ...summary().profiles[0], id: 'new-record' }] }, created_at: new Date().toISOString() }
  let fail = false; let posted: unknown
  vi.stubGlobal('fetch', vi.fn(async (_url: string, options: RequestInit) => {
    if (options.method === 'POST') { posted = JSON.parse(String(options.body)); n.revision++; n.current = n.candidate!; n.candidate = null; return json(n) }
    if (fail) throw new TypeError('offline'); return json({ items: [n] })
  }))
  render(<Sources api={new ApiClient()} canWrite intents={new SourceIntents()} />)
  fireEvent.click(await screen.findByRole('button', { name: /^Тестовый источник/ }))
  expect(screen.queryByRole('button', { name: 'Принять эту версию' })).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Посмотреть изменения' }))
  fireEvent.click(screen.getByRole('button', { name: 'Принять эту версию' }))
  await waitFor(() => expect(posted).toMatchObject({ operation: 'accept', id, version_id: candidateId, revision: 1 }))
  fail = true; fireEvent.click(within(screen.getByRole('complementary', { name: 'Список источников' })).getByRole('button', { name: 'Обновить' }))
  await screen.findByRole('alert'); expect(screen.getByRole('heading', { name: 'Принятая версия' })).toBeTruthy()
})
it('read-only roles cannot import or accept versions and errors do not expose source text', async () => {
  const n = fixture(); n.error_code = 'source_fetch_failed'
  vi.stubGlobal('fetch', vi.fn(async () => json({ items: [n] })))
  render(<Sources api={new ApiClient()} canWrite={false} intents={new SourceIntents()} />)
  fireEvent.click(await screen.findByRole('button', { name: /^Тестовый источник/ }))
  expect(screen.queryByRole('button', { name: 'Добавить источник' })).toBeNull()
  expect((screen.getByRole('button', { name: 'Проверить обновление' }) as HTMLButtonElement).disabled).toBe(true)
  expect(screen.getByText(/Сохранённая версия не удалена/)).toBeTruthy()
})
