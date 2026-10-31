import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { Nodes } from './nodes'
import { ApiClient, ApiError } from './api'
import { NodeIntents } from './nodeIntent'
import { canWriteNodes, contact, control, node } from './nodeApi'
import type { Command, Control, Node } from './nodeApi'

const id = '11111111-1111-4111-8111-111111111111'
const other = '22222222-2222-4222-8222-222222222222'
const operation = '33333333-3333-4333-8333-333333333333'
const fixture = (): Node => ({ id, name: 'Тестовый узел', state: 'active', revision: 1, serial: 'serial', certificate_expires_at: new Date(Date.now() + 86400000).toISOString(), last_seen_at: new Date().toISOString(), inventory: { schema_version: 1, node_id: id, boot_id: other, sequence: 1, version: 'test-agent', platform: 'linux', arch: 'arm64', capabilities: ['heartbeat'] }, contact_state: 'fresh', engine_state: 'not_configured', created_at: new Date().toISOString(), updated_at: new Date().toISOString() })
const desired = (generation = 1): Command => ({ schema_version: 1, node_id: id, operation_id: operation, authority_epoch: 1, generation, created_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 600000).toISOString(), kind: 'agent.config.set', payload_sha256: 'a'.repeat(64), payload: { heartbeat_interval_seconds: 7 } })
const signed = (generation = 1) => ({ body: JSON.stringify(desired(generation)), signature: 'a'.repeat(86) })
const settings = (): Control => ({ node_id: id, node_revision: 1, desired: null, observed: null })
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status })
function read(url: string, n: Node, c: Control, extra?: Node) {
  if (url.endsWith('/vpn')) return json({ node_id: url.includes(other) ? other : n.id, installation: null, desired_generation: 0, policy_expires_at: null, received_at: null, observed: null, state: 'not_configured' })
  if (url.includes('/nodes?')) return json({ items: [n, ...(extra ? [extra] : [])] })
  if (url.endsWith('/control')) return json(url.includes(other) ? { ...settings(), node_id: other } : c)
  return json(url.endsWith(other) ? extra : n)
}
const select = async (name = 'Тестовый узел') => { fireEvent.click(await screen.findByRole('button', { name: new RegExp(`^${name}`) })); await screen.findByRole('heading', { name }) }
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals() })

it('validates identity and receipt generation; keeps unknown separate from fresh', () => {
  const n = fixture()
  expect(() => node({ ...n, inventory: { ...n.inventory!, node_id: other } })).toThrow(ApiError)
  const c = settings(); c.desired = signed()
  c.observed = { schema_version: 1, node_id: id, operation_id: operation, authority_epoch: 1, generation: 2, command_sha256: 'b'.repeat(64), status: 'applied', config: { heartbeat_interval_seconds: 7 }, completed_at: new Date().toISOString() }
  expect(() => control(c, id)).toThrow(ApiError)
  c.observed.generation = 1; c.observed.config!.heartbeat_interval_seconds = 8
  expect(() => control(c, id)).toThrow(ApiError)
  expect(contact(n, Date.now() + 60001).label).toBe('Нет свежих данных')
  expect(contact(n, Date.now(), true).label).toBe('Связь не подтверждена')
  expect(contact(n, Date.now() - 60000).label).not.toBe('На связи')
})
it.each(['owner', 'infrastructure_operator', 'access_operator', 'support', 'auditor'] as const)('node actions follow role %s', async role => {
  const n = fixture(); const c = settings()
  vi.stubGlobal('fetch', vi.fn(async (url: string) => read(url, n, c)))
  render(<Nodes api={new ApiClient()} canWrite={canWriteNodes(role)} intents={new NodeIntents()} />)
  await select()
  const write = role === 'owner' || role === 'infrastructure_operator'
  expect(!!screen.queryByRole('button', { name: 'Добавить сервер' })).toBe(write)
  expect(!!screen.queryByRole('button', { name: 'Настроить отчёты' })).toBe(write)
  expect(!!screen.queryByRole('button', { name: 'Отозвать доступ узла' })).toBe(write)
})
it('preserves snapshot after failure, removes live claim and blocks writes until refresh', async () => {
  const n = fixture(); const c = settings(); let fail = false
  vi.stubGlobal('fetch', vi.fn(async (url: string) => { if (fail && url.endsWith('/control')) throw new TypeError('offline'); return read(url, n, c) }))
  render(<Nodes api={new ApiClient()} canWrite intents={new NodeIntents()} />); await select()
  fail = true
  fireEvent.click(within(screen.getByRole('region', { name: 'Карточка узла' })).getByRole('button', { name: 'Обновить' }))
  await screen.findByRole('alert')
  expect(screen.getByText('test-agent')).toBeTruthy()
  expect(screen.getByText('Связь не подтверждена')).toBeTruthy()
  expect((screen.getByRole('button', { name: 'Настроить отчёты' }) as HTMLButtonElement).disabled).toBe(true)
  fail = false
  fireEvent.click(within(screen.getByRole('region', { name: 'Карточка узла' })).getByRole('button', { name: 'Обновить' }))
  await waitFor(() => expect((screen.getByRole('button', { name: 'Настроить отчёты' }) as HTMLButtonElement).disabled).toBe(false))
})
it('a 202 response remains waiting until an agent receipt exists; failed receipt does not claim reset', async () => {
  const n = fixture(); const c = settings()
  vi.stubGlobal('fetch', vi.fn(async (url: string, options) => {
    if (options.method === 'POST') { n.revision++; c.node_revision++; c.desired = signed(); return json({ node_id: id, node_revision: n.revision, command: c.desired }, 202) }
    return read(url, n, c)
  }))
  render(<Nodes api={new ApiClient()} canWrite intents={new NodeIntents()} />); await select()
  fireEvent.click(screen.getByRole('button', { name: 'Настроить отчёты' }))
  fireEvent.change(screen.getByLabelText('Интервал, секунды'), { target: { value: '7' } })
  fireEvent.click(screen.getByRole('button', { name: 'Отправить настройку' }))
  await screen.findByText(/Ожидаем ответ на новую настройку/)
  expect(screen.queryByText(/^Применено:/)).toBeNull()
  c.observed = { schema_version: 1, node_id: id, operation_id: operation, authority_epoch: 1, generation: 1, command_sha256: 'b'.repeat(64), status: 'failed', config: null, error_code: 'clock_rollback', completed_at: new Date().toISOString() }
  fireEvent.click(within(screen.getByRole('region', { name: 'Карточка узла' })).getByRole('button', { name: 'Обновить' }))
  await screen.findByText('Ошибка применения')
  expect(screen.getByText(/Текущая действующая настройка этим ответом не подтверждена/)).toBeTruthy()
})
it('retains original request through lost commit, navigation, remount and rate limit', async () => {
  const n = fixture(); const c = settings(); const extra = { ...fixture(), id: other, name: 'Другой узел', inventory: null }
  const requests: unknown[] = []; const intents = new NodeIntents()
  vi.stubGlobal('fetch', vi.fn(async (url: string, options) => {
    if (options.method !== 'POST') return read(url, n, c, extra)
    requests.push({ path: url, body: options.body, headers: options.headers })
    if (requests.length === 1) { n.revision++; c.node_revision++; c.desired = signed(); throw new TypeError('lost response') }
    if (requests.length === 2) return json({ error: { code: 'rate_limited' } }, 429)
    return json({ node_id: id, node_revision: 2, command: c.desired }, 202)
  }))
  const view = render(<Nodes api={new ApiClient()} canWrite intents={intents} />); await select()
  fireEvent.click(screen.getByRole('button', { name: 'Настроить отчёты' })); fireEvent.change(screen.getByLabelText('Интервал, секунды'), { target: { value: '7' } })
  fireEvent.click(screen.getByRole('button', { name: 'Отправить настройку' })); await screen.findByText(/Исход изменения пока неизвестен/)
  await select('Другой узел'); expect(screen.queryByRole('button', { name: 'Повторить изменение' })).toBeNull()
  view.unmount(); render(<Nodes api={new ApiClient()} canWrite intents={intents} />); await select()
  fireEvent.click(screen.getByRole('button', { name: 'Повторить изменение' })); await screen.findByText(/Слишком много попыток/)
  fireEvent.click(screen.getByRole('button', { name: 'Повторить изменение' })); await screen.findByText(/Изменение сохранено в панели/)
  expect(requests).toHaveLength(3); expect(new Set(requests.map(r => JSON.stringify(r))).size).toBe(1)
  expect(localStorage.length).toBe(0)
})
it('polling does not rebase an open editor or replace the entered interval', async () => {
  vi.useFakeTimers()
  const n = fixture(); const c = settings(); let sent = ''
  vi.stubGlobal('fetch', vi.fn(async (url: string, options) => {
    if (options.method === 'POST') { sent = options.headers['If-Match']; return json({ error: { code: 'revision_conflict' } }, 412) }
    return read(url, n, c)
  }))
  await act(async () => { render(<Nodes api={new ApiClient()} canWrite intents={new NodeIntents()} />) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /^Тестовый узел/ })) })
  fireEvent.click(screen.getByRole('button', { name: 'Настроить отчёты' })); fireEvent.change(screen.getByLabelText('Интервал, секунды'), { target: { value: '9' } })
  n.revision++; c.node_revision++
  await act(async () => { await vi.advanceTimersByTimeAsync(5001) })
  expect(screen.getByText(/Запись изменилась после открытия формы/)).toBeTruthy()
  expect((screen.getByLabelText('Интервал, секунды') as HTMLInputElement).value).toBe('9')
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Отправить настройку' })) })
  expect(sent).toBe('"1"'); expect(screen.getByRole('alert').textContent).toMatch(/Запись уже изменена/)
})
it('keeps enrollment secret out of DOM and storage, and deletes expired secrets', async () => {
  vi.useFakeTimers()
  const n = { ...fixture(), state: 'pending' as const, inventory: null, last_seen_at: null, certificate_expires_at: null }; const c = settings()
  const intents = new NodeIntents(); const token = 't'.repeat(43)
  vi.stubGlobal('fetch', vi.fn(async (url: string, options) => {
    if (options.method === 'POST') { n.revision++; c.node_revision++; return json({ node: n, enrollment: { node_id: id, token, expires_at: new Date(Date.now() + 1000).toISOString() } }, 201) }
    return read(url, n, c)
  }))
  await act(async () => { render(<Nodes api={new ApiClient()} canWrite intents={intents} />) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /^Тестовый узел/ })) })
  fireEvent.click(screen.getByRole('button', { name: 'Подключить агент' }))
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Создать файл подключения' })) })
  expect(screen.getByRole('button', { name: 'Скачать файл подключения' })).toBeTruthy()
  expect(document.body.innerHTML).not.toContain(token); expect(localStorage.length).toBe(0)
  await act(async () => { await vi.advanceTimersByTimeAsync(1001) })
  expect(screen.queryByRole('button', { name: 'Скачать файл подключения' })).toBeNull(); expect(intents.secret(id)).toBeUndefined()
})

it('does not duplicate an in-flight enrollment after route remount and retains its delayed secret', async () => {
  vi.useFakeTimers()
  const n = { ...fixture(), state: 'pending' as const, inventory: null, last_seen_at: null, certificate_expires_at: null }; const c = settings()
  const intents = new NodeIntents(); let resolve!: (r: Response) => void; let writes = 0
  vi.stubGlobal('fetch', vi.fn(async (url: string, options) => {
    if (options.method === 'POST') { writes++; return new Promise<Response>(r => { resolve = r }) }
    return read(url, n, c)
  }))
  let view!: ReturnType<typeof render>
  await act(async () => { view = render(<Nodes api={new ApiClient()} canWrite intents={intents} />) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /^Тестовый узел/ })) })
  fireEvent.click(screen.getByRole('button', { name: 'Подключить агент' }))
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Создать файл подключения' })) })
  view.unmount()
  await act(async () => { render(<Nodes api={new ApiClient()} canWrite intents={intents} />) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /^Тестовый узел/ })) })
  expect((screen.getByRole('button', { name: 'Повторить изменение' }) as HTMLButtonElement).disabled).toBe(true)
  await act(async () => { resolve(json({ node: { ...n, revision: 2 }, enrollment: { node_id: id, token: 't'.repeat(43), expires_at: new Date(Date.now() + 600000).toISOString() } })); await vi.advanceTimersByTimeAsync(1001) })
  expect(screen.getByRole('button', { name: 'Скачать файл подключения' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Повторить изменение' })).toBeNull()
  expect(writes).toBe(1)
})
