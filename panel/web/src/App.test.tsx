import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { App } from './App'
import { ApiClient, OperationIntent } from './api'
import type { Role } from './api'
import { Admins, Operations, OverviewPage } from './pages'

const session = (role: Role = 'owner') => ({ user: { id: 'owner', username: 'owner', role }, csrf_token: 'synthetic_csrf' })
const overview = { service_status: 'ok', database_status: 'ok', counts: { admins: 3, jobs_pending: 2, jobs_failed: 1 }, vpn_status: 'not_configured' }
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status })
afterEach(() => { vi.unstubAllGlobals(); window.history.replaceState({}, '', '/'); localStorage.clear() })

it('keeps overview values visible and marks them stale after refresh fails', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json(overview)).mockRejectedValue(new TypeError('offline')))
  render(<OverviewPage api={new ApiClient()} openOperations={() => {}} />)
  await screen.findByText('3')
  fireEvent.click(screen.getByRole('button', { name: 'Обновить' }))
  await screen.findByRole('alert')
  expect(screen.getByText('3')).toBeTruthy()
  expect(screen.getByText(/Не обновлено/)).toBeTruthy()
  expect(screen.getByText('Что хотите сделать?')).toBeTruthy()
})

it('does not turn unavailable initial data into zero or successful service health', async () => {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')))
  render(<OverviewPage api={new ApiClient()} openOperations={() => {}} />)
  await screen.findByRole('alert')
  expect(screen.getAllByText('—')).toHaveLength(3)
  expect(screen.queryByText('Работает')).toBeNull()
})

it('retries the same operation key after an unknown outcome', async () => {
  const keys: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (_url, options) => {
    if (options.method === 'POST') {
      keys.push(options.headers['Idempotency-Key'])
      if (keys.length === 1) throw new TypeError('connection lost after commit')
      return json({ id: 'job1', status: 'pending', kind: 'system.check', created_at: '2026-10-13T12:00:00Z' }, 202)
    }
    return json({ items: [], next_cursor: null })
  }))
  render(<Operations api={new ApiClient()} canCreate intent={new OperationIntent()} />)
  fireEvent.click(screen.getByRole('button', { name: 'Проверить систему' }))
  await screen.findByText(/Исход запроса пока неизвестен/)
  fireEvent.click(screen.getByRole('button', { name: 'Повторить запрос' }))
  await screen.findByText(/Запрос принят/)
  expect(keys).toHaveLength(2)
  expect(keys[0]).toBe(keys[1])
})

it('a rejected retry cannot discard a prior unknown operation outcome', async () => {
  const keys: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (_url, options) => {
    if (options.method !== 'POST') return json({ items: [], next_cursor: null })
    keys.push(options.headers['Idempotency-Key'])
    if (keys.length === 1) throw new TypeError('connection lost after commit')
    if (keys.length === 2) return json({ error: { code: 'rate_limited' } }, 429)
    return json({ id: 'same-job', status: 'pending', kind: 'system.check' }, 202)
  }))
  render(<Operations api={new ApiClient()} canCreate intent={new OperationIntent()} />)
  fireEvent.click(screen.getByRole('button', { name: 'Проверить систему' }))
  await screen.findByText(/Исход запроса пока неизвестен/)
  fireEvent.click(screen.getByRole('button', { name: 'Повторить запрос' }))
  await screen.findByText(/Слишком много попыток/)
  expect(screen.getByText(/Исход запроса пока неизвестен/)).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Повторить запрос' }))
  await screen.findByText(/Запрос принят/)
  expect(keys).toHaveLength(3)
  expect(new Set(keys).size).toBe(1)
})

it.each(['support', 'access_operator', 'auditor', 'infrastructure_operator'] as Role[])('shows role-limited navigation and actions for %s', async role => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url.endsWith('/setup/status')) return json({ setup_required: false })
    if (url.endsWith('/auth/session')) return json(session(role))
    if (url.endsWith('/overview')) return json(overview)
    return json({ items: [] })
  }))
  render(<App />)
  await screen.findByRole('heading', { name: 'Обзор панели' })
  const nav = screen.getByRole('navigation', { name: 'Главная навигация' })
  fireEvent.click(within(nav).getByRole('button', { name: 'Настройки и инструменты' }))
  expect(within(nav).queryByRole('button', { name: 'Администраторы' })).toBeNull()
  expect(Boolean(within(nav).queryByRole('button', { name: 'Журнал действий' }))).toBe(role === 'auditor')
  fireEvent.click(within(nav).getByRole('button', { name: 'Операции' }))
  await screen.findByRole('heading', { name: 'Операции' })
  expect(Boolean(screen.queryByRole('button', { name: 'Проверить систему' }))).toBe(role === 'infrastructure_operator')
  expect(Boolean(within(nav).queryByRole('button', { name: 'Пользователи' }))).toBe(role !== 'infrastructure_operator')
  if (role !== 'infrastructure_operator') {
    fireEvent.click(within(nav).getByRole('button', { name: 'Пользователи' }))
    await screen.findByRole('heading', { name: 'Пользователи', level: 1 })
    expect(Boolean(screen.queryByRole('button', { name: 'Добавить пользователя' }))).toBe(role === 'access_operator')
  }
})

it('performs explicit one-time setup then login without storing credentials', async () => {
  const calls: { url: string; options: RequestInit }[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, options) => {
    calls.push({ url, options })
    if (url.endsWith('/setup/status')) return json({ setup_required: true })
    if (url.endsWith('/setup')) return json({}, 201)
    if (url.endsWith('/auth/login')) return json(session())
    return json(overview)
  }))
  render(<App />)
  await screen.findByRole('heading', { name: 'Настройте вашу панель' })
  fireEvent.change(screen.getByLabelText('Одноразовый токен'), { target: { value: 'synthetic_token' } })
  fireEvent.change(screen.getByLabelText('Имя пользователя'), { target: { value: 'owner' } })
  fireEvent.change(screen.getByLabelText(/^Пароль/), { target: { value: 'Synthetic-B1-pass' } })
  fireEvent.click(screen.getByRole('button', { name: 'Создать владельца' }))
  await screen.findByRole('heading', { name: 'Вход в управление' })
  expect((screen.getByLabelText('Пароль') as HTMLInputElement).value).toBe('')
  expect(calls.some(c => c.url.endsWith('/auth/login'))).toBe(false)
  fireEvent.change(screen.getByLabelText('Имя пользователя'), { target: { value: 'owner' } })
  fireEvent.change(screen.getByLabelText('Пароль'), { target: { value: 'Synthetic-B1-pass' } })
  fireEvent.click(screen.getByRole('button', { name: 'Войти' }))
  await screen.findByRole('heading', { name: 'Обзор панели' })
  expect(localStorage.length).toBe(0)
})

it('uses quoted revision and leaves the row editable on a conflict', async () => {
  const admin = { id: 'a1', username: 'support1', role: 'support', disabled: false, revision: 7, created_at: '2026-10-13T12:00:00Z', updated_at: '2026-10-13T12:00:00Z' }
  const fetcher = vi.fn(async (_url, options) => options.method === 'PATCH' ? json({ error: { code: 'revision_conflict' } }, 412) : json({ items: [admin] }))
  vi.stubGlobal('fetch', fetcher)
  render(<Admins api={new ApiClient()} currentUser={session().user} />)
  await screen.findByText('support1')
  fireEvent.change(screen.getByRole('combobox', { name: 'Роль для support1' }), { target: { value: 'auditor' } })
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
  await screen.findByRole('alert')
  expect(fetcher.mock.calls.find(c => c[1].method === 'PATCH')?.[1].headers['If-Match']).toBe('"7"')
  expect(screen.getByText('support1')).toBeTruthy()
  await waitFor(() => expect((screen.getByRole('button', { name: 'Сохранить' }) as HTMLButtonElement).disabled).toBe(false))
})

it('clears the authenticated view and CSRF even when logout cannot be confirmed', async () => {
  const api = new ApiClient()
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url.endsWith('/setup/status')) return json({ setup_required: false })
    if (url.endsWith('/auth/session')) return json(session())
    if (url.endsWith('/auth/logout')) throw new TypeError('offline')
    return json(overview)
  }))
  render(<App client={api} />)
  await screen.findByRole('heading', { name: 'Обзор панели' })
  fireEvent.click(screen.getByRole('button', { name: 'Меню аккаунта' }))
  fireEvent.click(screen.getByRole('button', { name: 'Выйти' }))
  await screen.findByRole('heading', { name: 'Вход в управление' })
  expect(screen.queryByRole('heading', { name: 'Обзор панели' })).toBeNull()
  expect(screen.getByRole('alert').textContent).toMatch(/Выход на сервере не подтверждён/)
})

it('searches only permitted sections, clears search and closes mobile navigation on selection', async () => {
 vi.stubGlobal('fetch',vi.fn(async (url:string) => {
  if(url.endsWith('/setup/status'))return json({setup_required:false})
  if(url.endsWith('/auth/session'))return json(session('support'))
  if(url.endsWith('/overview'))return json(overview)
  return json({testers:[],generated_at_ms:Date.now()})
 }))
 render(<App />)
 await screen.findByRole('heading',{name:'Обзор панели'})
 fireEvent.click(screen.getByRole('button',{name:'Разделы панели'}))
 const search=screen.getByRole('textbox',{name:'Найти раздел'})
 fireEvent.change(search,{target:{value:'администраторы'}})
 expect(screen.getByText(/Раздел не найден/)).toBeTruthy()
 fireEvent.change(search,{target:{value:'логи'}})
 const nav=screen.getByRole('navigation',{name:'Главная навигация'})
 expect(within(nav).getAllByRole('button')).toHaveLength(1)
 fireEvent.click(within(nav).getByRole('button',{name:'Логи'}))
 await screen.findByRole('heading',{name:'Диагностика тестеров'})
 expect(window.location.pathname).toBe('/diagnostics')
 expect(screen.getByRole('button',{name:'Разделы панели'}).getAttribute('aria-expanded')).toBe('false')
 expect((search as HTMLInputElement).value).toBe('')
 fireEvent.change(search,{target:{value:'unknown'}})
 fireEvent.keyDown(window,{key:'Escape'})
 expect((search as HTMLInputElement).value).toBe('')
})
