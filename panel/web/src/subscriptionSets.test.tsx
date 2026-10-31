import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { ApiClient, ApiError } from './api'
import { SubscriptionSets } from './subscriptionSets'
import { SetSession, personalURL, setPage } from './subscriptionSetModel'
import type { SetRecord } from './subscriptionSetModel'
import { emptyDocument } from './constructorModel'
const id = '11111111-1111-4111-8111-111111111111', user = '22222222-2222-4222-8222-222222222222', device = '33333333-3333-4333-8333-333333333333', aid = '44444444-4444-4444-8444-444444444444', pub = '55555555-5555-4555-8555-555555555555'
const now = new Date().toISOString()
const record = (): SetRecord => ({ id, revision: 2, document: { ...emptyDocument(), title: 'Основная' }, published_id: null, updated_at: now })
const published = () => ({ id: pub, set_id: id, revision: 2, current: true, created_at: now, expected_devices: 2, users_without_device: 1, published_devices: 1, pending_devices: 0, retry_devices: 1, cancelled_devices: 0 })
function fixture(edit = true, publish = true) {
 const api = new ApiClient(), session = new SetSession(); session.saved = record(); session.document = structuredClone(session.saved.document); session.selected = id
 const fetch = vi.spyOn(api, 'request').mockImplementation(async path => {
  if (path === '/subscription-sets') return { items: [{ id, revision: 2, title: 'Основная', updated_at: now }], next_cursor: '' } as never
  if (path.startsWith('/nodes?')) return { items: [], next_cursor: null } as never
  if (path === '/sources') return { items: [] } as never
  if (path === `/subscription-sets/${id}`) return session.saved as never
  if (path.startsWith('/subscription-sets/publications/')) return published() as never
  if (path.startsWith('/subscription-sets/targets')) return { items: [], next_cursor: '' } as never
  throw new Error(`Unexpected synthetic path: ${path}`)
 })
 const ui = () => <SubscriptionSets api={api} canEdit={edit} canPublish={publish} session={session} openServers={() => {}} openSources={() => {}} />
 return { api, session, fetch, ui }
}
it('saves a shared set without publishing or altering assigned access', async () => {
 const f = fixture(); const original = f.fetch.getMockImplementation()!
 f.fetch.mockImplementation(async (path, options) => path.endsWith('/save') ? { ...record(), revision: 3, document: (options!.body as any).document } as never : original(path, options))
 render(f.ui()); fireEvent.change(screen.getByLabelText('Название подписки'), { target: { value: 'Тестовая' } }); fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
 await screen.findByText(/Черновик сохранён/)
 expect(f.session.saved?.revision).toBe(3); expect(f.session.saved?.document.title).toBe('Тестовая')
 expect(f.fetch.mock.calls.filter(([, o]) => o?.method === 'POST').map(([p]) => p)).toEqual(['/subscription-sets/save'])
})
it('keeps edits on revision conflict, never claims save success', async () => {
 const f = fixture(); const original = f.fetch.getMockImplementation()!
 f.fetch.mockImplementation(async (p, o) => { if (p.endsWith('/save')) throw new ApiError('subscription_set_conflict', 409); return original(p, o) })
 render(f.ui()); fireEvent.change(screen.getByLabelText('Название подписки'), { target: { value: 'Правки' } }); fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
 await screen.findByRole('alert'); expect(f.session.document?.title).toBe('Правки'); expect(f.session.saved?.document.title).toBe('Основная'); expect(screen.queryByText(/Черновик сохранён/)).toBeNull()
})
it('lost save response retains the exact body and key across navigation', async () => {
 const f = fixture(); const original = f.fetch.getMockImplementation()!; const writes: any[] = []
 f.fetch.mockImplementation(async (p, o) => { if (p.endsWith('/save')) { writes.push(o); if (writes.length === 1) throw new ApiError('network_error'); return { ...record(), revision: 3, document: (o!.body as any).document } as never }; return original(p, o) })
 const view = render(f.ui()); fireEvent.change(screen.getByLabelText('Название подписки'), { target: { value: 'Не терять' } }); fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
 await screen.findByRole('button', { name: 'Повторить запрос' }); view.unmount(); render(f.ui())
 fireEvent.click(screen.getByRole('button', { name: 'Повторить запрос' })); await screen.findByText(/Черновик сохранён/)
 expect(writes[0].headers).toEqual(writes[1].headers); expect(writes[0].body).toEqual(writes[1].body)
})
it('publishes only after confirmation and shows partial delivery honestly', async () => {
 const f = fixture(); const original = f.fetch.getMockImplementation()!
 f.fetch.mockImplementation(async (p, o) => { if (p.endsWith('/publish')) { f.session.saved!.published_id = pub; return published() as never }; return original(p, o) })
 render(f.ui()); fireEvent.click(screen.getByRole('button', { name: 'Опубликовать' }))
 expect(f.fetch.mock.calls.some(([p]) => p.endsWith('/publish'))).toBe(false)
 fireEvent.click(screen.getByRole('button', { name: 'Подтвердить публикацию' })); await screen.findByText('повтор сборки', { exact: false })
 expect(f.fetch.mock.calls.find(([p]) => p.endsWith('/publish'))?.[1]?.body).toEqual({ id, revision: 2 })
 expect(screen.getByText(/Готовность конфига не подтверждает подключение телефона/)).toBeTruthy()
})
it('retains locations when switching sets with unsaved work; reorder persists in document', async () => {
 const f = fixture(); f.session.document!.recipe.blueprint.locations = ['A', 'B'].map(title => ({ id: title, title, mode: 'vpn', kind: 'location', selection: 'first_working', members: [] }))
 render(f.ui()); fireEvent.click(screen.getByRole('button', { name: 'Поднять B' })); expect(f.session.document!.recipe.blueprint.locations.map(l => l.title)).toEqual(['B', 'A'])
 fireEvent.click(await screen.findByRole('button', { name: /Основная.*Сохранённая версия/ })); await screen.findByText(/Сначала сохраните изменения/)
 expect(f.session.document!.recipe.blueprint.locations).toHaveLength(2)
})
it('editor modal returns focus and closes by Escape without publishing', async () => {
 const f = fixture(); render(f.ui()); fireEvent.click(screen.getByRole('button', { name: 'Добавить локацию' }))
 const dialog = screen.getByRole('dialog'); fireEvent.change(within(dialog).getByLabelText('Название локации'), { target: { value: 'Германия' } }); fireEvent.click(within(dialog).getByRole('button', { name: 'Значок 🇩🇪' })); fireEvent.keyDown(document, { key: 'Escape' })
 expect(screen.queryByRole('dialog')).toBeNull(); expect(f.session.document!.recipe.blueprint.locations[0]).toMatchObject({ title: 'Германия', icon: '🇩🇪' }); expect(f.fetch.mock.calls.some(([, o]) => o?.method === 'POST')).toBe(false)
})
it('infrastructure editor cannot publish or request personal links', () => {
 const f = fixture(true, false); render(f.ui()); expect(screen.queryByRole('button', { name: 'Опубликовать' })).toBeNull(); expect(screen.queryByRole('tab', { name: 'Пользователи' })).toBeNull()
})
it('access operator cannot edit or create sets but can publish saved revision', () => {
 const f = fixture(false, true); render(f.ui()); expect(screen.queryByRole('button', { name: 'Новая подписка' })).toBeNull(); expect((screen.getByLabelText('Название подписки') as HTMLInputElement).disabled).toBe(true); expect(screen.getByRole('button', { name: 'Опубликовать' })).toBeTruthy()
})
it('looks beyond first assignment page and resolves the correct device URL', async () => {
 const f = fixture(); const original = f.fetch.getMockImplementation()!
 const a = { id: aid, user_id: user, set_id: id, state: 'active', revision: 8, updated_at: now }
 f.fetch.mockImplementation(async (p, o) => {
  if (p.startsWith('/access/users?')) return { items: [{ id: user, name: 'Тестер', state: 'active', revision: 1 }], next_cursor: null } as never
  if (p.startsWith('/subscription-sets/assignments?')) return { items: p.includes('&after=') ? [a] : [], next_cursor: p.includes('&after=') ? '' : aid } as never
  if (p === `/access/users/${user}`) return { user: { id: user, name: 'Тестер', state: 'active', revision: 1 }, entitlement: null, decision: { allowed: true, reason: 'active', node_state: 'not_provisioned' }, blocks: [], outbox_pending: 0, devices: [{ id: device, name: 'iPhone', user_id: user, state: 'registered', revision: 1, decision: { allowed: true, reason: 'active', node_state: 'not_provisioned' }, credential: null }] } as never
  if (p.endsWith('/device-link')) return { url: 'https://subscription.example.invalid/s/synthetic_token' } as never
  return original(p, o)
 })
 render(f.ui()); fireEvent.click(screen.getByRole('tab', { name: 'Пользователи' })); await screen.findByRole('option', { name: 'Тестер' }); fireEvent.change(screen.getByLabelText('Пользователь'), { target: { value: user } }); await screen.findByText('Набор назначен')
 fireEvent.click(screen.getByRole('button', { name: 'Ссылка для iPhone' })); await screen.findByLabelText('Ссылка для текущего приложения')
 expect(f.fetch.mock.calls.find(([p]) => p.endsWith('/device-link'))?.[1]?.body).toEqual({ assignment_id: aid, device_id: device })
 expect(localStorage.length + sessionStorage.length).toBe(0)
})
it('accepts opaque target cursors and rejects unsafe personal URLs', () => {
 expect(setPage({ items: [], next_cursor: `${aid}:0000000000000008:${device}` }, () => {})).toBeTruthy()
 for (const url of ['javascript:alert(1)', 'http://example.invalid/a/token', 'https://example.invalid/a/token?secret=x', ['https://', 'name', ':', 'pass', '@example.invalid/s/token'].join('')]) expect(() => personalURL({ url }, 'a')).toThrow()
})
it('duplicates composition into an unsaved independent set and keeps JSON edits across navigation', () => {
 const f = fixture(); const view = render(f.ui()); fireEvent.click(screen.getByRole('button', { name: 'Дублировать' }))
 expect(f.session.saved).toBeUndefined(); expect(f.session.document?.title).toBe('Основная · копия')
 fireEvent.click(screen.getByRole('tab', { name: 'Конфиг' })); fireEvent.click(screen.getByRole('button', { name: 'Редактировать JSON' })); fireEvent.change(screen.getByLabelText('JSON подписки'), { target: { value: '{ unfinished' } }); view.unmount(); render(f.ui()); fireEvent.click(screen.getByRole('tab', { name: 'Конфиг' }))
 expect((screen.getByLabelText('JSON подписки') as HTMLTextAreaElement).value).toBe('{ unfinished'); expect(f.fetch.mock.calls.some(([, o]) => o?.method === 'POST')).toBe(false)
})

it.each(['no_eligible_device','user_blocked','entitlement_expired'])('invitation respects account admission before a first device: %s',async reason=>{
 const f=fixture(),original=f.fetch.getMockImplementation()!
 const a={id:aid,user_id:user,set_id:id,state:'active',revision:1,updated_at:now}
 f.fetch.mockImplementation(async(p,o)=>{
  if(p.startsWith('/access/users?'))return {items:[{id:user,name:'Первый телефон',state:'active',revision:1}],next_cursor:null} as never
  if(p.startsWith('/subscription-sets/assignments?'))return {items:[a],next_cursor:''} as never
  if(p===`/access/users/${user}`)return {user:{id:user,name:'Первый телефон',state:'active',revision:1},entitlement:null,decision:{allowed:false,reason,node_state:'not_provisioned'},blocks:[],outbox_pending:0,devices:[]} as never
  return original(p,o)
 })
 render(f.ui());fireEvent.click(screen.getByRole('tab',{name:'Пользователи'}));await screen.findByRole('option',{name:'Первый телефон'});fireEvent.change(screen.getByLabelText('Пользователь'),{target:{value:user}})
 const button=await screen.findByRole('button',{name:'Создать приглашение для приложения'})
 await waitFor(()=>expect((button as HTMLButtonElement).disabled).toBe(reason!=='no_eligible_device'))
 expect(f.fetch.mock.calls.some(([,o])=>o?.method==='POST')).toBe(false)
})

const catalogNode = (id: string, state = 'pending') => ({id,name:`Подключение ${id}`,state,revision:1,serial:null,certificate_expires_at:null,last_seen_at:null,inventory:null,contact_state:'unknown',engine_state:'not_configured',created_at:now,updated_at:now})
it('loads beyond 100 newer nodes and deduplicates page overlaps before offering connections',async()=>{
 const f=fixture(),original=f.fetch.getMockImplementation()!
 const first=Array.from({length:100},(_,i)=>catalogNode(`00000000-0000-4000-8000-${String(i).padStart(12,'0')}`)),old=catalogNode(device,'active')
 f.fetch.mockImplementation(async(p,o)=>{
  if(p===`/nodes/${device}/vpn`)return {node_id:device,installation:{node_id:device,installation_id:id,group_id:aid,node_revision:1,enabled:true,endpoint:{host:'vpn.example.com',port:443,server_name:'target.example.com'}},desired_generation:1,policy_expires_at:null,state:'pending',received_at:null,observed:null} as never
  return p.startsWith('/nodes?')?{items:p.includes('&cursor=')?[first[99],old]:first,next_cursor:p.includes('&cursor=')?'':first[99].id} as never:original(p,o)
 })
 render(f.ui());await screen.findByRole('option',{name:old.name})
 expect(f.fetch.mock.calls.filter(([p])=>p.startsWith('/nodes?')).map(([p])=>p)).toEqual(['/nodes?limit=100',`/nodes?limit=100&cursor=${first[99].id}`])
 expect(within(screen.getByLabelText('Подключение сервера')).getAllByRole('option')).toHaveLength(2)
 fireEvent.change(screen.getByLabelText('Подключение сервера'),{target:{value:device}})
 await waitFor(()=>expect(f.session.document?.recipe.node_ids).toEqual([device]))
 expect(f.session.document?.recipe.blueprint.locations[0].members).toEqual([{node_id:device}])
 expect(screen.queryByRole('alert')).toBeNull()
})
it.each(['failure','cycle'])('does not present an incomplete catalogue on pagination %s',async mode=>{
 const f=fixture(),original=f.fetch.getMockImplementation()!,entry=catalogNode(device,'active')
 f.fetch.mockImplementation(async(p,o)=>{
  if(!p.startsWith('/nodes?'))return original(p,o)
  if(p.includes('&cursor=')&&mode==='failure')throw new ApiError('network_error')
  return {items:[entry],next_cursor:device} as never
 })
 render(f.ui());await screen.findByRole('alert')
 expect(screen.queryByRole('option',{name:entry.name})).toBeNull()
 expect(f.fetch.mock.calls.filter(([p])=>p.startsWith('/nodes?'))).toHaveLength(2)
})
