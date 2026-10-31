import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { ApiClient, ApiError } from './api'
import { Constructor } from './constructor'
import { BuilderSession, emptyDocument, move, parseDocument, parseReleasePreview } from './constructorModel'
import services from './constructorServices.json'
const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status })
afterEach(() => vi.unstubAllGlobals())
it('cancel restores the saved document; a lost ACK retries exactly across navigation', async () => {
 const session = new BuilderSession(), api = new ApiClient(), writes: RequestInit[] = []; let fail = true
 vi.stubGlobal('fetch', vi.fn(async (url: string, options: RequestInit) => {
  if (url.endsWith('/builder/save')) { writes.push(options); if (fail) throw new TypeError('offline'); return json({ id, revision: 1, document: JSON.parse(options.body as string).document, updated_at: new Date().toISOString() }) }
  return json({ items: [], next_cursor: url.endsWith('/builder') ? '' : null })
 }))
 const props = { api, canEdit: true, canPublish: true, session }
 const first = render(<Constructor {...props} />)
 fireEvent.change(screen.getByLabelText('Название конфигурации'), { target: { value: 'Мой набор' } })
 fireEvent.click(screen.getByRole('button', { name: 'Сохранить черновик' }))
 await screen.findByText(/Результат сохранения неизвестен/)
 first.unmount(); fail = false
 render(<Constructor {...props} />)
 fireEvent.click(screen.getByRole('button', { name: 'Повторить сохранение черновика' }))
 await screen.findByText(/Черновик сохранён/)
 expect(writes).toHaveLength(2); expect(writes[0].body).toEqual(writes[1].body); expect(writes[0].headers).toEqual(writes[1].headers)
 fireEvent.change(screen.getByLabelText('Название конфигурации'), { target: { value: 'Не сохранять' } })
 fireEvent.click(screen.getByRole('button', { name: 'Отменить изменения' }))
 expect((screen.getByLabelText('Название конфигурации') as HTMLInputElement).value).toBe('Мой набор')
 expect(localStorage.length + sessionStorage.length).toBe(0)
})
it('a conflicting save keeps local edits and does not claim success', async () => {
 const session = new BuilderSession(); session.saved = { id, revision: 1, document: emptyDocument(), updated_at: new Date().toISOString() }; session.document = structuredClone(session.saved.document)
 vi.stubGlobal('fetch', vi.fn(async (url: string) => url.endsWith('/builder/save') ? json({ error: { code: 'builder_conflict' } }, 409) : json({ items: [], next_cursor: url.endsWith('/builder') ? '' : null })))
 render(<Constructor api={new ApiClient()} canEdit canPublish session={session} />)
 fireEvent.change(screen.getByLabelText('Название конфигурации'), { target: { value: 'Мои правки' } })
 fireEvent.click(screen.getByRole('button', { name: 'Сохранить черновик' }))
 await waitFor(() => expect(session.busy).toBe(false))
 expect((screen.getByLabelText('Название конфигурации') as HTMLInputElement).value).toBe('Мои правки')
 expect(session.saved.document.title).toBe('Новая конфигурация')
 expect(screen.queryByText(/Черновик сохранён/)).toBeNull()
})
it('rejects malformed expert policy shapes without losing the original model', () => {
 const doc = emptyDocument()
 expect(() => parseDocument(doc)).not.toThrow()
 const bad = structuredClone(doc); (bad.recipe.blueprint.network as any).value.dns_servers = 'bad'
 expect(() => parseDocument(bad)).toThrow(ApiError)
 expect(doc.recipe.blueprint.locations).toEqual([])
 expect(() => parseReleasePreview({} as never, id, id)).toThrow(ApiError)
})
it('reorders explicit membership and retains the pinned client service definitions', () => {
 expect(move(['a', 'b', 'c'], 1, -1)).toEqual(['b', 'a', 'c'])
 const registry = JSON.parse(readFileSync('../../mobile/core/routing/assets/registry-v1.json', 'utf8'))
 expect(services).toEqual({ revision: registry.revision, services: registry.services.map((s: any) => ({ id: s.id, title: s.title, matchers: s.matchers, coverage: s.coverage })) })
})

it('adds an owned bypass with ordered selection', async () => {
 const session = new BuilderSession(), api = new ApiClient()
 vi.spyOn(api,'request').mockImplementation(async (url: string) => {
  if (url.startsWith('/nodes?')) return {items:[{id,name:'Managed bypass',state:'active',revision:1,contact_state:'fresh',engine_state:'not_configured',serial:null,certificate_expires_at:null,last_seen_at:null,inventory:null,created_at:new Date().toISOString(),updated_at:new Date().toISOString()}],next_cursor:null} as never
  if(url.endsWith('/vpn')) return {node_id:id,installation:{node_id:id,installation_id:id,node_revision:1,group_id:id,enabled:true,endpoint:{backend:'olcrtc',host:'',port:0,server_name:'',provider:'jitsi',transport:'vp8channel',room:'https://room.example.invalid/test',bootstrap_dns:'1.1.1.1:53'}},state:'pending',desired_generation:0,observed:null,received_at:null,policy_expires_at:null} as never
  return {items:[],next_cursor:url.endsWith('/builder')?'':null} as never
 })
 render(<Constructor api={api} canEdit canPublish session={session} />)
 fireEvent.click(screen.getByRole('button',{name:'Подключения'}))
 await screen.findByRole('option',{name:'Managed bypass'})
 fireEvent.change(screen.getByLabelText('Добавить свой узел'),{target:{value:id}})
 await waitFor(()=>expect(session.document.recipe.blueprint.locations).toHaveLength(1))
 expect(session.document.recipe.blueprint.locations[0]).toMatchObject({mode:'bypass',selection:'first_working'})
})

it('loads an owned-only draft when the API omits its empty sources list', () => {
 const d=emptyDocument();delete (d.recipe as any).sources;delete (d.recipe.blueprint.routing as any).bypass
 expect(parseDocument(d).recipe.sources).toEqual([])
 expect(d.recipe.blueprint.routing.bypass).toEqual({authority:'personal'})
})

it('checks readiness without publishing and retries a lost check with the same intent', async () => {
 const user = '11111111-1111-4111-8111-111111111111', device = '22222222-2222-4222-8222-222222222222'
 const release = '44444444-4444-4444-8444-444444444444', now = new Date().toISOString()
 const session = new BuilderSession(); session.saved = { id, revision: 1, document: emptyDocument(), updated_at: now }; session.document = structuredClone(session.saved.document)
 const profile = { content_digest: 'a'.repeat(64), id: 'xray', engine: 'xray', mode: 'vpn', native: true, auto: false, source_dns: false }
 const detail = { subscription: { id, user_id: user, device_id: device, revision: 1, active_release: null as string | null, token_active: false, token_revision: 0 }, releases: [{ id: release, number: 1, state: 'partial', digest: 'a'.repeat(64), preview: { format: 'manifest', digest: 'a'.repeat(64), profiles: [profile], valid_until: new Date(Date.now() + 86400000).toISOString(), subscription_expires_at: null, publication_ready: false }, provenance: { external_credentials: false }, checks: [{ node_id: id, state: 'grant_pending' }], created_at: now }] }
 const decision = { allowed: true, reason: 'active', node_state: 'not_provisioned' }
 const u = { id: user, name: 'Тестер', revision: 1, policy_epoch: 1, state: 'active', created_at: now, updated_at: now }
 const writes: RequestInit[] = []; let loseCheck = true
 vi.stubGlobal('fetch', vi.fn(async (url: string, options: RequestInit) => {
  if (url.endsWith('/builder/stage')) return json(detail)
  if (url.endsWith('/subscriptions/mutate')) {
   writes.push(options); const body = JSON.parse(options.body as string)
   if (body.operation === 'check' && loseCheck) { loseCheck = false; throw new TypeError('lost ACK') }
   detail.subscription.revision++
   detail.releases[0].state = body.operation === 'publish' ? 'published' : 'healthy'
   detail.releases[0].checks[0].state = 'healthy'
   if (body.operation === 'publish') detail.subscription.active_release = release
   return json(detail)
  }
  if (url.includes('/subscriptions/')) return json({ error: { code: 'subscription_unavailable' } }, 404)
  if (url.endsWith('/builder/preview')) return json({ user_id: user, device_id: device, candidate: { version: 2, network: {}, routing: {}, locations: [], profiles: [profile], policy_digest: 'a'.repeat(64) }, current: null, node_ids: [id], access_changed: false, server_restart: false, checks: detail.releases[0].checks })
  if (url.includes('/access/users?')) return json({ items: [u], next_cursor: null })
  if (url.endsWith(`/access/users/${user}`)) return json({ user: u, entitlement: null, devices: [{ id: device, user_id: user, name: 'Телефон', state: 'registered', revision: 1, public_key: 'public', credential: null, decision }], blocks: [], decision, outbox_pending: 0 })
  return json({ items: [], next_cursor: url.endsWith('/builder') ? '' : null })
 }))
 render(<Constructor api={new ApiClient()} canEdit canPublish session={session} />)
 fireEvent.click(screen.getByRole('button', { name: 'Публикация' }))
 await screen.findByRole('option', { name: 'Тестер' }); fireEvent.change(screen.getByLabelText('Получатель'), { target: { value: user } })
 await screen.findByRole('option', { name: 'Телефон' }); fireEvent.change(screen.getByLabelText('Устройство получателя'), { target: { value: device } })
 fireEvent.click(screen.getByRole('button', { name: 'Подготовить и проверить версию' }))
 await screen.findByText(/Серверы ещё применяют ключ/)
 expect(screen.queryByText('Версия опубликована')).toBeNull()
 fireEvent.click(screen.getByRole('button', { name: 'Проверить узлы' }))
 fireEvent.click(await screen.findByRole('button', { name: 'Повторить операцию публикации' }))
 await screen.findByText(/Узлы готовы. Нажмите/)
 expect(writes).toHaveLength(2)
 expect(writes[0].body).toBe(writes[1].body); expect(writes[0].headers).toEqual(writes[1].headers)
 expect(JSON.parse(writes[1].body as string)).toMatchObject({ operation: 'check', release_id: release })
 expect(screen.queryByText('Версия опубликована')).toBeNull()
 fireEvent.click(screen.getByRole('button', { name: 'Опубликовать в персональную подписку' }))
 await screen.findByRole('heading', { name: 'Версия опубликована' })
 expect(writes).toHaveLength(3)
 expect(JSON.parse(writes[2].body as string).operation).toBe('publish')
})
