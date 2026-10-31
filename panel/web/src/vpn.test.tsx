import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { webcrypto } from 'node:crypto'
import { ApiClient, ApiError } from './api'
import { NodeVPN } from './vpn'
import { NodeIntents } from './nodeIntent'
import { AccessIntents } from './accessIntent'
import { bytes, vpnFresh, vpnStatus } from './vpnApi'
import type { VPNStatus } from './vpnApi'
import type { Node } from './nodeApi'
import type { UserDetail } from './accessApi'
import { registerTrial, trialPending } from './trialDevice'
const id = '11111111-1111-4111-8111-111111111111', installation = '22222222-2222-4222-8222-222222222222', grant = '33333333-3333-4333-8333-333333333333'
const node = { id, name: 'VPN fixture', state: 'active', revision: 1 } as Node
function state(): VPNStatus {
  return { node_id: id, installation: { node_id: id, installation_id: installation, node_revision: 1, group_id: grant, enabled: true, endpoint: { host: 'vpn.invalid', port: 14443, server_name: 'vpn.invalid' } }, desired_generation: 1, policy_expires_at: new Date(Date.now() + 120000).toISOString(), state: 'applied', received_at: new Date().toISOString(), observed: { engine_epoch: 'a'.repeat(32), sequence: 1, observed_at: new Date().toISOString(), usage: [{ grant_id: grant, generation: 1, instance_epoch: 'a'.repeat(32), active: true, uplink: 500, downlink: null }], receipt: { generation: 1, completed_at: new Date().toISOString(), status: 'applied' } } }
}
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals() })
it('rejects mixed epochs and never converts missing or stale traffic into zero/live', () => {
  const v = state(); expect(vpnStatus(v, id)).toBe(v); expect(bytes(null)).toBe('Нет данных')
  expect(vpnFresh(v, Date.now())).toBe(true); expect(vpnFresh(v, Date.now() + 26000)).toBe(false); expect(vpnFresh(v, Date.now() - 60000)).toBe(false)
  expect(vpnFresh(v, Date.now(), new Error())).toBe(false)
  v.observed!.usage[0].instance_epoch = 'b'.repeat(32)
  expect(() => vpnStatus(v, id)).toThrow(ApiError)
})
it('retains observed values and visible error after failed VPN refresh', async () => {
  const api = new ApiClient(); let fail = false
  vi.spyOn(api, 'request').mockImplementation(async () => { if (fail) throw new ApiError('network_error'); return state() as never })
  render(<NodeVPN api={api} node={node} canWrite intents={new NodeIntents()} now={Date.now()} changed={() => {}} />)
  await screen.findByText('500 Б'); expect(screen.getByText('Применено движком')).toBeTruthy()
  fail = true; fireEvent.click(screen.getByRole('button', { name: 'Обновить состояние VPN' }))
  await screen.findByRole('alert'); expect(screen.getByText('500 Б')).toBeTruthy(); expect(screen.getByText('Нет свежего подтверждения')).toBeTruthy()
  expect((screen.getByRole('button', { name: 'Настроить VPN' }) as HTMLButtonElement).disabled).toBe(true)
})
it('keeps exact VPN config intent after lost response and route remount', async () => {
  const api = new ApiClient(), intents = new NodeIntents(); const writes: unknown[] = []; let fail = true
  vi.spyOn(api, 'request').mockImplementation(async (_path, options) => {
    if (options?.method === 'POST') { writes.push(options); if (fail) throw new ApiError('network_error'); return { ...state().installation!, node_revision: 2 } as never }
    return state() as never
  })
  const view = render(<NodeVPN api={api} node={node} canWrite intents={intents} now={Date.now()} changed={() => {}} />)
  await screen.findByText('500 Б'); fireEvent.click(screen.getByRole('button', { name: 'Настроить VPN' }))
  fireEvent.change(screen.getByLabelText('Порт TLS'), { target: { value: '24443' } })
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить настройку VPN' })); await screen.findByRole('alert')
  view.unmount(); fail = false
  render(<NodeVPN api={api} node={{ ...node, revision: 3 }} canWrite intents={intents} now={Date.now()} changed={() => {}} />)
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Повторить настройку VPN' })) })
  expect(writes).toHaveLength(2); expect(writes[1]).toEqual(writes[0]); expect(intents.get(`${id}/vpn`)).toBeUndefined()
})
it('retries a lost trial registration with the same proof and one device request', async () => {
  vi.stubGlobal('crypto', webcrypto)
  const api = new ApiClient(), intents = new AccessIntents(), writes: unknown[] = []; let attempts = 0
  const detail = { user: { id, name: 'Test', state: 'active', revision: 1, policy_epoch: 1, created_at: new Date().toISOString(), updated_at: new Date().toISOString() }, entitlement: null, devices: [], blocks: [], decision: { allowed: true, reason: 'eligible', node_state: 'not_provisioned' }, outbox_pending: 1 } as UserDetail
  vi.spyOn(api, 'request').mockImplementation(async (path, options) => {
    if (path.endsWith('/challenges')) {
      const key = (options!.body as { public_key: string }).public_key
      return { id: grant, user_id: id, public_key: key, user_revision: 2, signing_message: `salfetka-device-proof-v1\n${id}\n${grant}\n${key}\nsynthetic` } as never
    }
    writes.push(options); attempts++; if (attempts === 1) throw new ApiError('network_error')
    return { ...detail, user: { ...detail.user, revision: 3 } } as never
  })
  await expect(registerTrial(api, intents, detail)).rejects.toThrow(ApiError)
  expect(trialPending(intents, id)?.unknown).toBe(true)
  await registerTrial(api, intents, { ...detail, user: { ...detail.user, revision: 5 } })
  expect(writes).toHaveLength(2); expect(writes[0]).toEqual(writes[1]); expect(trialPending(intents, id)).toBeUndefined()
})

it('keeps typed backend profiles and rejects unknown backends in read-back', () => {
 const hy = state(); hy.installation!.endpoint!.backend = 'hysteria2'
 expect(vpnStatus(hy, id).installation!.endpoint!.backend).toBe('hysteria2')
 const olc = state(); olc.installation!.endpoint = { backend:'olcrtc', host:'',port:0,server_name:'',provider:'jitsi',transport:'vp8channel',room:'https://room.example.invalid/test',bootstrap_dns:'1.1.1.1:53' }
 expect(vpnStatus(olc,id).installation!.endpoint!.backend).toBe('olcrtc')
 ;(olc.installation!.endpoint! as any).backend = 'unknown'
 expect(()=>vpnStatus(olc,id)).toThrow(ApiError)
})

it('preserves personal rooms and account admission when saving a node setting', async () => {
  const v = state()
  v.installation!.endpoint = { backend: 'olcrtc', host: '', port: 0, server_name: '', provider: 'jitsi', transport: 'vp8channel', room: 'https://room.example.invalid/base', bootstrap_dns: '1.1.1.1:53', account_session: true, personal_rooms: true }
  v.observed!.usage[0].ready = false
  const api = new ApiClient(), writes: unknown[] = []
  vi.spyOn(api, 'request').mockImplementation(async (_path, options) => {
    if (options?.method === 'POST') {
      writes.push(options.body)
      return { ...v.installation!, enabled: false, node_revision: 2 } as never
    }
    return v as never
  })
  render(<NodeVPN api={api} node={node} canWrite intents={new NodeIntents()} now={Date.now()} changed={() => {}} />)
  await screen.findByText(/ожидает подключения комнаты/)
  fireEvent.click(screen.getByRole('button', { name: 'Настроить VPN' }))
  expect(screen.getByText(/Персональная комната на аккаунт/)).toBeTruthy()
  fireEvent.change(screen.getByLabelText('Режим'), { target: { value: 'false' } })
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить настройку VPN' }))
  await waitFor(() => expect(writes).toHaveLength(1))
  expect(writes[0]).toEqual({ installation_id: installation, group_id: grant, enabled: false, endpoint: v.installation!.endpoint })
})

it('rejects malformed room capabilities and readiness instead of displaying them as ready', () => {
  const v = state()
  v.installation!.endpoint!.personal_rooms = true
  expect(() => vpnStatus(v, id)).toThrow(ApiError)
  v.installation!.endpoint = { backend: 'olcrtc', host: '', port: 0, server_name: '', provider: 'jitsi', transport: 'vp8channel', room: 'https://room.example.invalid/base', bootstrap_dns: '1.1.1.1:53', personal_rooms: true }
  expect(() => vpnStatus(v, id)).toThrow(ApiError)
  v.installation!.endpoint.account_session = true
  expect(vpnStatus(v, id)).toBe(v)
  ;(v.observed!.usage[0] as unknown as { ready: unknown }).ready = 'false'
  expect(() => vpnStatus(v, id)).toThrow(ApiError)
})


it.each([1, 443, 1023, 65535])('accepts supported TLS port %s from managed connections', port => {
  const v = state(); v.installation!.endpoint!.port = port
  expect(vpnStatus(v, id)).toBe(v)
})
it.each([0, -1, 65536, 443.5])('rejects invalid TLS port %s in VPN responses', port => {
  const v = state(); v.installation!.endpoint!.port = port
  expect(() => vpnStatus(v, id)).toThrow(ApiError)
})
