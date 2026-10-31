import { ApiClient, ApiError } from './api'
import { AccessIntents } from './accessIntent'
import type { PendingAccessIntent } from './accessIntent'
import { userDetail } from './accessApi'
import type { UserDetail } from './accessApi'

type Flow = { key: CryptoKeyPair; publicKey: string; phase: 'challenge' | 'register'; busy: boolean }
const locks = new WeakMap<AccessIntents, Set<string>>()
const flows = new WeakMap<AccessIntents, Map<string, Flow>>()
const encode = (value: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(value))).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
function store(intents: AccessIntents) { let map = flows.get(intents); if (!map) { map = new Map(); flows.set(intents, map) } return map }
export function trialPending(intents: AccessIntents, id: string) { return intents.get(`trial/${id}`) }
export function trialBusy(intents: AccessIntents, id: string) { return locks.get(intents)?.has(id) || (store(intents).get(id)?.busy ?? false) }
// One proof key and one exact request survive component navigation in session
// memory. No key, config or credential is placed in local/session storage.
async function registerTrialUnlocked(api: ApiClient, intents: AccessIntents, detail: UserDetail) {
  const id = detail.user.id, scope = `trial/${id}`, map = store(intents)
  let flow = map.get(id)
  if (flow?.busy) throw new ApiError('conflict', 409)
  if (!flow) {
    const key = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair
    flow = { key, publicKey: encode(await crypto.subtle.exportKey('raw', key.publicKey)), phase: 'challenge', busy: false }
    map.set(id, flow)
  }
  flow.busy = true
  let request: PendingAccessIntent | undefined
  try {
    if (flow.phase === 'challenge') {
      request = intents.get(scope) ?? intents.begin(scope, { path: `/access/users/${id}/devices/challenges`, method: 'POST', revision: detail.user.revision, body: { public_key: flow.publicKey }, label: 'Подтвердить тестовое устройство' })
      const c = await api.request<{ id: string; user_id: string; public_key: string; signing_message: string; user_revision: number }>(request.path, { method: 'POST', body: request.body, headers: { 'Idempotency-Key': request.key, 'If-Match': `"${request.revision}"` } })
      if (!c || c.user_id !== id || c.public_key !== flow.publicKey || !/^[0-9a-f-]{36}$/.test(c.id) || typeof c.signing_message !== 'string' || !c.signing_message.startsWith(`salfetka-device-proof-v1\n${id}\n${c.id}\n${flow.publicKey}\n`) || !Number.isSafeInteger(c.user_revision) || c.user_revision !== request.revision! + 1) throw new ApiError('invalid_response')
      const signature = encode(await crypto.subtle.sign('Ed25519', flow.key.privateKey, new TextEncoder().encode(c.signing_message)))
      intents.finish(scope, request.key)
      request = intents.begin(scope, { path: `/access/users/${id}/devices/register`, method: 'POST', revision: c.user_revision, body: { challenge_id: c.id, name: 'Тестовый Xray', signature }, label: 'Зарегистрировать тестовое устройство' })
      flow.phase = 'register'
    } else request = intents.get(scope)
    if (!request) throw new ApiError('invalid_response')
    const result = userDetail(await api.request<UserDetail>(request.path, { method: 'POST', body: request.body, headers: { 'Idempotency-Key': request.key, 'If-Match': `"${request.revision}"` } }), id)
    intents.finish(scope, request.key); map.delete(id); return result
  } catch (e) {
    if (request) intents.failed(scope, request.key, e)
    if (!intents.get(scope)) map.delete(id)
    throw e
  } finally { flow.busy = false }
}

export async function registerTrial(api: ApiClient, intents: AccessIntents, detail: UserDetail) {
  let held = locks.get(intents); if (!held) { held = new Set(); locks.set(intents, held) }
  if (held.has(detail.user.id)) throw new ApiError('conflict', 409)
  held.add(detail.user.id)
  try { return await registerTrialUnlocked(api, intents, detail) } finally { held.delete(detail.user.id) }
}
