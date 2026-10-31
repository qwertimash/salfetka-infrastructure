import { useEffect, useRef, useState } from 'react'
import { ApiClient, ApiError } from './api'
import { AccessIntents } from './accessIntent'
import { Notice, formatDate } from './components'
import { personalURL } from './subscriptionSetModel'

export function DeviceInvite({ api, assignment, generation, intents, disabled }: { api: ApiClient; assignment: string; generation: number; intents: AccessIntents; disabled?: boolean }) {
 const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(), [value, setValue] = useState<{url: string; expires_at: string}>(), [copied, setCopied] = useState(false)
 const scope = `device-invite:${assignment}:${generation}`, alive = useRef(true)
 useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
 const create = async () => {
  if (busy) return
  const request = intents.get(scope) ?? intents.begin(scope, { path: '/subscription-sets/invite', method: 'POST', body: { assignment_id: assignment }, label: 'Приглашение устройства' })
  setBusy(true); setError(undefined); setCopied(false)
  try {
   const result = await api.request<{url: string; expires_at: string}>(request.path, { method: 'POST', body: request.body, headers: { 'Idempotency-Key': request.key } })
   personalURL(result, 'i')
   if (!Number.isFinite(Date.parse(result.expires_at))) throw new ApiError('invalid_response')
   intents.finish(scope, request.key); if (alive.current) setValue(result)
  } catch (e) { intents.failed(scope, request.key, e); if (alive.current) setError(e) }
  finally { if (alive.current) setBusy(false) }
 }
 return <div className="invite-card"><h4>Подключить телефон</h4><p className="field-hint">Приглашение действует 30 минут и регистрирует одно устройство с его собственным ключом. Передайте его лично тестеру. Сбор логов включается отдельно с его согласия.</p>{error != null && <Notice error={error} />}
 {!value && <button className="button secondary" disabled={disabled || busy} onClick={() => void create()}>{intents.get(scope) ? 'Повторить выдачу приглашения' : 'Создать приглашение для приложения'}</button>}
 {value && <div data-private><label>Приглашение для приложения<input readOnly value={value.url} onFocus={e => e.target.select()} /></label><p>Действует до {formatDate(value.expires_at)}. В приложении: «Подписки» → добавить ссылку. После подключения обновления используют постоянную ссылку набора.</p><div className="builder-actions"><button className="button secondary" onClick={() => void navigator.clipboard.writeText(value.url).then(() => setCopied(true)).catch(() => setError(new ApiError('clipboard_unavailable')))}>{copied ? 'Скопировано' : 'Копировать приглашение'}</button><button className="button secondary" onClick={() => setValue(undefined)}>Скрыть приглашение</button></div></div>}
 </div>
}
