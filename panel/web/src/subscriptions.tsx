import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiClient, ApiError } from './api'
import type { Page } from './api'
import { AccessIntents } from './accessIntent'
import { accessUsers, userDetail } from './accessApi'
import type { AccessUser, UserDetail } from './accessApi'
import { source, preview } from './sources'
import type { Source, Preview } from './sources'
import { nodesPage } from './nodeApi'
import type { Node } from './nodeApi'
import { Empty, Freshness, Notice, PageHeading, formatDate } from './components'
import { useResource } from './useResource'
export class SubscriptionIntents extends AccessIntents { busy = new Set<string>() }
export function subscriptionLink(value: unknown): string {
  if (typeof value !== 'string') throw new ApiError('invalid_response')
  let u: URL
  try { u = new URL(value) } catch { throw new ApiError('invalid_response') }
  // The authenticated API may return a separately hosted delivery endpoint.
  if (u.protocol !== 'https:' || u.username || u.password || u.href !== value || !/^\/s\/[A-Za-z0-9_-]{43}$/.test(u.pathname) || value.includes('?') || value.includes('#')) throw new ApiError('invalid_response')
  return value
}
type Release = { id: string; number: number; state: 'staged' | 'partial' | 'healthy' | 'published'; digest: string; preview: Preview; provenance: { external_credentials: boolean }; checks: { node_id: string; state: string }[]; created_at: string }
export type SubscriptionDetail = { subscription: { id: string; user_id: string; device_id: string; revision: number; active_release: string | null; token_active: boolean; token_revision: number }; releases: Release[] }
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/
export function subscriptionDetail(v: SubscriptionDetail, user: string, device: string) {
  const s = v?.subscription
  if (!s || !uuid.test(s.id) || s.user_id !== user || s.device_id !== device || !Number.isSafeInteger(s.revision) || s.revision < 1 || typeof s.token_active !== 'boolean' || !Number.isSafeInteger(s.token_revision) || s.token_revision < 0 || s.active_release !== null && !uuid.test(s.active_release) || !Array.isArray(v.releases) || v.releases.length > 100) throw new ApiError('invalid_response')
  const seen = new Set<string>()
  for (const r of v.releases) {
    if (!r || !uuid.test(r.id) || seen.has(r.id) || !Number.isSafeInteger(r.number) || r.number < 1 || !['staged', 'partial', 'healthy', 'published'].includes(r.state) || !/^[a-f0-9]{64}$/.test(r.digest) || !Number.isFinite(Date.parse(r.created_at)) || !r.provenance || typeof r.provenance.external_credentials !== 'boolean' || !Array.isArray(r.checks) || r.checks.some(c => !c || !uuid.test(c.node_id) || typeof c.state !== 'string')) throw new ApiError('invalid_response')
    preview(r.preview); seen.add(r.id)
  }
  if (s.active_release && !v.releases.some(r => r.id === s.active_release && r.state === 'published')) throw new ApiError('invalid_response')
  return v
}
const states = { staged: 'Подготовлена', partial: 'Не все узлы готовы', healthy: 'Узлы готовы', published: 'Опубликована' }
export function publicationReadiness(detail: SubscriptionDetail, release: Release): string {
  if (detail.subscription.active_release === release.id) return 'Эта версия опубликована и выдаётся устройству.'
  const current = detail.subscription.active_release ? 'Прежняя версия продолжает выдаваться.' : 'Первая версия ещё не опубликована: ссылка пока не готова к выдаче.'
  if (release.state === 'healthy') return `Узлы готовы. Нажмите «Опубликовать», чтобы выдать эту версию. ${current}`
  const waiting = release.checks.filter(c => c.state !== 'healthy')
  const reason = waiting.length > 0 && waiting.every(c => c.state === 'grant_pending')
    ? 'Серверы ещё применяют ключ устройства. Это может занять несколько секунд.'
    : 'Не все серверы подтвердили готовность подключения.'
  return `${reason} ${current} Нажмите «Проверить узлы», затем опубликуйте готовую версию.`
}
export function Subscriptions({ api, canWrite, intents }: { api: ApiClient; canWrite: boolean; intents: SubscriptionIntents }) {
  const [selected, setSelected] = useState('')
  const [cursor, setCursor] = useState('')
  const users = useResource(useCallback(async (signal: AbortSignal) => accessUsers(await api.request<Page<AccessUser>>(`/access/users?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, { signal })), [api, cursor]))
  return <><PageHeading eyebrow="ЛИЧНЫЙ ДОСТУП" title="Подписки">Одна ссылка для устройства. Состав можно обновить после проверки, сохранив действующие соединения.</PageHeading>
    <div className="access-layout"><aside className="card user-directory" aria-label="Получатели подписок"><div className="directory-heading"><h2>Пользователи</h2><Freshness resource={users} /></div>{users.error != null && <Notice error={users.error} />}
      <div className="user-list">{users.data?.items.map(u => <button className={`user-choice ${u.id === selected ? 'selected' : ''}`} key={u.id} onClick={() => setSelected(u.id)}><strong>{u.name}</strong></button>)}</div>
      {cursor && <button className="button secondary" onClick={() => setCursor('')}>В начало списка</button>}{users.data?.next_cursor && <button className="button secondary" onClick={() => setCursor(users.data!.next_cursor!)}>Следующие пользователи</button>}
    </aside><section className="user-workspace">{selected ? <Recipient key={selected} api={api} user={selected} canWrite={canWrite} intents={intents} /> : <div className="card"><Empty icon="layers" title="Выберите пользователя">Подписка привязывается к его зарегистрированному устройству.</Empty></div>}</section></div></>
}
function Recipient({ api, user, canWrite, intents }: { api: ApiClient; user: string; canWrite: boolean; intents: SubscriptionIntents }) {
  const [device, setDevice] = useState('')
  const data = useResource(useCallback(async (signal: AbortSignal) => userDetail(await api.request<UserDetail>(`/access/users/${user}`, { signal }), user), [api, user]), 10000)
  return <>{data.error != null && <Notice error={data.error} />}<section className="card form-card"><h2>{data.data?.user.name ?? 'Получатель'}</h2><label>Устройство<select value={device} onChange={e => setDevice(e.target.value)}><option value="">Выберите устройство</option>{data.data?.devices.map(d => <option key={d.id} value={d.id}>{d.name}{d.decision.allowed ? '' : ' · доступ закрыт'}</option>)}</select></label>{data.data?.devices.length === 0 && <p>Сначала зарегистрируйте устройство в разделе пользователей.</p>}</section>{device && <DeviceSubscription key={device} api={api} user={user} device={device} canWrite={canWrite} intents={intents} />}</>
}
function DeviceSubscription({ api, user, device, canWrite, intents }: { api: ApiClient; user: string; device: string; canWrite: boolean; intents: SubscriptionIntents }) {
  const [sourceID, setSourceID] = useState(''); const [extraSources, setExtraSources] = useState<string[]>([]); const [nodeIDs, setNodeIDs] = useState<string[]>([]); const [external, setExternal] = useState(false)
  const [dns, setDNS] = useState('1.1.1.1, 8.8.8.8'); const [probeURL, setProbeURL] = useState(''); const [probeIP, setProbeIP] = useState(''); const [probeStatus, setProbeStatus] = useState('204'); const [probeHash, setProbeHash] = useState(''); const [error, setError] = useState<unknown>(); const [link, setLink] = useState(''); const [copied, setCopied] = useState(false)
  const [, redraw] = useState(0); const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const scope = `subscription:${device}`
  const resource = useResource(useCallback(async (signal: AbortSignal) => {
    try { return subscriptionDetail(await api.request<SubscriptionDetail>(`/subscriptions/${user}/${device}`, { signal }), user, device) }
    catch (e) { if (e instanceof ApiError && e.code === 'subscription_unavailable') return null; throw e }
  }, [api, user, device]), 10000)
  const choices = useResource(useCallback(async (signal: AbortSignal) => {
    const [sources, nodes] = await Promise.all([api.request<{ items: Source[] }>('/sources', { signal }), api.request<Page<Node>>('/nodes?limit=100', { signal })])
    if (!sources || !Array.isArray(sources.items)) throw new ApiError('invalid_response')
    return { sources: sources.items.map(source), nodes: nodesPage(nodes) }
  }, [api]))
  useEffect(() => { setLink(''); setCopied(false) }, [resource.data?.subscription.token_revision])
  const d = resource.data; const pending = intents.get(scope); const busy = intents.busy.has(scope)
  const locked = busy || !!pending || resource.loading || resource.data === undefined
  const submit = async (operation?: string, releaseID = '') => {
    if (!canWrite || intents.busy.has(scope)) return
    let intent = intents.get(scope)
    if (!intent && operation) {
      let recipe: unknown
      if (operation === 'stage') {
        const selected = choices.data?.sources.find(s => s.id === sourceID)
        if (sourceID && !selected) { setError(new ApiError('release_conflict')); return }
        let explicitNetwork: unknown
        if (!selected) { explicitNetwork = { dns_servers: dns.split(',').map(s => s.trim()).filter(Boolean), probe: { url: probeURL.trim(), ipv4: probeIP.trim(), expected_status: Number(probeStatus), body_sha256: probeHash.trim() } } }
        const others = extraSources.map(id => choices.data?.sources.find(s => s.id === id))
        if (others.some(s => !s) || extraSources.length > 0 && !selected) { setError(new ApiError('release_conflict')); return }
        const imports = selected && others.length ? { source_id: '', version_id: '', sources: [selected, ...others].map(s => ({ id: s!.id, version_id: s!.current.id })) } : { source_id: selected?.id ?? '', version_id: selected?.current.id ?? '' }
        recipe = { ...imports, external_credentials: external && !!selected, node_ids: nodeIDs, max_version: 2, engines: ['xray', 'olcrtc', 'openflux'], ...(explicitNetwork ? { network: explicitNetwork } : {}) }
      }
      intent = intents.begin(scope, { path: '/subscriptions/mutate', method: 'POST', label: operation, body: { operation, user_id: user, device_id: device, revision: d?.subscription.revision ?? 0, token_revision: d?.subscription.token_revision ?? 0, release_id: releaseID, ...(recipe ? { recipe } : {}) } })
    }
    if (!intent) return
    intents.busy.add(scope); setError(undefined); setLink(''); redraw(n => n + 1)
    try { subscriptionDetail(await api.request<SubscriptionDetail>(intent.path, { method: intent.method, body: intent.body, headers: { 'Idempotency-Key': intent.key } }), user, device); intents.finish(scope, intent.key); if (alive.current) resource.refresh() }
    catch (e) { intents.failed(scope, intent.key, e); if (alive.current) setError(e) }
    finally { intents.busy.delete(scope); if (alive.current) redraw(n => n + 1) }
  }
  return <>{resource.error != null && <Notice error={resource.error} />}{choices.error != null && <Notice error={choices.error} />}{error != null && <Notice error={error} />}{pending && <Notice kind="info">Результат изменения пока неизвестен. Повтор сохранит исходное действие.<button className="button secondary" disabled={busy} onClick={() => void submit()}>Повторить изменение</button></Notice>}
    <section className="card form-card"><div className="directory-heading"><h2>Личная ссылка</h2><Freshness resource={resource} /></div><p>{d?.subscription.active_release ? 'Выдаётся опубликованная версия. Новые сборки не меняют ссылку.' : 'Сначала подготовьте и опубликуйте первую версию.'}</p>
      {canWrite && d && <div className="form-actions subscription-actions"><button className="button secondary" disabled={locked || !d.subscription.active_release || !d.subscription.token_active} onClick={async () => { setError(undefined); try { const v = await api.request<{ url: string }>('/subscriptions/link', { method: 'POST', body: { user_id: user, device_id: device } }); const url = subscriptionLink(v.url); if (alive.current) { setLink(url); setCopied(false) } } catch (e) { if (alive.current) setError(e) } }}>Показать ссылку</button><button className="button secondary" disabled={locked || !d.subscription.active_release} onClick={() => void submit('rotate')}>{d.subscription.token_active ? 'Заменить ссылку' : 'Создать ссылку'}</button><button className="button secondary" disabled={locked || !d.subscription.token_active} onClick={() => void submit('revoke')}>Отозвать ссылку</button></div>}
      {link && <div><label>Ссылка для устройства<input value={link} readOnly autoComplete="off" /></label><button className="button secondary" onClick={async () => { try { await navigator.clipboard.writeText(link); setCopied(true) } catch { setError(new ApiError('internal_error')) } }}>{copied ? 'Скопировано' : 'Копировать'}</button><button className="button link" onClick={() => setLink('')}>Скрыть</button></div>}
      <p className="field-hint">Замена ссылки закрывает старый адрес. Для отключения уже выданного VPN используйте отзыв устройства или блокировку пользователя.</p>
    </section>
    {canWrite && <section className="card form-card"><h2>Новая версия</h2><label>Принятый источник<select value={sourceID} disabled={locked} onChange={e => { setSourceID(e.target.value); setExtraSources([]); setExternal(false) }}><option value="">Только свои узлы</option>{choices.data?.sources.map(s => <option key={s.id} value={s.id} disabled={!['manifest', 'catalog'].includes(s.current.preview.format)}>{s.name}{['manifest', 'catalog'].includes(s.current.preview.format) ? '' : ' · нужна настройка в конструкторе'}</option>)}</select></label>
      {sourceID ? <label className="checkbox-label"><input type="checkbox" checked={external} disabled={locked} onChange={e => setExternal(e.target.checked)} />Выдать настройки внешнего источника. Его серверы и уже скачанные ключи управляются отдельно.</label> : <details><summary>Сетевые настройки подписки</summary><p>Проверка соединения должна отвечать по HTTPS с известным содержимым.</p><div className="subscription-network"><label>DNS-серверы через запятую<input value={dns} onChange={e => setDNS(e.target.value)} disabled={locked} /></label><label>Адрес проверки HTTPS<input type="url" value={probeURL} onChange={e => setProbeURL(e.target.value)} disabled={locked} /></label><label>IPv4 проверки<input value={probeIP} onChange={e => setProbeIP(e.target.value)} disabled={locked} /></label><label>Код успешного ответа<input type="number" min={200} max={299} value={probeStatus} onChange={e => setProbeStatus(e.target.value)} disabled={locked} /></label><label>SHA-256 содержимого ответа<input value={probeHash} onChange={e => setProbeHash(e.target.value)} disabled={locked} spellCheck={false} /></label></div></details>}
      {sourceID && <details><summary>Добавить другие источники</summary><p className="field-hint">Совместимые источники собираются целиком. Разные сетевые правила требуют явной настройки в конструкторе.</p>{choices.data?.sources.filter(s => s.id !== sourceID && ['manifest', 'catalog'].includes(s.current.preview.format)).map(s => <label className="checkbox-label" key={s.id}><input type="checkbox" disabled={locked} checked={extraSources.includes(s.id)} onChange={e => { setExternal(false); setExtraSources(ids => e.target.checked ? [...ids, s.id] : ids.filter(id => id !== s.id)) }} />{s.name}</label>)}</details>}
      <fieldset disabled={locked}><legend>Свои узлы</legend>{choices.data?.nodes.items.map(n => <label className="checkbox-label" key={n.id}><input type="checkbox" checked={nodeIDs.includes(n.id)} onChange={e => setNodeIDs(ids => e.target.checked ? [...ids, n.id] : ids.filter(id => id !== n.id))} />{n.name}</label>)}</fieldset>
      {choices.data?.nodes.next_cursor && <Notice kind="info">Показаны первые 100 узлов. Другие узлы доступны через API сборки.</Notice>}
      <button className="button primary" disabled={locked || !!sourceID && !external || !sourceID && nodeIDs.length === 0} onClick={() => void submit('stage')}>Подготовить версию</button><p className="field-hint">Сначала будет создана отдельная версия. Публикация доступна следующим действием.</p>
    </section>}
    <section className="card form-card"><h2>Версии подписки</h2>{d?.releases.map((r, index) => <article className="release-card" key={r.id}><div className="directory-heading"><h3>Версия {r.number}</h3><span>{d.subscription.active_release === r.id ? 'Выдаётся сейчас' : states[r.state]}</span></div><p>{formatDate(r.created_at)} · {r.preview.profiles.length} подключений</p><p>{r.preview.profiles.filter(p => p.mode === 'vpn').length} VPN · {r.preview.profiles.filter(p => p.mode === 'bypass').length} обходов{r.preview.profiles.some(p => p.auto) ? ' · Auto источника' : ''}</p>
      {r.provenance.external_credentials && <p className="field-hint">Есть внешний источник: готовность его серверов панель не подтверждает.</p>}
      {r.checks.map(c => <p key={c.node_id}>{choices.data?.nodes.items.find(n => n.id === c.node_id)?.name ?? 'Узел'}: {c.state === 'healthy' ? 'подтверждён' : c.state === 'grant_pending' ? 'ожидает ключ устройства' : 'не готов к выдаче'}</p>)}
      {(r.state === 'partial' || r.state === 'healthy') && <Notice kind="info">{publicationReadiness(d, r)}</Notice>}
      {canWrite && <div className="form-actions subscription-actions">{index === 0 && r.state !== 'published' && <><button className="button secondary" disabled={locked} onClick={() => void submit('check', r.id)}>Проверить узлы</button><button className="button primary" disabled={locked} onClick={() => void submit('publish', r.id)}>Опубликовать версию {r.number}</button></>}{r.state === 'published' && d.subscription.active_release !== r.id && <button className="button secondary" disabled={locked} onClick={() => void submit('rollback', r.id)}>Подготовить откат к версии {r.number}</button>}</div>}
    </article>)}{d?.releases.length === 0 || d === null ? <p>Опубликованных настроек пока нет.</p> : null}</section>
  </>
}
