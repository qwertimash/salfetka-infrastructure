import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiClient, ApiError } from './api'
import { AccessIntents } from './accessIntent'
import { Empty, formatDate, Freshness, Icon, Notice, PageHeading } from './components'
import { useResource } from './useResource'

type Profile = { content_digest?: string; id: string; engine: 'xray' | 'olcrtc' | 'openflux'; mode: 'vpn' | 'bypass'; native: boolean; auto: boolean; source_dns: boolean }
export type Preview = { format: string; digest: string; profiles: Profile[]; valid_until: string | null; subscription_expires_at: string | null; publication_ready: false }
type Version = { id: string; preview: Preview; created_at: string }
export type Source = { id: string; name: string; kind: 'upload' | 'url'; revision: number; paused: boolean; error_code: string | null; next_fetch_at: string | null; current: Version; candidate: Version | null; updated_at: string }
type Draft = { id: string; preview: Preview; expires_at: string }
type Change = { operation: 'create' | 'refresh' | 'pause' | 'accept'; id: string; revision: number; draft_id: string; version_id: string; paused: boolean }
export class SourceIntents extends AccessIntents { busy = new Set<string>() }
const uuid = /^[0-9a-f-]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/
const validDate = (v: unknown) => typeof v === 'string' && Number.isFinite(Date.parse(v))
export function preview(value: Preview): Preview {
  if (!value || !['uri', 'base64', 'xray', 'catalog', 'manifest'].includes(value.format) || !/^[a-f0-9]{64}$/.test(value.digest) || value.publication_ready !== false || !Array.isArray(value.profiles) || value.profiles.length < 1 || value.profiles.length > 32 || value.valid_until !== null && !validDate(value.valid_until) || value.subscription_expires_at !== null && !validDate(value.subscription_expires_at)) throw new ApiError('invalid_response')
  const ids = new Set<string>()
  for (const p of value.profiles) {
    if (!p || typeof p.id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(p.id) || ids.has(p.id) || !['xray', 'olcrtc', 'openflux'].includes(p.engine) || p.mode !== (p.engine === 'xray' ? 'vpn' : 'bypass') || [p.native, p.auto, p.source_dns].some(v => typeof v !== 'boolean')) throw new ApiError('invalid_response')
    if (p.content_digest && !/^[a-f0-9]{64}$/.test(p.content_digest)) throw new ApiError('invalid_response')
    ids.add(p.id)
  }
  return value
}
function version(v: Version) { if (!v || !uuid.test(v.id) || !validDate(v.created_at)) throw new ApiError('invalid_response'); preview(v.preview); return v }
export function source(v: Source): Source {
  if (!v || !uuid.test(v.id) || typeof v.name !== 'string' || v.name.length > 160 || !['url', 'upload'].includes(v.kind) || !Number.isSafeInteger(v.revision) || v.revision < 1 || typeof v.paused !== 'boolean' || v.error_code !== null && (typeof v.error_code !== 'string' || !/^source_[a-z_]{1,50}$/.test(v.error_code)) || !validDate(v.updated_at) || v.next_fetch_at !== null && !validDate(v.next_fetch_at)) throw new ApiError('invalid_response')
  version(v.current); if (v.candidate !== null) version(v.candidate); return v
}
function draft(v: Draft) { if (!v || !uuid.test(v.id) || !validDate(v.expires_at)) throw new ApiError('invalid_response'); preview(v.preview); return v }
const change = (operation: Change['operation'], n?: Source): Change => ({ operation, id: n?.id ?? '', revision: n?.revision ?? 0, draft_id: '', version_id: '', paused: false })

function useChange(api: ApiClient, intents: SourceIntents, scope: string, done: () => void) {
  const [error, setError] = useState<unknown>()
  const [, redraw] = useState(0)
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const submit = async (body?: Change, label = 'Изменение источника') => {
    if (intents.busy.has(scope)) return
    const old = intents.get(scope)
    if (!old && !body) return
    const intent = old ?? intents.begin(scope, { path: '/sources/mutate', method: 'POST', body, label })
    intents.busy.add(scope); setError(undefined); redraw(n => n + 1)
    try {
      source(await api.request<Source>(intent.path, { method: 'POST', body: intent.body, headers: { 'Idempotency-Key': intent.key } }))
      intents.finish(scope, intent.key)
      if (alive.current) done()
    } catch (e) { intents.failed(scope, intent.key, e); if (alive.current) setError(e) }
    finally { intents.busy.delete(scope); if (alive.current) redraw(n => n + 1) }
  }
  return { submit, error, pending: intents.get(scope), busy: intents.busy.has(scope) }
}
function ChangeStatus({ m }: { m: ReturnType<typeof useChange> }) {
  return <>{m.error != null && <Notice error={m.error} />}{m.pending && <Notice kind="info">{m.pending.unknown ? 'Результат изменения пока неизвестен.' : 'Ожидаем подтверждение.'} Повтор сохранит исходное действие.<p>{m.pending.label}</p><button className="button secondary small" disabled={m.busy} onClick={() => void m.submit()}>Повторить изменение</button></Notice>}</>
}
export function differences(before: Preview, after: Preview) {
  const old = new Map(before.profiles.map(p => [p.id, p]))
  const next = new Map(after.profiles.map(p => [p.id, p]))
  let changed: number | null = 0
  for (const p of after.profiles) { const prior = old.get(p.id); if (!prior) continue; if (!p.content_digest || !prior.content_digest) changed = null; else if (changed !== null && (p.content_digest !== prior.content_digest || p.engine !== prior.engine)) changed++ }
  return { added: after.profiles.filter(p => !old.has(p.id)).length, removed: before.profiles.filter(p => !next.has(p.id)).length, changed }
}
function Summary({ value, now }: { value: Preview; now: number }) {
  const expired = [value.valid_until, value.subscription_expires_at].some(v => v !== null && Date.parse(v) <= now)
  return <><div className="source-facts"><span><strong>{value.profiles.length}</strong> подключений</span><span>{value.profiles.filter(p => p.mode === 'vpn').length} VPN</span><span>{value.profiles.filter(p => p.mode === 'bypass').length} обходов</span></div>
    <dl className="source-dates"><div><dt>Срок подписки источника</dt><dd>{value.subscription_expires_at ? formatDate(value.subscription_expires_at) : 'Не указан'}</dd></div><div><dt>Срок настроек</dt><dd>{value.valid_until ? formatDate(value.valid_until) : 'Не указан'}</dd></div></dl>
    {expired && <Notice kind="info">Срок источника истёк. Сохранённая версия остаётся в истории; обновление не продлевает её срок.</Notice>}
    <div className="source-profile-list">{value.profiles.map((p, i) => <div key={p.id}><strong>Подключение {i + 1}</strong><span>{p.engine === 'xray' ? 'Xray · VPN' : p.engine === 'olcrtc' ? 'olcRTC · обход' : 'OpenFlux · обход'}{p.auto ? ' · Auto источника' : ''}{p.source_dns ? ' · свой DNS' : ''}{p.native ? ' · полный конфиг' : ''}</span></div>)}</div>
  </>
}
export function Sources({ api, canWrite, intents }: { api: ApiClient; canWrite: boolean; intents: SourceIntents }) {
  const [adding, setAdding] = useState(Boolean(intents.get('create')))
  const [selected, setSelected] = useState<string>()
  const [now, setNow] = useState(Date.now)
  useEffect(() => { const id = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(id) }, [])
  const load = useCallback(async (signal: AbortSignal) => {
    const value = await api.request<{ items: Source[] }>('/sources', { signal })
    if (!value || !Array.isArray(value.items) || value.items.length > 200) throw new ApiError('invalid_response')
    return { items: value.items.map(source) }
  }, [api])
  const resource = useResource(load, 5000)
  const n = resource.data?.items.find(n => n.id === selected)
  return <><PageHeading eyebrow="НАСТРОЙКИ ПОДКЛЮЧЕНИЙ" title="Источники" action={canWrite && <button className="button primary" onClick={() => setAdding(!adding)}><Icon name="plus" size={17} />Добавить источник</button>}>Собирайте VPN и обходы из файлов, ссылок и готовых подписок.</PageHeading>
    <div className="access-boundary"><Icon name="layers" size={18} /><p><strong>Сначала проверка и просмотр.</strong> Импорт сохраняет настройки для дальнейшей сборки. Подготовка и выдача пользователям доступны в разделе подписок.</p></div>
    {!canWrite && <Notice kind="info">Добавлять и принимать версии могут владелец и оператор инфраструктуры. Вам доступен просмотр.</Notice>}
    {adding && canWrite && <CreateSource api={api} intents={intents} now={now} close={() => setAdding(false)} done={() => { setAdding(false); resource.refresh() }} />}
    <div className="access-layout"><aside className="card user-directory" aria-label="Список источников"><div className="directory-heading"><h2>Источники</h2><Freshness resource={resource} /></div>{resource.error != null && <Notice error={resource.error} />}
      {resource.data?.items.length ? <div className="user-list">{resource.data.items.map(n => <button key={n.id} className={`user-choice ${selected === n.id ? 'selected' : ''}`} aria-pressed={selected === n.id} onClick={() => setSelected(n.id)}><span className="user-initial"><Icon name="layers" size={17} /></span><span><strong>{n.name}</strong><small>{n.error_code ? 'Обновление не удалось' : n.candidate ? 'Новая версия на проверке' : n.paused ? 'Обновление приостановлено' : n.kind === 'url' ? 'Подписка по ссылке' : 'Загруженный конфиг'}</small></span></button>)}</div> : <Empty icon="layers" title={resource.data ? 'Источников пока нет' : 'Получаем источники'}>Добавьте конфиг или ссылку на подписку.</Empty>}
    </aside><section className="user-workspace" aria-label="Карточка источника">{n ? <SourceDetail key={n.id} api={api} n={n} now={now} canWrite={canWrite} intents={intents} changed={resource.refresh} /> : <div className="card"><Empty icon="layers" title="Выберите источник">Здесь будут сохранённая версия, результат обновления и новые подключения.</Empty></div>}</section></div>
  </>
}
function CreateSource({ api, intents, now, close, done }: { api: ApiClient; intents: SourceIntents; now: number; close: () => void; done: () => void }) {
  const [name, setName] = useState(''); const [kind, setKind] = useState<'upload' | 'url'>('upload'); const [input, setInput] = useState(''); const [result, setResult] = useState<Draft>(); const [busy, setBusy] = useState(false); const [error, setError] = useState<unknown>()
  const m = useChange(api, intents, 'create', done)
  const locked = busy || m.busy || !!m.pending
  const current = result && Date.parse(result.expires_at) > now
  const reset = () => { setResult(undefined); setError(undefined) }
  return <section className="card form-card source-form"><h2>Новый источник</h2><ChangeStatus m={m} />{error != null && <Notice error={error} />}
    <form onSubmit={async event => { event.preventDefault(); if (locked) return; setBusy(true); reset(); try { const checked = draft(await api.request<Draft>('/sources/preview', { method: 'POST', body: { name: name.trim(), kind, input } })); setResult(checked); setInput('') } catch (e) { setError(e) } finally { setBusy(false) } }}>
      <label>Название источника<input required minLength={2} maxLength={80} value={name} disabled={locked || !!result} onChange={e => { setName(e.target.value); reset() }} /></label>
      {!result && <><label>Способ добавления<select value={kind} disabled={locked} onChange={e => { setKind(e.target.value as 'upload' | 'url'); setInput(''); reset() }}><option value="upload">Конфиг или список подключений</option><option value="url">HTTPS-ссылка на подписку</option></select></label>
        {kind === 'upload' ? <><label>Файл конфига<input type="file" accept=".json,.txt,.conf" disabled={locked} onChange={async e => { reset(); const file = e.target.files?.[0]; if (!file) return; if (file.size > 524288) { setError(new ApiError('source_invalid')); return } setBusy(true); try { setInput(new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer())) } catch { setError(new ApiError('source_invalid')) } finally { setBusy(false) } }} /></label><label>Или вставьте настройки<textarea required value={input} disabled={locked} onChange={e => { setInput(e.target.value); reset() }} rows={7} autoComplete="off" spellCheck={false} /></label></> : <label>Ссылка на подписку<input type="password" required autoComplete="off" value={input} disabled={locked} onChange={e => { setInput(e.target.value); reset() }} /></label>}
        <p className="field-hint">VLESS, Hysteria2, Xray JSON, каталоги САЛФЕТКА и списки base64. До 512 КБ. Настройки и ключи хранятся в зашифрованном виде.</p></>}
      {result && <div className="source-preview"><h3>Предварительный просмотр</h3><Summary value={result.preview} now={now} />{!current && <Notice kind="info">Срок предпросмотра истёк. Загрузите источник и проверьте его снова.</Notice>}</div>}
      <div className="form-actions"><button className="button secondary" type="button" onClick={close}>Закрыть</button>{result ? <><button type="button" className="button secondary" disabled={locked} onClick={() => { setResult(undefined); setInput('') }}>Другой конфиг</button><button type="button" className="button primary" disabled={locked || !current} onClick={() => void m.submit({ ...change('create'), draft_id: result.id }, `Сохранить источник: ${name}`)}>Сохранить источник</button></> : <button className="button primary" disabled={locked}>{busy ? 'Проверяем…' : 'Проверить источник'}</button>}</div>
    </form>
  </section>
}
function SourceDetail({ api, n, now, canWrite, intents, changed }: { api: ApiClient; n: Source; now: number; canWrite: boolean; intents: SourceIntents; changed: () => void }) {
  const m = useChange(api, intents, n.id, changed); const locked = !canWrite || m.busy || !!m.pending
  const [review, setReview] = useState<{ revision: number; version: Version }>()
  const [history, setHistory] = useState<Version[]>(); const [historyError, setHistoryError] = useState<unknown>(); const [historyBusy, setHistoryBusy] = useState(false)
  const diff = review && differences(n.current.preview,review.version.preview)
  const expired = review && [review.version.preview.valid_until, review.version.preview.subscription_expires_at].some(v => v && Date.parse(v) <= now)
  return <><section className="card form-card"><div className="directory-heading"><h2>{n.name}</h2><span className="badge neutral">{n.kind === 'url' ? 'Подписка' : 'Файл / текст'}</span></div><ChangeStatus m={m} />
    {n.error_code && <Notice kind="info">{n.error_code === 'source_expired' ? 'Срок полученного источника истёк.' : 'Последняя попытка обновления не удалась.'} Сохранённая версия не удалена.{n.next_fetch_at && !n.paused ? ` Следующая попытка: ${formatDate(n.next_fetch_at)}.` : ''}</Notice>}
    {historyError != null && <Notice error={historyError} />}<h3>Принятая версия</h3><p className="field-hint">Сохранена {formatDate(n.current.created_at)}. Использование в VPN требует отдельной публикации.</p><Summary value={n.current.preview} now={now} />
    {n.kind === 'url' && <div className="form-actions"><button className="button secondary" disabled={locked} onClick={() => void m.submit(change('refresh', n), 'Проверить обновление источника')}>Проверить обновление</button><button className="button secondary" disabled={locked} onClick={() => void m.submit({ ...change('pause', n), paused: !n.paused }, n.paused ? 'Возобновить обновление' : 'Приостановить обновление')}>{n.paused ? 'Возобновить' : 'Приостановить'}</button></div>}
  <div className="form-actions"><button className="button secondary" disabled={historyBusy} onClick={async () => { if (history) { setHistory(undefined); return }; setHistoryBusy(true); setHistoryError(undefined); try { const data = await api.request<{items:Version[]}>(`/sources/${n.id}/versions`); if (!data || !Array.isArray(data.items) || data.items.length>200) throw new ApiError('invalid_response'); setHistory(data.items.map(version)) } catch(e) { setHistoryError(e) } finally { setHistoryBusy(false) } }}>{history ? 'Скрыть историю' : 'История версий'}</button></div>
    {history && <div className="source-profile-list">{history.map(v => <div key={v.id}><strong>{formatDate(v.created_at)}</strong><span>{v.preview.profiles.length} подключений · {v.id === n.current.id ? 'принятая' : v.id === n.candidate?.id ? 'на проверке' : 'сохранённая'}</span></div>)}</div>}
  </section>{n.candidate && <section className="card form-card"><h2>Новая версия</h2><p>Получена {formatDate(n.candidate.created_at)}. Прежние настройки сохраняются до вашего решения.</p><button className="button secondary" disabled={!canWrite} onClick={() => setReview({ revision: n.revision, version: structuredClone(n.candidate!) })}>Посмотреть изменения</button></section>}
    {review && <section className="card form-card"><h2>Проверка новой версии</h2><Notice kind="info">Было подключений: {n.current.preview.profiles.length}. В новой версии: {review.version.preview.profiles.length}. Добавлено записей: {diff!.added}; отсутствует: {diff!.removed}; изменены настройки: {diff!.changed ?? 'нет данных для сравнения'}. При принятии весь набор этой версии заменит текущий источник.</Notice><Summary value={review.version.preview} now={now} />{review.revision !== n.revision && <Notice kind="info">Источник изменился после открытия просмотра. Откройте новую версию заново.</Notice>}<div className="form-actions"><button className="button secondary" onClick={() => setReview(undefined)}>Закрыть просмотр</button><button className="button primary" disabled={locked || !!expired || review.revision !== n.revision} onClick={() => void m.submit({ ...change('accept', n), revision: review.revision, version_id: review.version.id }, 'Принять просмотренную версию источника').then(() => { if (!intents.get(n.id)) setReview(undefined) })}>Принять эту версию</button></div></section>}
  </>
}
