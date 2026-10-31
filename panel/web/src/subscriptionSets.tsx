import { DeviceInvite } from './deviceInvite'
import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiClient, ApiError } from './api'
import type { Page } from './api'
import { Empty, formatDate, Freshness, Icon, Notice, PageHeading } from './components'
import { useResource } from './useResource'
import { Modal } from './modal'
import { emptyNetwork, fromOutline, memberKey, move, parseDocument, parseOutline } from './constructorModel'
import type { Document, Location, Network, Outline } from './constructorModel'
import { LocationFields, NetworkFields, RoutingFields } from './constructorFields'
import type { ConnectionOption } from './constructorFields'
import { nodesPage } from './nodeApi'
import type { Node } from './nodeApi'
import { vpnStatus } from './vpnApi'
import type { VPNStatus } from './vpnApi'
import { source } from './sources'
import type { Source } from './sources'
import { accessUsers, userDetail, decisionReason } from './accessApi'
import type { AccessUser, UserDetail } from './accessApi'
import { SetSession, assignment, personalURL, publication, setPage, setRecord, summary } from './subscriptionSetModel'
import type { Assignment, Publication, SetPage, SetRecord, SetSummary, Target } from './subscriptionSetModel'

const base = '/subscription-sets'
export function SubscriptionSets({ api, canEdit, canPublish, session, openServers, openSources }: { api: ApiClient; canEdit: boolean; canPublish: boolean; session: SetSession; openServers: () => void; openSources: () => void }) {
 const [doc, setDoc] = useState(session.document), [saved, setSaved] = useState(session.saved), [selected, setSelected] = useState(session.selected)
 const [cursor, setCursor] = useState(''), [query, setQuery] = useState(''), [tab, setTab] = useState('Состав'), [error, setError] = useState<unknown>(), [message, setMessage] = useState(''), [, redraw] = useState(0)
 const [editing, setEditing] = useState<string>(), [confirm, setConfirm] = useState<'publish' | 'discard'>(), [json, setJSONState] = useState<string | undefined>(session.json), [dragged, setDragged] = useState<number>()
 const setJSON = (value: string | undefined) => { session.json = value; setJSONState(value) }
 const [opening, setOpening] = useState(false), generation = useRef(0)
 const list = useResource(useCallback(async (signal: AbortSignal) => setPage(await api.request<SetPage<SetSummary>>(`${base}${cursor ? `?after=${cursor}` : ''}`, { signal }), summary), [api, cursor]))
 const dirty = !!doc && (!saved || JSON.stringify(doc) !== JSON.stringify(saved.document)) || json !== undefined
 const pending = session.pendingScope ? session.get(session.pendingScope) : undefined
 const locked = session.busy || !!pending || opening
 const update = (value: Document) => { session.document = value; setDoc(value); setMessage('') }
 const mutate = (f: (value: Document) => void) => { if (!doc || locked) return; const d = structuredClone(doc); f(d); update(d) }
 const adopt = (value: SetRecord) => { session.saved = value; session.selected = value.id; setSaved(value); setSelected(value.id); update(structuredClone(value.document)); setJSON(undefined) }
 useEffect(() => { const warn = (e: BeforeUnloadEvent) => { if (dirty || pending) { e.preventDefault(); e.returnValue = '' } }; window.addEventListener('beforeunload', warn); return () => window.removeEventListener('beforeunload', warn) }, [dirty, pending])
 useEffect(() => () => { generation.current++ }, [])
 const open = async (id: string) => {
  if (dirty || locked) { setMessage('Сначала сохраните изменения или отмените их.'); return }
  const version = ++generation.current; setOpening(true); setError(undefined)
  try { const value = setRecord(await api.request<SetRecord>(`${base}/${id}`), id); if (version === generation.current) { adopt(value); setTab('Состав') } }
  catch (e) { if (version === generation.current) setError(e) } finally { if (version === generation.current) setOpening(false) }
 }
 const create = () => { if (dirty || locked) { setMessage('Сначала сохраните изменения или отмените их.'); return }; session.fresh(); setSaved(undefined); setSelected('new'); setDoc(session.document); setTab('Состав'); setError(undefined) }
 const write = async (kind: 'save' | 'publish') => {
  if (session.busy || !doc) return
  const scope = session.pendingScope ?? `set-${kind}:${saved?.id ?? 'new'}`
  const intent = session.get(scope) ?? session.begin(scope, { path: `${base}/${kind}`, method: 'POST', label: kind === 'save' ? 'Сохранение подписки' : 'Публикация подписки', body: kind === 'save' ? { id: saved?.id ?? '', revision: saved?.revision ?? 0, document: doc } : { id: saved!.id, revision: saved!.revision } })
  session.pendingScope = scope; session.busy = true; redraw(n => n + 1); setError(undefined)
  try {
   const value = await api.request<unknown>(intent.path, { method: 'POST', body: intent.body, headers: { 'Idempotency-Key': intent.key } })
   if (intent.path.endsWith('/save')) { const result = setRecord(value as SetRecord, (intent.body as { id: string }).id || undefined); adopt(result) }
   else { const p = publication(value as Publication, saved!.id); if (p.current) { const next = { ...saved!, published_id: p.id }; session.saved = next; setSaved(next) }; setMessage(`Публикация версии ${p.revision} принята. Результаты сборки показаны ниже.`); setTab('Публикация') }
   session.finish(scope, intent.key); session.pendingScope = undefined; list.refresh()
   if (intent.path.endsWith('/save')) {
    setMessage('Черновик сохранён. Для обновления пользователей нажмите «Опубликовать».')
    const result = value as SetRecord
    const latest = setRecord(await api.request<SetRecord>(`${base}/${result.id}`), result.id)
    if (latest.revision !== result.revision) { setMessage(`Ваше сохранение подтверждено как версия ${result.revision}, но уже существует версия ${latest.revision}. Откройте её перед следующим изменением.`) }
   }
   else { const current = setRecord(await api.request<SetRecord>(`${base}/${saved!.id}`), saved!.id); adopt(current); setMessage('Публикация принята. Проверьте результаты сборки для устройств.') }
  } catch (e) { session.failed(scope, intent.key, e); if (!session.get(scope)) session.pendingScope = undefined; setError(e) }
  finally { session.busy = false; setConfirm(undefined); redraw(n => n + 1) }
 }
 const discard = () => { if (saved) update(structuredClone(saved.document)); else { session.document = undefined; session.selected = undefined; setDoc(undefined); setSelected(undefined) }; setJSON(undefined); setError(undefined); setMessage(''); setConfirm(undefined) }
 const [outlines, setOutlines] = useState<Record<string, Outline>>({})
 const choices = useResource(useCallback(async (signal: AbortSignal) => {
  if (!canEdit) return { nodes: { items: [] as Node[] }, sources: [] as Source[] }
  const loadNodes = async () => {
   const items = new Map<string, Node>(), seen = new Set<string>(); let cursor = ''
   do {
    const page = nodesPage(await api.request<Page<Node>>(`/nodes?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, { signal }))
    for (const value of page.items) items.set(value.id, value)
    cursor = page.next_cursor ?? ''
    if (cursor && (!/^[0-9a-f-]{36}$/.test(cursor) || seen.has(cursor))) throw new ApiError('invalid_response')
    seen.add(cursor)
   } while (cursor)
   return { items: [...items.values()] }
  }
  const [n, s] = await Promise.all([loadNodes(), api.request<{ items: Source[] }>('/sources', { signal })])
  if (!s || !Array.isArray(s.items)) throw new ApiError('invalid_response')
  return { nodes: n, sources: s.items.map(source) }
 }, [api, canEdit]))
 useEffect(() => {
  let active = true
  for (const ref of doc?.recipe.sources ?? []) if (outlines[ref.id]?.version_id !== ref.version_id && canEdit) {
   void api.request<Outline>('/builder/source', { method: 'POST', body: ref }).then(parseOutline).then(o => { if (active) setOutlines(prev => ({ ...prev, [o.id]: o })) }).catch(e => { if (active) setError(e) })
  }
  return () => { active = false }
 }, [api, canEdit, JSON.stringify(doc?.recipe.sources)])
 const addNode = async (id: string) => {
  if (!id || !doc || locked) return
  session.busy = true; redraw(n => n + 1); setError(undefined)
  try {
   const v = vpnStatus(await api.request<VPNStatus>(`/nodes/${id}/vpn`), id)
   if (!v.installation?.enabled || !v.installation.endpoint) throw new ApiError('release_unavailable')
   const d = structuredClone(session.document!)
   if (!d.recipe.node_ids.includes(id)) {
    const bypass = v.installation.endpoint.backend === 'olcrtc'
    d.recipe.node_ids.push(id); d.recipe.blueprint.locations.push({ id: crypto.randomUUID(), title: choices.data?.nodes.items.find(n => n.id === id)?.name ?? 'Сервер', mode: bypass ? 'bypass' : 'vpn', kind: 'location', selection: bypass ? 'first_working' : 'native', members: [{ node_id: id }] }); update(d)
   }
  } catch (e) { setError(e) } finally { session.busy = false; redraw(n => n + 1) }
 }
 const addSource = async (id: string) => {
  const s = choices.data?.sources.find(s => s.id === id); if (!s || !doc || locked) return
  session.busy = true; redraw(n => n + 1); setError(undefined)
  try {
   const o = parseOutline(await api.request<Outline>('/builder/source', { method: 'POST', body: { id, version_id: s.current.id } }))
   const d = structuredClone(session.document!)
   if (!d.recipe.sources.some(r => r.id === id)) {
    d.recipe.sources.push({ id, version_id: s.current.id }); d.recipe.blueprint.locations.push(...fromOutline(o)); d.recipe.external_credentials = false
    if (o.network && !(d.recipe.blueprint.network.value as Network | undefined)?.probe?.url) d.recipe.blueprint.network = { authority: 'source', source_id: id }
    setOutlines(prev => ({ ...prev, [id]: o })); update(d)
   }
  } catch (e) { setError(e) } finally { session.busy = false; redraw(n => n + 1) }
 }
 const options: ConnectionOption[] = (doc?.recipe.node_ids ?? []).map(id => ({ key: `n:${id}`, member: { node_id: id }, label: choices.data?.nodes.items.find(n => n.id === id)?.name ?? id, mode: doc?.recipe.blueprint.locations.find(l => l.members.some(m => m.node_id === id))?.mode ?? 'vpn', native: true, auto: false, dns: false }))
 for (const ref of doc?.recipe.sources ?? []) for (const [i, p] of (outlines[ref.id]?.profiles ?? []).entries()) options.push({ key: `s:${ref.id}:${p.id}`, member: { source_id: ref.id, connection_id: p.id }, label: `${choices.data?.sources.find(s => s.id === ref.id)?.name ?? 'Источник'} · ${i + 1}`, mode: p.mode, native: p.native, auto: p.auto, dns: p.source_dns })
 const locations = doc?.recipe.blueprint.locations ?? [], location = locations.find(l => l.id === editing)
 const sourceOptions = doc?.recipe.sources.map(r => ({ id: r.id, name: choices.data?.sources.find(s => s.id === r.id)?.name ?? r.id })) ?? []
 return <><PageHeading eyebrow="РАБОЧАЯ ОБЛАСТЬ" title="Подписки" action={canEdit && <button className="button primary" disabled={locked} onClick={create}><Icon name="plus" size={16} />Новая подписка</button>}>Соберите набор подключений и назначьте его пользователям.</PageHeading>
 {error != null && <Notice error={error} />}{message && <Notice kind="info">{message}</Notice>}
 {pending && <Notice kind="info">Результат пока не подтверждён. Повтор отправит тот же запрос.<button className="button secondary" disabled={session.busy} onClick={() => void write('save')}>Повторить запрос</button></Notice>}
 <div className="sets-layout"><aside className="card set-directory"><h2>Все подписки</h2><label><span className="sr-only">Найти подписку на странице</span><input type="search" placeholder="Найти подписку…" value={query} onChange={e => setQuery(e.target.value)} /></label><Freshness resource={list} />{list.error != null && <Notice error={list.error} />}
 {list.data?.items.filter(s => s.title.toLocaleLowerCase().includes(query.toLocaleLowerCase())).map(s => <button key={s.id} className={`set-choice ${selected === s.id ? 'selected' : ''}`} disabled={locked} aria-pressed={selected === s.id} onClick={() => void open(s.id)}><strong>{s.title}</strong><span>Сохранённая версия {s.revision}</span></button>)}
 {!list.data?.items.length && <Empty title={list.loading ? 'Загружаем подписки' : list.error ? 'Список недоступен' : 'Создайте первый набор'}>Здесь будут общие подписки с разным составом.</Empty>}
 <div className="pagination">{cursor && <button className="button secondary small" onClick={() => setCursor('')}>В начало</button>}{list.data?.next_cursor && <button className="button secondary small" onClick={() => setCursor(list.data!.next_cursor)}>Далее</button>}</div></aside>
 <section className="set-workspace">{!doc ? <div className="card"><Empty icon="layers" title={opening ? 'Открываем подписку' : 'Выберите или создайте подписку'}>Серверы → подключения → состав подписки → пользователи.</Empty><div className="set-start-actions"><button className="button secondary" onClick={openServers}>Настроить серверы</button></div></div> : <>
 <div className="set-title"><div><span className="eyebrow">{saved ? `ВЕРСИЯ ${saved.revision}` : 'НОВЫЙ НАБОР'}</span><h2>{doc.title}</h2><span className="badge neutral">{dirty ? 'Есть несохранённые изменения' : saved?.published_id ? 'Есть опубликованная версия' : 'Черновик'}</span></div><div className="builder-actions">{canEdit && <><button className="button secondary" disabled={locked || dirty || !saved} onClick={() => { const copy = structuredClone(doc); copy.title = `${copy.title.slice(0, 118)} · копия`; session.fresh(); setSaved(undefined); setSelected('new'); update(copy); setTab('Состав') }}>Дублировать</button><button className="button secondary" disabled={locked || !dirty} onClick={() => setConfirm('discard')}>Отменить изменения</button><button className="button secondary" disabled={locked || json !== undefined || !doc.title.trim()} onClick={() => void write('save')}>Сохранить</button></>}{canPublish && <button className="button primary" disabled={locked || dirty || !saved} onClick={() => setConfirm('publish')}>Опубликовать</button>}</div></div>
 <div className="set-tabs" role="tablist" aria-label="Разделы подписки">{['Состав', 'Маршруты', ...(canPublish ? ['Пользователи'] : []), 'Конфиг', 'История', 'Публикация'].map(t => <button role="tab" aria-selected={tab === t} className={tab === t ? 'active' : ''} key={t} onClick={() => setTab(t)}>{t}</button>)}</div>
 {tab === 'Состав' && <div className="composition-layout"><section className="card set-section"><label>Название подписки<input maxLength={128} value={doc.title} disabled={!canEdit || locked} onChange={e => mutate(d => { d.title = e.target.value })} /></label><div className="section-toolbar"><h3>Локации и подключения</h3>{canEdit && <button className="button secondary small" disabled={locked || locations.length >= 64} onClick={() => { const l: Location = { id: crypto.randomUUID(), title: 'Новая локация', mode: 'vpn', kind: 'location', selection: 'first_working', members: [] }; mutate(d => d.recipe.blueprint.locations.push(l)); setEditing(l.id) }}>Добавить локацию</button>}</div>
 {locations.map((l, i) => <div key={l.id} className={`connection-row ${dragged === i ? 'dragging' : ''}`} draggable={canEdit && !locked} onDragStart={e => { e.dataTransfer.setData('text/plain', l.id); setDragged(i) }} onDragEnd={() => setDragged(undefined)} onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); if (dragged !== undefined && !locked) mutate(d => { const [m] = d.recipe.blueprint.locations.splice(dragged, 1); d.recipe.blueprint.locations.splice(i, 0, m) }); setDragged(undefined) }}><span className="connection-glyph">{l.icon || '◎'}</span><div className="connection-label"><strong>{l.title}</strong><small>{l.mode === 'vpn' ? 'VPN' : 'Обход'} · {l.members.length} подключений{l.country ? ` · ${l.country}` : ''}</small></div><div className="builder-actions">{canEdit && <><button className="button ghost small" aria-label={`Поднять ${l.title}`} disabled={locked || i === 0} onClick={() => mutate(d => { d.recipe.blueprint.locations = move(locations, i, -1) })}>↑</button><button className="button ghost small" aria-label={`Опустить ${l.title}`} disabled={locked || i === locations.length - 1} onClick={() => mutate(d => { d.recipe.blueprint.locations = move(locations, i, 1) })}>↓</button></>}<button className="button secondary small" disabled={locked} onClick={() => setEditing(l.id)} aria-label={`Редактировать ${l.title}`}>✎</button></div></div>)}
 {!locations.length && <p className="section-description">Добавьте подключённый сервер ниже. Его настройки появятся в составе подписки.</p>}
 {canEdit && <fieldset disabled={locked} className="set-catalog"><legend>Добавить в состав</legend>{choices.error != null && <Notice error={choices.error} />}<label>Подключение сервера<select value="" onChange={e => void addNode(e.target.value)}><option value="">Выберите сервер</option>{choices.data?.nodes.items.filter(n => n.state === 'active' && !doc.recipe.node_ids.includes(n.id)).map(n => <option key={n.id} value={n.id}>{n.name}</option>)}</select></label><button className="button secondary small" onClick={openServers}>Серверы и настройки VPN</button><details><summary>Источники и импорт</summary><p className="field-hint">Общие подписки требуют индивидуальных ключей. Источник с общим пользовательским ключом может быть сохранён в черновик, но публикация будет отклонена.</p><label>Сохранённый источник<select value="" onChange={e => void addSource(e.target.value)}><option value="">Выберите источник</option>{choices.data?.sources.filter(s => !doc.recipe.sources.some(r => r.id === s.id)).map(s => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label><button className="button secondary small" onClick={openSources}>Открыть каталог источников</button></details>
 {!!doc.recipe.node_ids.length && <details><summary>Убрать сервер из набора</summary>{doc.recipe.node_ids.map(id => <button key={id} className="button secondary small" onClick={() => mutate(d => { d.recipe.node_ids = d.recipe.node_ids.filter(n => n !== id); d.recipe.blueprint.locations = d.recipe.blueprint.locations.map(l => ({ ...l, members: l.members.filter(m => m.node_id !== id) })).filter(l => l.members.length) })}>Убрать {choices.data?.nodes.items.find(n => n.id === id)?.name ?? id}</button>)}</details>}</fieldset>}</section>
 <aside className="card set-preview"><h3>В приложении</h3><p className="field-hint">Предпросмотр состава, не проверка связи</p><div className="preview-phone"><span className="eyebrow">САЛФЕТКА</span><h3>{doc.title}</h3>{locations.map(l => <div className="preview-location" key={l.id}><span>{l.icon || '◎'}</span><div><strong>{l.title}</strong><small>{l.mode === 'vpn' ? 'VPN' : 'Обход'}</small></div></div>)}</div></aside></div>}
 {tab === 'Маршруты' && <section className="card set-section"><h3>Маршруты приложения</h3><fieldset disabled={!canEdit || locked}>{(['vpn', 'bypass'] as const).map(mode => <RoutingFields key={mode} mode={mode} value={doc.recipe.blueprint.routing[mode]} sourceOptions={sourceOptions} onChange={v => mutate(d => { d.recipe.blueprint.routing[mode] = v })} />)}<h3>DNS и проверка соединения</h3><label>Источник сетевых настроек<select value={doc.recipe.blueprint.network.authority === 'source' ? doc.recipe.blueprint.network.source_id : 'custom'} onChange={e => mutate(d => { d.recipe.blueprint.network = e.target.value === 'custom' ? { authority: 'custom', value: emptyNetwork() } : { authority: 'source', source_id: e.target.value } })}><option value="custom">Свои настройки</option>{sourceOptions.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>{doc.recipe.blueprint.network.authority === 'custom' && <NetworkFields value={doc.recipe.blueprint.network.value as Network} onChange={v => mutate(d => { d.recipe.blueprint.network.value = v })} />}</fieldset><p className="field-hint">Серверные маршруты изменяются отдельно в карточке сервера.</p></section>}
 {tab === 'Конфиг' && <section className="card set-section"><h3>Модель подписки</h3><p className="section-description">Персональные ключи добавляются при сборке для устройства. Здесь сохранён общий состав и правила.</p>{json === undefined ? <><pre className="config-preview" data-private>{JSON.stringify(doc, null, 2)}</pre>{canEdit && <button className="button secondary" disabled={locked} onClick={() => setJSON(JSON.stringify(doc, null, 2))}>Редактировать JSON</button>}</> : <><label>JSON подписки<textarea data-private rows={20} value={json} onChange={e => setJSON(e.target.value)} /></label><div className="builder-actions"><button className="button primary" onClick={() => { try { const d = parseDocument(JSON.parse(json)); if (d.recipe.external_credentials) throw new ApiError('subscription_set_invalid'); update(d); setJSON(undefined); setError(undefined) } catch { setError(new ApiError('builder_model_invalid')) } }}>Применить к черновику</button><button className="button secondary" onClick={() => setJSON(undefined)}>Отменить JSON</button></div></>}</section>}
 {tab === 'История' && (saved ? <SetHistory api={api} saved={saved} /> : <Empty title="Истории пока нет">Сначала сохраните подписку.</Empty>)}
 {tab === 'Пользователи' && canPublish && (saved ? <SetAssignments key={saved.id} api={api} setID={saved.id} session={session} /> : <Empty title="Сначала сохраните набор">После сохранения можно назначить пользователей.</Empty>)}
 {tab === 'Публикация' && (saved?.published_id ? <SetPublication key={saved.published_id} api={api} id={saved.published_id} setID={saved.id} revision={saved.revision} targets={canPublish} /> : <Empty title="Ещё не опубликовано">Сохраните набор и нажмите «Опубликовать». Получатели заберут конфиг при обновлении.</Empty>)}
 </>}</section></div>
 {location && <Modal title="Редактировать локацию" close={() => setEditing(undefined)}><fieldset disabled={!canEdit || locked}><LocationFields value={location} options={options} onChange={value => mutate(d => { d.recipe.blueprint.locations = locations.map(l => l.id === value.id ? value : l) })} /><div className="icon-picker" aria-label="Выбор значка">{['◎', '🌐', '🛡', '⚡', '🇩🇪', '🇫🇮', '🇵🇱', '🇺🇸', '🇸🇪'].map(icon => <button type="button" aria-label={`Значок ${icon}`} key={icon} aria-pressed={location.icon === icon} className="button secondary" onClick={() => mutate(d => { d.recipe.blueprint.locations.find(l => l.id === location.id)!.icon = icon })}>{icon}</button>)}</div></fieldset><div className="form-actions">{canEdit && <button className="button secondary danger-text" disabled={locked} onClick={() => { mutate(d => { d.recipe.blueprint.locations = locations.filter(l => l.id !== location.id) }); setEditing(undefined) }}>Удалить локацию из набора</button>}<button className="button primary" onClick={() => setEditing(undefined)}>Готово</button></div><p className="field-hint">Изменения остаются в черновике до сохранения и публикации.</p></Modal>}
 {confirm && <Modal title={confirm === 'publish' ? 'Опубликовать подписку?' : 'Отменить несохранённые изменения?'} close={() => { if (!session.busy) setConfirm(undefined) }}><p>{confirm === 'publish' ? `Версия ${saved?.revision} будет собрана для всех назначенных пользователей. Они получат её при обновлении подписки. Серверы не перезапускаются; ошибки сборки сохранят прежнюю выдачу.` : 'Изменения формы будут потеряны. Сохранённая версия и выдача пользователям останутся прежними.'}</p><div className="form-actions"><button className="button secondary" disabled={session.busy} onClick={() => setConfirm(undefined)}>Назад</button><button className="button primary" disabled={session.busy} onClick={() => confirm === 'publish' ? void write('publish') : discard()}>{confirm === 'publish' ? 'Подтвердить публикацию' : 'Отменить правки'}</button></div></Modal>}
 </>
}

function SetHistory({ api, saved }: { api: ApiClient; saved: SetRecord }) {
 const [revision, setRevision] = useState(saved.revision)
 const r = useResource(useCallback(async (signal: AbortSignal) => setRecord(await api.request<SetRecord>(`${base}/${saved.id}?revision=${revision}`, { signal }), saved.id), [api, saved.id, revision]))
 return <section className="card set-section"><h3>Сохранённые версии</h3><label>Версия<input type="number" min={1} max={saved.revision} value={revision} onChange={e => { const n = Number(e.target.value); if (Number.isInteger(n) && n >= 1 && n <= saved.revision) setRevision(n) }} /></label><Freshness resource={r} />{r.error != null && <Notice error={r.error} />}{r.data && <><p>{formatDate(r.data.updated_at)} · {r.data.document.title}</p><pre className="config-preview" data-private>{JSON.stringify(r.data.document, null, 2)}</pre></>}</section>
}
function SetPublication({ api, id, setID, revision, targets }: { api: ApiClient; id: string; setID: string; revision: number; targets: boolean }) {
 const r = useResource(useCallback(async (signal: AbortSignal) => publication(await api.request<Publication>(`${base}/publications/${id}`, { signal }), setID), [api, id, setID]), 5000)
 const [after, setAfter] = useState('')
 const t = useResource(useCallback(async (signal: AbortSignal) => targets ? setPage(await api.request<SetPage<Target>>(`${base}/targets?publication_id=${id}${after ? `&after=${encodeURIComponent(after)}` : ''}`, { signal }), x => { if (!x || typeof x.device_id !== 'string' || !['pending', 'retry', 'published', 'cancelled'].includes(x.state)) throw new ApiError('invalid_response') }) : null, [api, id, after, targets]), 5000)
 const p = r.data
 return <section className="card set-section"><h3>Обновление пользователей</h3><Freshness resource={r} />{r.error != null && <Notice error={r.error} />}{p && <><p>Опубликованная версия {p.revision}{revision !== p.revision ? ` · сохранён более новый черновик ${revision}` : ''}{!p.current ? ' · заменена другой публикацией' : ''}</p><div className="publication-counts"><span><strong>{p.published_devices}</strong> конфигов готово</span><span><strong>{p.pending_devices}</strong> ожидают</span><span><strong>{p.retry_devices}</strong> повтор сборки</span><span><strong>{p.users_without_device}</strong> без устройства</span></div><p className="field-hint">Готовность конфига не подтверждает подключение телефона. Ошибки сборки повторяются автоматически.</p></>}{t.error != null && <Notice error={t.error} />}{t.data && <><div className="table-scroll"><table><thead><tr><th>Устройство</th><th>Результат</th><th>Причина</th></tr></thead><tbody>{t.data.items.map((x, index) => <tr key={`${x.assignment_id}:${x.assignment_revision}:${x.device_id}:${index}`}><td><code>{x.device_id.slice(0, 8)}</code></td><td>{{ published: 'Готово к выдаче', pending: 'В очереди', retry: 'Повторяем сборку', cancelled: 'Отменено' }[x.state]}</td><td>{({ publication_unavailable: 'Конфигурация или подключение ещё не готовы', publication_conflict: 'Настройки изменились — повторяем', release_capacity: 'Достигнут предел сохранённых версий', access_denied: 'Доступ закрыт', superseded: 'Заменено новой публикацией' } as Record<string, string>)[x.code] ?? (x.code ? 'Требуется проверка' : '—')}</td></tr>)}</tbody></table></div><div className="pagination">{after && <button className="button secondary small" onClick={() => setAfter('')}>В начало</button>}{t.data.next_cursor && <button className="button secondary small" onClick={() => setAfter(t.data!.next_cursor)}>Далее</button>}</div></>}</section>
}

function SetAssignments({ api, setID, session }: { api: ApiClient; setID: string; session: SetSession }) {
 const [user, setUser] = useState(''), [cursor, setCursor] = useState(''), [error, setError] = useState<unknown>(), [url, setURL] = useState(''), [linkKind, setLinkKind] = useState<'a' | 's'>('a'), [busy, setBusy] = useState(false), [confirm, setConfirm] = useState(false), [copied, setCopied] = useState(false)
 const users = useResource(useCallback(async (signal: AbortSignal) => accessUsers(await api.request<Page<AccessUser>>(`/access/users?limit=50${cursor ? `&cursor=${cursor}` : ''}`, { signal })), [api, cursor]))
 const current = useResource(useCallback(async (signal: AbortSignal) => {
  if (!user) return null
  // Read every bounded page, never mistake a later assignment for a new one.
  const assignments: Assignment[] = []; let after = ''; const seen = new Set<string>()
  do { const page = setPage(await api.request<SetPage<Assignment>>(`${base}/assignments?user_id=${user}${after ? `&after=${encodeURIComponent(after)}` : ''}`, { signal }), a => assignment(a, user)); assignments.push(...page.items); after = page.next_cursor; if (after && seen.has(after) || seen.size > 100) throw new ApiError('invalid_response'); seen.add(after) } while (after)
  const detail = userDetail(await api.request<UserDetail>(`/access/users/${user}`, { signal }), user)
  return { assignment: assignments.find(a => a.set_id === setID), detail }
 }, [api, user, setID]))
 const scope = `set-assignment:${setID}:${user}`, pending = session.get(scope), a = current.data?.assignment
 const request = useRef(0)
 useEffect(() => { request.current++; setURL(''); setError(undefined); setCopied(false); setConfirm(false) }, [user])
 useEffect(() => () => { request.current++ }, [])
 const assign = async (state: 'active' | 'revoked') => {
  if (busy || !user || !current.data) return
  const turn = ++request.current; setBusy(true); setError(undefined); setURL('')
  const intent = pending ?? session.begin(scope, { path: `${base}/assign`, method: 'POST', label: 'Назначение подписки', body: { user_id: user, set_id: setID, state, revision: a?.revision ?? 0 } })
  try { assignment(await api.request<Assignment>(intent.path, { method: 'POST', body: intent.body, headers: { 'Idempotency-Key': intent.key } }), user, setID); session.finish(scope, intent.key); if (turn === request.current) current.refresh() }
  catch (e) { session.failed(scope, intent.key, e); if (turn === request.current) setError(e) } finally { if (turn === request.current) { setBusy(false); setConfirm(false) } }
 }
 const link = async (device?: string) => {
  if (!a || busy) return; const turn = ++request.current; setBusy(true); setURL(''); setError(undefined); setCopied(false)
  try { const kind = device ? 's' : 'a'; const value = personalURL(await api.request<{ url: string }>(`${base}/${device ? 'device-link' : 'link'}`, { method: 'POST', body: { assignment_id: a.id, ...(device ? { device_id: device } : {}) } }), kind); if (turn === request.current) { setURL(value); setLinkKind(kind) } }
  catch (e) { if (turn === request.current) setError(e) } finally { if (turn === request.current) setBusy(false) }
 }
 return <section className="card set-section"><h3>Назначения и персональные ссылки</h3><p className="section-description">Выберите аккаунт. У каждого назначенного набора — отдельная ссылка; срок доступа задаётся в карточке пользователя.</p>{users.error != null && <Notice error={users.error} />}<label>Пользователь<select value={user} disabled={busy} onChange={e => setUser(e.target.value)}><option value="">Выберите пользователя</option>{users.data?.items.map(u => <option key={u.id} value={u.id}>{u.name}</option>)}</select></label><div className="builder-actions">{cursor && <button className="button secondary small" disabled={busy} onClick={() => setCursor('')}>Первые пользователи</button>}{users.data?.next_cursor && <button className="button secondary small" disabled={busy} onClick={() => setCursor(users.data!.next_cursor!)}>Другие пользователи</button>}</div>
 {current.error != null && <Notice error={current.error} />}{error != null && <Notice error={error} />}{pending && <Notice kind="info">Исход назначения не подтверждён.<button className="button secondary" disabled={busy} onClick={() => void assign('active')}>Повторить назначение</button></Notice>}
 {current.data && <><span className={`badge ${a?.state === 'active' ? 'good' : 'neutral'}`}>{a?.state === 'active' ? 'Набор назначен' : a ? 'Назначение снято' : 'Набор не назначен'}</span><div className="builder-actions">{a?.state === 'active' ? <><button className="button primary" disabled={busy || !!pending || !!current.error || current.loading} onClick={() => void link()}>Получить персональную ссылку</button><button className="button secondary" disabled={busy || !!pending || !!current.error || current.loading} onClick={() => setConfirm(true)}>Снять назначение</button></> : <button className="button primary" disabled={busy || !!pending || !!current.error || current.loading || current.data.detail.user.state !== 'active'} onClick={() => void assign('active')}>Назначить подписку</button>}</div>
 {a?.state === 'active' && <>{!current.data.detail.decision.allowed && current.data.detail.decision.reason !== 'no_eligible_device' && <p className="field-hint">Приглашение недоступно: {decisionReason(current.data.detail.decision.reason)}. Проверьте доступ в карточке пользователя.</p>}<DeviceInvite key={`${a.id}:${a.revision}`} api={api} assignment={a.id} generation={a.revision} intents={session} disabled={busy || !!current.error || current.loading || (!current.data.detail.decision.allowed && current.data.detail.decision.reason !== 'no_eligible_device')} /><p className="field-hint">После подключения телефона можно добавлять другие персональные ссылки этого аккаунта. Для старой сборки доступна ссылка зарегистрированного устройства.</p>{current.data.detail.devices.filter(d => d.state === 'registered').map(d => <div className="connection-row" key={d.id}><span className="connection-label">{d.name}</span><button className="button secondary small" disabled={busy || !d.decision.allowed || !!current.error || current.loading} onClick={() => void link(d.id)}>Ссылка для {d.name}</button></div>)}</>}
 {url && <div className="personal-link" data-private><label>{linkKind === 'a' ? 'Персональная ссылка набора' : 'Ссылка для текущего приложения'}<input readOnly value={url} onFocus={e => e.target.select()} /></label><div className="builder-actions"><button className="button secondary" onClick={() => { void navigator.clipboard.writeText(url).then(() => setCopied(true)).catch(() => setError(new ApiError('clipboard_unavailable'))) }}>{copied ? 'Скопировано' : 'Копировать ссылку'}</button><button className="button secondary" onClick={() => setURL('')}>Скрыть ссылку</button></div></div>}</>}
 {confirm && <Modal title="Снять назначение подписки?" close={() => { if (!busy) setConfirm(false) }}><p>Ссылка перестанет выдавать конфиги. Уже скачанные VPN-ключи этим действием не отзываются. Для полного отзыва используйте блокировку аккаунта или устройства.</p><div className="form-actions"><button className="button secondary" disabled={busy} onClick={() => setConfirm(false)}>Назад</button><button className="button primary" disabled={busy} onClick={() => void assign('revoked')}>Подтвердить снятие</button></div></Modal>}
 </section>
}
