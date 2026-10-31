import { useCallback, useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { ApiClient, ApiError } from './api'
import type { Page } from './api'
import { AccessIntents } from './accessIntent'
import type { AccessRequest } from './accessIntent'
import { accessGroups, accessUsers, blockReasons, decisionReason, entitlementStates, userDetail, userStates } from './accessApi'
import type { AccessGroup, AccessUser, Decision, Device, UserDetail } from './accessApi'
import { Empty, formatDate, Freshness, Icon, Notice, PageHeading } from './components'
import { useResource } from './useResource'
import { Modal } from './modal'
import { TrialVPN } from './trialVPN'

export function Users({ api, canWrite, intents }: { api: ApiClient; canWrite: boolean; intents: AccessIntents }) {
  const [selected, setSelected] = useState<string>()
  const [adding, setAdding] = useState(Boolean(intents.get('create')))
  const [cursors, setCursors] = useState<string[]>([])
  const [search, setSearch] = useState('')
  const cursor = cursors.at(-1)
  const load = useCallback(async (signal: AbortSignal) => accessUsers(await api.request<Page<AccessUser>>(`/access/users?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, { signal })), [api, cursor])
  const resource = useResource(load)
  const loadGroups = useCallback(async (signal: AbortSignal) => accessGroups(await api.request<{ items: AccessGroup[] }>('/access/groups', { signal })), [api])
  const groups = useResource(loadGroups)
  const visible = resource.data?.items.filter(u => u.name.toLocaleLowerCase().includes(search.toLocaleLowerCase()))
  return <><PageHeading eyebrow="ДОСТУП ПОЛЬЗОВАТЕЛЕЙ" title="Пользователи" action={canWrite && <button className="button primary" onClick={() => setAdding(!adding)}><Icon name="plus" size={17} />Добавить пользователя</button>}>Сроки, ограничения и устройства — независимо от состояния узлов.</PageHeading>
    {!canWrite && <Notice kind="info">Ваша роль позволяет просматривать доступ. Изменения доступны владельцу и оператору доступа.</Notice>}
    <div className="access-boundary"><Icon name="server" size={18} /><p><strong>Правила доступа и подтверждение узла разделены.</strong> Подключение и трафик доступны в карточке пользователя.</p></div>
    {adding && canWrite && <Modal title="Создать пользователя" close={() => setAdding(false)}><CreateUser api={api} intents={intents} done={id => { setAdding(false); setSelected(id); setCursors([]); resource.refresh() }} close={() => setAdding(false)} /></Modal>}
    <div className="access-layout"><aside className="card user-directory" aria-label="Список пользователей"><div className="directory-heading"><h2>Пользователи</h2><label className="search-label"><span className="sr-only">Найти на этой странице</span><input type="search" placeholder="Найти на этой странице" value={search} onChange={e => setSearch(e.target.value)} /></label><Freshness resource={resource} /></div>{resource.error != null && <Notice error={resource.error} />}
      {visible?.length ? <div className="user-list">{visible.map(user => <button className={`user-choice ${selected === user.id ? 'selected' : ''}`} aria-pressed={selected === user.id} key={user.id} onClick={() => setSelected(user.id)}><span className="user-initial" aria-hidden="true">{user.name.slice(0, 1).toUpperCase()}</span><span><strong>{user.name}</strong><small>{userStates[user.state]}</small></span><Icon name="arrow" size={15} /></button>)}</div> : resource.data ? <Empty icon="admins" title={search ? 'Совпадений нет' : 'Пользователей пока нет'}>{search ? 'Поиск работает по текущей странице.' : 'Создайте пользователя и задайте его право доступа.'}</Empty> : <Empty title={resource.loading ? 'Получаем пользователей' : 'Список недоступен'}>После успешного обновления здесь появятся данные.</Empty>}
      {(resource.data?.next_cursor || cursors.length > 0) && <div className="pagination"><button className="button secondary small" disabled={!cursors.length || resource.loading} onClick={() => setCursors(c => c.slice(0, -1))}>Назад</button><button className="button secondary small" disabled={!resource.data?.next_cursor || resource.loading} onClick={() => { if (resource.data?.next_cursor) setCursors(c => [...c, resource.data!.next_cursor!]) }}>Далее</button></div>}
    </aside><section className="user-workspace" aria-label="Карточка пользователя">{selected ? <UserDetails key={selected} api={api} id={selected} canWrite={canWrite} intents={intents} groups={groups.data?.items} groupsError={groups.error} retryGroups={groups.refresh} changed={resource.refresh} /> : <div className="card"><Empty icon="admins" title="Выберите пользователя">Откройте карточку, чтобы проверить условия доступа, блокировки и устройства.</Empty></div>}</section></div>
  </>
}

function useAccessMutation(api: ApiClient, intents: AccessIntents, scope: string, expectedID: string | undefined, done: (detail: UserDetail) => void) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const [success, setSuccess] = useState(false)
  const [, redraw] = useState(0)
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const submit = async (request?: AccessRequest) => {
    if (busy) return
    const pending = intents.get(scope)
    if (!pending && !request) return
    const intent = pending ?? intents.begin(scope, request!)
    setBusy(true); setError(undefined); setSuccess(false)
    try {
      const detail = userDetail(await api.request<UserDetail>(intent.path, { method: intent.method, body: intent.body, headers: { 'Idempotency-Key': intent.key, ...(intent.revision == null ? {} : { 'If-Match': `"${intent.revision}"` }) } }), expectedID)
      intents.finish(scope, intent.key)
      if (alive.current) { setSuccess(true); done(detail) }
    } catch (error) {
      intents.failed(scope, intent.key, error)
      if (alive.current) setError(error)
    } finally { if (alive.current) { setBusy(false); redraw(n => n + 1) } }
  }
  return { busy, error, success, pending: intents.get(scope), submit }
}

function MutationNotice({ mutation }: { mutation: ReturnType<typeof useAccessMutation> }) {
  return <>{mutation.error != null && <Notice error={mutation.error} />}{mutation.pending && <Notice kind="info"><p>{mutation.pending.unknown ? 'Исход изменения пока неизвестен. Повтор проверит то же действие для этого пользователя.' : 'Запрос ожидает повторной отправки. Сохраняются исходные условия изменения.'}</p><p className="pending-description">{mutation.pending.label}</p><button className="button secondary small" disabled={mutation.busy} onClick={() => void mutation.submit()}>{mutation.busy ? 'Отправляем…' : 'Повторить изменение'}</button></Notice>}{mutation.success && <Notice kind="success">Изменение сохранено в панели. Применение на узлах не подтверждено.</Notice>}</>
}

function CreateUser({ api, intents, done, close }: { api: ApiClient; intents: AccessIntents; done: (id: string) => void; close: () => void }) {
  const previous = intents.get('create')?.body as { name?: string } | undefined
  const [name, setName] = useState(previous?.name ?? '')
  const mutation = useAccessMutation(api, intents, 'create', undefined, data => done(data.user.id))
  const locked = mutation.busy || Boolean(mutation.pending)
  return <section className="card form-card"><MutationNotice mutation={mutation} /><form className="create-user-form" onSubmit={event => { event.preventDefault(); if (!locked) void mutation.submit({ path: '/access/users', method: 'POST', body: { name: name.trim() }, label: `Создать пользователя «${name.trim()}»` }) }}><label>Имя пользователя VPN<input value={name} onChange={e => setName(e.target.value)} required maxLength={80} minLength={2} autoComplete="off" disabled={locked} /></label><div className="form-actions"><button className="button secondary" type="button" onClick={close}>Закрыть</button><button className="button primary" disabled={locked || !name.trim()}>Создать пользователя</button></div></form></section>
}

type EditorRequest = { kind: 'entitlement'; action: 'set' | 'renew' | 'restore' } | { kind: 'block'; device?: Device } | { kind: 'confirm'; title: string; explanation: string; path: string; body: unknown }
type Editor = EditorRequest & { snapshot: UserDetail }

function UserDetails({ api, id, canWrite, intents, groups, groupsError, retryGroups, changed }: { api: ApiClient; id: string; canWrite: boolean; intents: AccessIntents; groups?: AccessGroup[]; groupsError?: unknown; retryGroups: () => void; changed: () => void }) {
  const load = useCallback(async (signal: AbortSignal) => userDetail(await api.request<UserDetail>(`/access/users/${encodeURIComponent(id)}`, { signal }), id), [api, id])
  const resource = useResource(load, 15_000)
  const [editor, setEditor] = useState<Editor>()
  const editorRef = useRef<HTMLElement>(null)
  useEffect(() => {
    if (editor) { editorRef.current?.focus({ preventScroll: true }); editorRef.current?.scrollIntoView?.({ block: 'start' }) }
  }, [editor])
  const mutation = useAccessMutation(api, intents, id, id, () => { setEditor(undefined); resource.refresh(); changed() })
  const data = resource.data
  const [, tick] = useState(0)
  const invalidatedExpiry = useRef<number | undefined>(undefined)
  const expiry = data?.entitlement ? Date.parse(data.entitlement.expires_at) : undefined
  const deadlinePassed = expiry !== undefined && expiry <= Date.now()
  useEffect(() => {
    if (expiry === undefined || data?.entitlement?.state !== 'active') return
    const invalidate = () => {
      tick(n => n + 1)
      if (invalidatedExpiry.current !== expiry) { invalidatedExpiry.current = expiry; resource.refresh() }
    }
    if (expiry <= Date.now()) { if (invalidatedExpiry.current !== expiry) invalidate(); return }
    if (expiry - Date.now() >= 2_147_483_647) return
    const timer = setTimeout(invalidate, expiry - Date.now() + 1)
    return () => clearTimeout(timer)
  }, [expiry, data?.entitlement?.state, resource.updatedAt, resource.refresh])
  // Do not permit changes from a stale snapshot or while another intent is unresolved.
  const locked = mutation.busy || Boolean(mutation.pending) || resource.loading || resource.error != null
  const submit = (suffix: string, body: unknown, label: string) => {
    if (!data || locked) return
    void mutation.submit({ path: `/access/users/${encodeURIComponent(id)}${suffix}`, method: 'POST', body, revision: editor?.snapshot.user.revision ?? data.user.revision, label })
  }
  if (!data) return <div className="card detail-loading"><Freshness resource={resource} />{resource.error != null && <Notice error={resource.error} />}<Empty title={resource.loading ? 'Открываем карточку' : 'Карточка недоступна'}>Изменения станут доступны после успешного ответа сервера.</Empty></div>
  const terminal = data.entitlement?.state === 'revoked' || data.entitlement?.state === 'refunded'
  const activeBlocks = data.blocks.filter(b => b.active)
  const group = groups?.find(g => g.id === data.entitlement?.group_id)
  const mayIssueCredential = data.user.state === 'active' && data.entitlement?.state === 'active' && Date.parse(data.entitlement.expires_at) > Date.now() && data.entitlement.quota_bytes === null && group?.enabled === true && !activeBlocks.some(b => b.scope === 'user')
  const openEditor = (request: EditorRequest) => setEditor({ ...request, snapshot: structuredClone(data) })
  const confirm = (title: string, explanation: string, path: string, body: unknown = {}) => openEditor({ kind: 'confirm', title, explanation, path, body })
  return <><header className="detail-header"><div><h2>{data.user.name}</h2><span className={`badge ${data.user.state === 'active' ? 'neutral' : 'pending'}`}>{userStates[data.user.state]}</span></div><span className="revision-note">Версия {data.user.revision}</span></header><Freshness resource={resource} />{resource.error != null && <Notice error={resource.error} />}<MutationNotice mutation={mutation} />
    <section className="card access-decision" aria-label="Решение о доступе"><div className="decision-top"><Icon name="lock" size={22} /><div><h3>По правилам панели</h3><DecisionBadge decision={data.decision} expired={deadlinePassed} /></div></div><p>{deadlinePassed && data.decision.allowed ? 'Срок по последним данным истёк. Проверяем актуальное разрешение.' : decisionReason(data.decision.reason)}</p><p className="field-hint">Решение получено {formatDate(resource.updatedAt)}</p><div className="node-status"><span>Применение на узлах</span><strong>Смотрите выбранный VPN-узел ниже</strong></div><p className="field-hint">{data.outbox_pending > 0 ? `Изменения в общей очереди доступа: ${data.outbox_pending}.` : 'Нет подтверждения от VPN-узлов.'}</p></section>
    {canWrite && editor && <section ref={editorRef} tabIndex={-1} className="card form-card access-editor"><h2>{editor.kind === 'entitlement' ? editor.action === 'restore' ? 'Восстановить право доступа' : editor.action === 'renew' ? 'Продлить право доступа' : 'Условия права доступа' : editor.kind === 'block' ? editor.device ? `Блокировка: ${editor.device.name}` : 'Блокировка пользователя' : editor.title}</h2>{editor.snapshot.user.revision !== data.user.revision && <Notice kind="info">Запись изменилась после открытия формы. Введённые условия сохранены; проверка исходной версии не позволит перезаписать чужие изменения. Закройте и откройте форму заново для актуальных условий.</Notice>}{editor.kind === 'entitlement' ? <EntitlementForm key={editor.action} action={editor.action} data={editor.snapshot} groups={groups} groupsError={groupsError} retryGroups={retryGroups} locked={locked} close={() => setEditor(undefined)} submit={body => submit('/entitlement', body, editor.action === 'restore' ? 'Восстановить право доступа' : editor.action === 'renew' ? 'Продлить право доступа' : 'Изменить условия доступа')} /> : editor.kind === 'block' ? <BlockForm locked={locked} close={() => setEditor(undefined)} submit={reason => submit('/blocks', { scope: editor.device ? 'device' : 'user', ...(editor.device ? { device_id: editor.device.id } : {}), reason }, editor.device ? `Заблокировать устройство «${editor.device.name}»` : 'Заблокировать пользователя')} /> : <><p className="editor-explanation">{editor.explanation}</p><div className="form-actions"><button className="button secondary" onClick={() => setEditor(undefined)}>Отмена</button><button className="button primary" disabled={locked} onClick={() => submit(editor.path, editor.body, editor.title)}>Подтвердить действие</button></div></>}</section>}
    <section className="card access-section" aria-label="Право доступа"><div className="access-section-heading"><h3>Право доступа</h3>{data.entitlement && <span className={`badge ${terminal ? 'bad' : data.entitlement.state === 'expired' ? 'pending' : 'neutral'}`}>{entitlementStates[deadlinePassed && data.entitlement.state === 'active' ? 'expired' : data.entitlement.state]}</span>}</div>{data.entitlement ? <dl className="access-facts"><div><dt>Срок до</dt><dd>{new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' }).format(new Date(data.entitlement.expires_at))}</dd></div><div><dt>Лимит устройств</dt><dd>{data.entitlement.device_limit}</dd></div><div><dt>Группа</dt><dd>{group?.name ?? 'Нет данных о группе'}</dd></div><div><dt>Трафик</dt><dd>{data.entitlement.quota_bytes === null ? 'Без ограничений' : `${(data.entitlement.quota_bytes / 1073741824).toLocaleString('ru-RU')} ГиБ · расход неизвестен`}</dd></div></dl> : <p className="section-description">Право доступа ещё не выдано.</p>}{canWrite && <div className="access-actions">{!terminal && <button className="button secondary small" disabled={locked} onClick={() => openEditor({ kind: 'entitlement', action: 'set' })}>{data.entitlement ? 'Изменить условия' : 'Выдать доступ'}</button>}{data.entitlement && !terminal && <><button className="button secondary small" disabled={locked} onClick={() => openEditor({ kind: 'entitlement', action: 'renew' })}>Продлить</button><button className="button ghost small danger-text" disabled={locked} onClick={() => confirm('Отозвать право доступа', 'Право станет недействующим. Продление не восстановит его автоматически. Действующие блокировки сохранятся.', '/entitlement', { action: 'revoke' })}>Отозвать право</button><button className="button ghost small danger-text" disabled={locked} onClick={() => confirm('Отметить возврат', 'Будет сохранён факт возврата по праву доступа и запрещён доступ. Денежный платёж эта панель не возвращает.', '/entitlement', { action: 'refund' })}>Отметить возврат</button></>}{terminal && <button className="button secondary small" disabled={locked} onClick={() => openEditor({ kind: 'entitlement', action: 'restore' })}>Восстановить право</button>}</div>}</section>
    <section className="card access-section" aria-label="Блокировки"><div className="access-section-heading"><h3>Блокировки</h3>{canWrite && <button className="button secondary small" disabled={locked} onClick={() => openEditor({ kind: 'block' })}>Заблокировать пользователя</button>}</div><p className="section-description">Продление или восстановление права не снимает блокировку.</p>{activeBlocks.length ? <div className="block-list">{activeBlocks.map(block => <div className="block-row" key={block.id}><div><strong>{block.scope === 'user' ? 'Пользователь' : data.devices.find(d => d.id === block.device_id)?.name ?? 'Устройство'}</strong><span>{blockReasons[block.reason] ?? 'Причина требует проверки'}</span></div>{canWrite && <button className="button secondary small" disabled={locked} onClick={() => confirm('Снять блокировку', 'Снимается только выбранная блокировка. Срок, состояние права и другие ограничения проверяются отдельно.', `/blocks/${encodeURIComponent(block.id)}/clear`)}>Снять блокировку</button>}</div>)}</div> : <p className="empty-inline">Активных блокировок нет.</p>}</section>
    <section className="card access-section" aria-label="Устройства"><div className="access-section-heading"><h3>Устройства</h3><span className="section-caption">{data.devices.filter(d => d.state === 'registered').length} зарегистрировано</span></div><p className="section-description">Установка регистрируется клиентом после подтверждения своего ключа. Панель показывает подтверждённые устройства.</p>{data.devices.length ? <div className="device-list">{data.devices.map(device => <article className="device-card" key={device.id} aria-label={`Устройство ${device.name}`}><div className="device-heading"><strong>{device.name}</strong><span className={`badge ${device.state === 'revoked' ? 'bad' : 'neutral'}`}>{device.state === 'revoked' ? 'Отозвано' : 'Зарегистрировано'}</span></div><DecisionBadge decision={device.decision} expired={deadlinePassed} /><p className="section-description">{deadlinePassed && device.decision.allowed ? 'Срок по последним данным истёк. Проверяем актуальное разрешение.' : decisionReason(device.decision.reason)}</p><p className="credential-note">{device.credential ? `Ключ доступа · версия ${device.credential.version} · ${device.credential.state === 'active' ? 'действует в панели' : 'отозван'}` : 'Ключ доступа отсутствует'}</p><p className="field-hint">Подтверждение выбранного узла — в разделе подключения.</p>{canWrite && device.state === 'registered' && <div className="access-actions"><button className="button secondary small" disabled={locked} onClick={() => openEditor({ kind: 'block', device })}>Заблокировать устройство</button><button className="button secondary small" disabled={locked || !mayIssueCredential || activeBlocks.some(b => b.scope === 'device' && b.device_id === device.id)} onClick={() => confirm('Обновить ключ устройства', 'Будет создана новая версия внутреннего ключа доступа. Это не выдача VPN-конфига. Блокировки и ограничения сохранятся.', `/devices/${encodeURIComponent(device.id)}/rotate`)}>Обновить ключ</button><button className="button ghost small danger-text" disabled={locked} onClick={() => confirm('Отозвать устройство', 'Устройство и его ключ будут отозваны. Продление права или снятие блокировки не восстановит это устройство.', `/devices/${encodeURIComponent(device.id)}/revoke`)}>Отозвать устройство</button></div>}</article>)}</div> : <p className="empty-inline">Устройства ещё не зарегистрированы.</p>}</section>
    <details className="card access-section"><summary>Техническая проверка VPN</summary><p className="section-description">Создание синтетического устройства для оператора. Для телефона тестера используйте обычную регистрацию в приложении.</p><TrialVPN api={api} detail={data} intents={intents} canWrite={canWrite} changed={() => { resource.refresh(); changed() }} /></details>
    {canWrite && <section className="card access-section"><h3>Состояние пользователя</h3><p className="section-description">Приостановка и удаление независимы от срока и блокировок.</p><div className="access-actions">{data.user.state === 'active' && <button className="button secondary small" disabled={locked} onClick={() => confirm('Приостановить пользователя', 'Право доступа сохранится, но доступ по правилам панели будет запрещён.', '/state', { state: 'suspended' })}>Приостановить</button>}{data.user.state === 'suspended' && <button className="button secondary small" disabled={locked} onClick={() => confirm('Возобновить пользователя', 'Пользователь станет активным. Доступ останется зависеть от срока, устройств и блокировок.', '/state', { state: 'active' })}>Возобновить</button>}{data.user.state !== 'deleted' && <button className="button ghost small danger-text" disabled={locked} onClick={() => confirm('Удалить пользователя', 'Будет сохранено логическое удаление. История останется в учёте, устройства и ключи будут отозваны, доступ будет запрещён. Удаление нельзя отменить.', '/state', { state: 'deleted' })}>Удалить пользователя</button>}</div></section>}
  </>
}

function DecisionBadge({ decision, expired = false }: { decision: Decision; expired?: boolean }) {
  if (expired && decision.allowed) return <span className="badge pending">Нет актуального разрешения</span>
  return <span className={`badge ${decision.allowed ? 'good' : 'bad'}`}>{decision.allowed ? 'Разрешено по правилам' : 'Запрещено по правилам'}</span>
}
function dateInput(value: string) { const date = new Date(value); return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16) }
function EntitlementForm({ action, data, groups, groupsError, retryGroups, locked, close, submit }: { action: 'set' | 'renew' | 'restore'; data: UserDetail; groups?: AccessGroup[]; groupsError?: unknown; retryGroups: () => void; locked: boolean; close: () => void; submit: (body: unknown) => void }) {
  const [expires, setExpires] = useState(dateInput(action === 'renew' ? new Date(Math.max(Date.now(), new Date(data.entitlement?.expires_at ?? 0).getTime()) + 30 * 86400000).toISOString() : data.entitlement?.expires_at && new Date(data.entitlement.expires_at).getTime() > Date.now() ? data.entitlement.expires_at : new Date(Date.now() + 30 * 86400000).toISOString()))
  const [limit, setLimit] = useState(data.entitlement?.device_limit ?? 1)
  const [groupID, setGroupID] = useState(data.entitlement?.group_id ?? groups?.find(g => g.enabled)?.id ?? '')
  const [quota, setQuota] = useState(data.entitlement?.quota_bytes == null ? '' : String(data.entitlement.quota_bytes / 1073741824))
  const [error, setError] = useState<unknown>()
  const validGroup = groups?.some(g => g.id === groupID && g.enabled)
  const save = (event: FormEvent) => {
    event.preventDefault(); if (locked) return
    try {
      const expiry = new Date(expires)
      if (!Number.isFinite(expiry.getTime()) || expiry.getTime() <= Date.now() || action === 'renew' && expiry.getTime() <= new Date(data.entitlement!.expires_at).getTime()) throw new ApiError('invalid_request', 400)
      const body: Record<string, unknown> = { action, expires_at: expiry.toISOString() }
      if (action !== 'renew') {
        if (!validGroup || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new ApiError('invalid_request', 400)
        Object.assign(body, { device_limit: limit, group_id: groupID })
        if (quota !== '') { const bytes = Number(quota) * 1073741824; if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > 1000000000000000) throw new ApiError('invalid_request', 400); body.quota_bytes = bytes }
      }
      setError(undefined); submit(body)
    } catch (error) { setError(error) }
  }
  return <form className="entitlement-form" onSubmit={save}>{error != null && <Notice error={error} />}{action === 'restore' && <Notice kind="info">Восстановление выдаёт новое действующее право. Блокировки и отозванные устройства остаются в силе.</Notice>}<div className="duration-field"><label>Срок доступа до<input type="datetime-local" value={expires} onChange={e => setExpires(e.target.value)} required disabled={locked} /></label><span className="duration-presets">{[7, 30, 90].map(days => <button key={days} type="button" className="button secondary small" disabled={locked} onClick={() => setExpires(dateInput(new Date((action === 'renew' ? Math.max(Date.now(), Date.parse(data.entitlement!.expires_at)) : Date.now()) + days * 86400000).toISOString()))}>{days} дней</button>)}</span><span className="field-hint">Часовой пояс браузера. Повтор сохраняет этот же срок.</span></div>{action !== 'renew' && <><label>Лимит устройств<input type="number" min={1} max={100} value={limit} onChange={e => setLimit(Number(e.target.value))} required disabled={locked} /></label><label>Группа доступа<select value={groupID} onChange={e => setGroupID(e.target.value)} required disabled={locked || groupsError != null}><option value="">Выберите группу</option>{groups?.map(g => <option value={g.id} disabled={!g.enabled} key={g.id}>{g.name}{g.enabled ? '' : ' · отключена'}</option>)}</select></label>{groupsError != null && <><Notice error={groupsError} /><button type="button" className="button secondary small" onClick={retryGroups}>Обновить группы</button></>}<label>Квота трафика, ГиБ<input type="number" min={1} step={1} value={quota} onChange={e => setQuota(e.target.value)} placeholder="Без ограничений" disabled={locked} /><span className="field-hint">Пустое поле — без ограничений. При заданной квоте доступ запрещён, пока расход неизвестен.</span></label></>}<div className="form-actions"><button type="button" className="button secondary" onClick={close}>Отмена</button><button className="button primary" disabled={locked || action !== 'renew' && (!validGroup || groupsError != null)}>Сохранить право</button></div></form>
}
function BlockForm({ locked, close, submit }: { locked: boolean; close: () => void; submit: (reason: string) => void }) {
  const [reason, setReason] = useState('manual')
  return <form onSubmit={event => { event.preventDefault(); if (!locked) submit(reason) }}><label>Причина блокировки<select value={reason} onChange={e => setReason(e.target.value)} disabled={locked}>{Object.entries(blockReasons).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label><div className="form-actions"><button type="button" className="button secondary" onClick={close}>Отмена</button><button className="button primary" disabled={locked}>Сохранить блокировку</button></div></form>
}
