import { useCallback, useState } from 'react'
import { ApiClient, ApiError, OperationIntent, roles, safeError, validateNewPassword } from './api'
import type { Admin, AuditItem, Operation, Overview, Page, Role, User } from './api'
import { Empty, formatDate, Freshness, Icon, Notice, PageHeading, StateBadge } from './components'
import { useResource } from './useResource'

function overviewResponse(value: Overview) {
  if (!value || typeof value.service_status !== 'string' || typeof value.database_status !== 'string' || !['not_configured', 'per_node'].includes(value.vpn_status) || !value.counts || Object.values(value.counts).some(n => !Number.isSafeInteger(n) || n < 0) || ['admins', 'jobs_pending', 'jobs_failed'].some(k => !(k in value.counts))) throw new ApiError('invalid_response')
  return value
}

function pageResponse<T extends { id: string }>(value: Page<T>): Page<T> {
  if (!value || !Array.isArray(value.items) || value.items.some(i => !i || typeof i.id !== 'string') || value.next_cursor != null && typeof value.next_cursor !== 'string') throw new ApiError('invalid_response')
  return value
}

export function OverviewPage({ api, openOperations, quickActions = [] }: { api: ApiClient; openOperations: () => void; quickActions?: { id: string; title: string; description: string; onClick: () => void }[] }) {
  const load = useCallback(async (signal: AbortSignal) => overviewResponse(await api.request<Overview>('/overview', { signal })), [api])
  const resource = useResource(load, 15_000)
  const data = resource.data
  return <><PageHeading eyebrow="ВАША УСТАНОВКА" title="Обзор панели">Состояние системы и работа команды в одном месте.</PageHeading><Freshness resource={resource} />{resource.error != null && <Notice error={resource.error} />}
    <section className="summary-grid" aria-label="Показатели панели">{[{ label: 'Администраторы', value: data?.counts.admins, icon: 'admins', note: 'Аккаунты команды' }, { label: 'В работе', value: data?.counts.jobs_pending, icon: 'clock', note: 'Ожидают или выполняются' }, { label: 'С ошибкой', value: data?.counts.jobs_failed, icon: 'operations', note: 'Требуют внимания' }].map(item => <article className="metric card" key={item.label}><div className="metric-label">{item.label}<Icon name={item.icon} size={18} /></div><strong>{item.value == null ? '—' : item.value.toLocaleString('ru-RU')}</strong><p>{item.note}</p></article>)}</section>
    <div className="overview-columns"><section className="card system-card"><div className="section-heading"><h2>Система</h2><span className="section-caption">Состояние компонентов</span></div><div className="system-row"><span className="system-icon"><Icon name="layers" /></span><div><strong>Служба панели</strong><p>Управление и доступ к данным</p></div><StateBadge state={data?.service_status ?? 'unknown'} /></div><div className="system-row"><span className="system-icon"><Icon name="server" /></span><div><strong>База данных</strong><p>Аккаунты, операции и журнал</p></div><StateBadge state={data?.database_status ?? 'unknown'} /></div><button className="card-action" onClick={openOperations}>Открыть операции<Icon name="arrow" size={18} /></button></section>
    <section className="card next-card"><h2>Что хотите сделать?</h2><p>Выберите задачу — откроем нужный раздел.</p><div className="quick-actions">{quickActions.map(action => <button className="quick-action" key={action.id} onClick={action.onClick}><span><strong>{action.title}</strong><small>{action.description}</small></span><Icon name="arrow" size={18} /></button>)}</div>{quickActions.length === 0 && <p>Разделы доступны в меню панели.</p>}</section></div>

  </>
}

function Pagination({ next, previous, onNext, onPrevious, loading }: { next?: string | null; previous: boolean; onNext: () => void; onPrevious: () => void; loading: boolean }) {
  if (!next && !previous) return null
  return <div className="pagination"><button className="button secondary small" disabled={!previous || loading} onClick={onPrevious}>Более новые</button><button className="button secondary small" disabled={!next || loading} onClick={onNext}>Более ранние</button></div>
}

function usePages<T extends { id: string }>(api: ApiClient, path: string, poll = 0) {
  const [cursors, setCursors] = useState<string[]>([])
  const cursor = cursors.at(-1)
  const load = useCallback(async (signal: AbortSignal) => pageResponse(await api.request<Page<T>>(`${path}?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, { signal })), [api, path, cursor])
  const resource = useResource(load, poll)
  const pagination = <Pagination next={resource.data?.next_cursor} previous={cursors.length > 0} loading={resource.loading} onNext={() => { const next = resource.data?.next_cursor; if (next) setCursors(c => [...c, next]) }} onPrevious={() => setCursors(c => c.slice(0, -1))} />
  return { resource, pagination }
}

export function Operations({ api, canCreate, intent }: { api: ApiClient; canCreate: boolean; intent: OperationIntent }) {
  const { resource, pagination } = usePages<Operation>(api, '/operations', 5_000)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const [uncertain, setUncertain] = useState(intent.outcomeUnknown)
  const [created, setCreated] = useState(false)
  const create = async () => {
    if (busy) return
    setBusy(true); setError(undefined); setCreated(false)
    const key = intent.key()
    try {
      const job = await api.request<Operation>('/operations', { method: 'POST', body: { kind: 'system.check' }, headers: { 'Idempotency-Key': key } })
      if (!job || typeof job.id !== 'string' || typeof job.status !== 'string') throw new ApiError('invalid_response')
      intent.finish(key); setUncertain(intent.outcomeUnknown); setCreated(true); resource.refresh()
    } catch (error) {
      intent.failed(key, !(error instanceof ApiError) || error.outcomeUnknown)
      setUncertain(intent.outcomeUnknown); setError(error)
    } finally { setBusy(false) }
  }
  return <><PageHeading eyebrow="ВЫПОЛНЕНИЕ ЗАДАЧ" title="Операции" action={canCreate && <button className="button primary" onClick={() => void create()} disabled={busy}><Icon name="operations" size={17} />{busy ? 'Отправляем…' : intent.uncertain ? 'Повторить запрос' : 'Проверить систему'}</button>}>Задачи панели, их состояние и результат выполнения.</PageHeading>
    {error != null && <Notice error={error} />}{uncertain && !busy && <Notice kind="info">Исход запроса пока неизвестен. Повторная отправка проверит ту же операцию.</Notice>}{created && <Notice kind="success">Запрос принят. Результат появится в списке операций.</Notice>}<Freshness resource={resource} />{resource.error != null && <Notice error={resource.error} />}
    <section className="card table-card" aria-label="Список операций">{resource.data?.items.length ? <div className="table-scroll"><table><thead><tr><th>Операция</th><th>Состояние</th><th>Создана</th><th>Подробности</th></tr></thead><tbody>{resource.data.items.map(job => <tr key={job.id}><td><strong>{job.kind === 'system.check' ? 'Проверка системы' : 'Системная операция'}</strong><span className="table-sub id-label">{job.id}</span></td><td><StateBadge state={job.status} /></td><td className="nowrap">{formatDate(job.created_at)}</td><td>{job.error_code ? <span className="inline-error">{safeError(new ApiError(job.error_code))}</span> : job.status === 'succeeded' ? 'Проверка завершена' : job.status === 'running' ? 'Панель выполняет задачу' : job.status === 'pending' ? 'Ожидает обработки' : 'Нет подробностей'}{job.attempts != null && <span className="table-sub">Попытки: {job.attempts}{job.max_attempts != null ? ` из ${job.max_attempts}` : ''}</span>}</td></tr>)}</tbody></table></div> : resource.data ? <Empty icon="operations" title="Операций пока нет">{canCreate ? 'Запустите проверку системы — её состояние и результат появятся здесь.' : 'Здесь появятся задачи, запущенные командой.'}</Empty> : <Empty icon="clock" title={resource.loading ? 'Получаем операции' : 'Данные недоступны'}>История появится после успешного ответа сервера.</Empty>}{pagination}</section>
    <p className="section-footnote">Проверка системы проверяет работу базы данных панели. Она не проверяет VPN-подключение.</p>
  </>
}

export function Admins({ api, currentUser, onSelfChanged }: { api: ApiClient; currentUser: User; onSelfChanged?: () => void }) {
  const load = useCallback(async (signal: AbortSignal) => pageResponse(await api.request<Page<Admin>>('/admins', { signal })), [api])
  const resource = useResource(load)
  const [adding, setAdding] = useState(false)
  return <><PageHeading eyebrow="УПРАВЛЕНИЕ КОМАНДОЙ" title="Администраторы" action={<button className="button primary" onClick={() => setAdding(!adding)}><Icon name="plus" size={17} />Добавить аккаунт</button>}>Назначайте роли и управляйте доступом к панели.</PageHeading>{adding && <CreateAdmin api={api} done={() => { setAdding(false); resource.refresh() }} close={() => setAdding(false)} />}<Freshness resource={resource} />{resource.error != null && <Notice error={resource.error} />}
    <section className="card table-card" aria-label="Список администраторов">{resource.data?.items.length ? <div className="table-scroll"><table className="admins-table"><thead><tr><th>Аккаунт</th><th>Роль</th><th>Доступ</th><th>Изменения</th></tr></thead><tbody>{resource.data.items.map(admin => <AdminRow key={`${admin.id}:${admin.revision}`} api={api} admin={admin} own={admin.id === currentUser.id} refresh={resource.refresh} onSelfChanged={onSelfChanged} />)}</tbody></table></div> : <Empty icon="admins" title={resource.loading ? 'Получаем аккаунты' : 'Нет данных об аккаунтах'}>Список будет доступен после ответа сервера.</Empty>}</section><p className="section-footnote">Изменения проверяются по версии записи. Системная защита не позволяет удалить доступ последнего владельца.</p>
  </>
}

function RoleSelect({ value, onChange, disabled, label }: { value: Role; onChange: (r: Role) => void; disabled?: boolean; label: string }) {
  return <select aria-label={label} value={value} onChange={e => onChange(e.target.value as Role)} disabled={disabled}>{Object.entries(roles).map(([value, title]) => <option value={value} key={value}>{title}</option>)}</select>
}

function CreateAdmin({ api, done, close }: { api: ApiClient; done: () => void; close: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Role>('support')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  return <section className="card form-card"><h2>Новый аккаунт</h2>{error != null && <Notice error={error} />}<form className="admin-form" onSubmit={async e => {
    e.preventDefault(); if (busy) return; setBusy(true); setError(undefined)
    try { validateNewPassword(password); await api.request('/admins', { method: 'POST', body: { username: username.trim(), password, role } }); setPassword(''); done() }
    catch (error) { setError(error) } finally { setBusy(false) }
  }}><label>Имя пользователя<input autoFocus value={username} onChange={e => setUsername(e.target.value)} autoComplete="off" autoCapitalize="none" pattern="[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}" minLength={3} maxLength={64} required disabled={busy} /></label><label>Пароль<input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="new-password" minLength={12} maxLength={128} required disabled={busy} /><span className="field-hint">Не менее 12 символов</span></label><label>Роль<RoleSelect value={role} onChange={setRole} disabled={busy} label="Роль нового аккаунта" /></label><div className="form-actions"><button type="button" className="button secondary" disabled={busy} onClick={close}>Отмена</button><button className="button primary" disabled={busy}>{busy ? 'Создаём…' : 'Создать аккаунт'}</button></div></form></section>
}

function AdminRow({ api, admin, own, refresh, onSelfChanged }: { api: ApiClient; admin: Admin; own: boolean; refresh: () => void; onSelfChanged?: () => void }) {
  const [role, setRole] = useState(admin.role)
  const [disabled, setDisabled] = useState(admin.disabled)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const changed = role !== admin.role || disabled !== admin.disabled
  return <tr><td><strong>{admin.username}{own && <span className="you">Вы</span>}</strong><span className="table-sub">Добавлен {formatDate(admin.created_at)}</span></td><td><RoleSelect value={role} onChange={setRole} disabled={busy} label={`Роль для ${admin.username}`} /></td><td><label className="checkbox-label"><input type="checkbox" checked={!disabled} onChange={e => setDisabled(!e.target.checked)} disabled={busy} aria-label={`Доступ для ${admin.username}`} /><span>{disabled ? 'Отключён' : 'Разрешён'}</span></label></td><td><button className="button secondary small" disabled={!changed || busy} onClick={async () => {
    if (busy) return; setBusy(true); setError(undefined)
    try { await api.request(`/admins/${encodeURIComponent(admin.id)}`, { method: 'PATCH', body: { role, disabled }, headers: { 'If-Match': `"${admin.revision}"` } }); if (own) onSelfChanged?.(); else refresh() }
    catch (error) { setError(error) } finally { setBusy(false) }
  }}>{busy ? 'Сохраняем…' : 'Сохранить'}</button>{error != null && <div role="alert" className="row-error">{safeError(error)}</div>}</td></tr>
}

const auditActions: Record<string, string> = {
  'node.certificate_renewed': 'Продлён сертификат узла', 'node.created': 'Создан узел', 'node.enrollment_created': 'Создан файл подключения узла', 'node.enrolled': 'Подключён агент узла', 'node.revoked': 'Отозван доступ узла', 'node.command_created': 'Отправлена настройка агента', 'node.command_recorded': 'Получен результат настройки агента',
  'node.vpn_configured': 'Изменена настройка VPN', 'node.vpn_policy_issued': 'Выдано разрешение движку', 'access.vpn_config_exported': 'Скачан личный VPN-конфиг',
  'access.user_created': 'Создан пользователь VPN', 'access.user_state': 'Изменено состояние пользователя', 'access.entitlement_changed': 'Изменено право доступа', 'access.block_added': 'Добавлена блокировка', 'access.block_cleared': 'Снята блокировка', 'access.challenge_created': 'Запрошено подтверждение устройства', 'access.device_registered': 'Зарегистрировано устройство', 'access.device_revoked': 'Отозвано устройство', 'access.credential_rotated': 'Обновлён ключ устройства', 'access.entitlement_expired': 'Истёк срок права доступа',
  'job.enqueued': 'Операция поставлена в очередь', 'job.succeeded': 'Операция завершена', 'job.retry_scheduled': 'Назначена повторная попытка', 'job.failed': 'Операция завершилась ошибкой',
  'identity.bootstrap_prepared': 'Подготовлена первоначальная настройка', 'identity.bootstrap_completed': 'Создан первый владелец', 'identity.login_succeeded': 'Вход в панель', 'identity.login_failed': 'Неудачная попытка входа', 'identity.logout': 'Выход из панели', 'identity.admin_created': 'Создан аккаунт', 'identity.admin_updated': 'Изменён аккаунт', 'identity.sessions_revoked': 'Завершены сессии',
}
export function Audit({ api }: { api: ApiClient }) {
  const { resource, pagination } = usePages<AuditItem>(api, '/audit', 15_000)
  return <><PageHeading eyebrow="ИСТОРИЯ ИЗМЕНЕНИЙ" title="Журнал действий">Кто и когда изменил настройки или запустил операцию.</PageHeading><Freshness resource={resource} />{resource.error != null && <Notice error={resource.error} />}<section className="card table-card" aria-label="Журнал действий">{resource.data?.items.length ? <div className="table-scroll"><table><thead><tr><th>Действие</th><th>Инициатор</th><th>Результат</th><th>Время</th></tr></thead><tbody>{resource.data.items.map(item => <tr key={item.id}><td><strong>{auditActions[item.action] ?? 'Действие с аккаунтом'}</strong>{item.target_id && <span className="table-sub id-label">Объект: {item.target_id}</span>}</td><td className="id-label">{item.actor_id === 'system' ? 'Система' : item.actor_id === 'worker' ? 'Обработчик задач' : item.actor_id === 'anonymous' ? 'До входа' : item.actor_id ?? 'Нет данных'}</td><td><StateBadge state={item.outcome ?? 'unknown'} /></td><td className="nowrap">{formatDate(item.created_at)}</td></tr>)}</tbody></table></div> : resource.data ? <Empty icon="audit" title="Журнал пока пуст">Здесь будут появляться действия команды и результаты операций.</Empty> : <Empty icon="clock" title={resource.loading ? 'Получаем журнал' : 'Журнал недоступен'}>Попробуйте обновить данные.</Empty>}{pagination}</section></>
}
