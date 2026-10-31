import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiClient, ApiError } from './api'
import type { Page } from './api'
import type { AccessRequest } from './accessIntent'
import { NodeIntents } from './nodeIntent'
import { command, contact, control, enrollment, node, nodesPage, receiptErrors } from './nodeApi'
import type { Control, Enrollment, Node, SignedCommand } from './nodeApi'
import { Empty, formatDate, Freshness, Icon, Notice, PageHeading } from './components'
import { useResource } from './useResource'
import { Modal } from './modal'
import { NodeVPN } from './vpn'

function useNow() {
  const [now, setNow] = useState(Date.now)
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer) }, [])
  return now
}
function Contact({ value, now, stale }: { value: Node; now: number; stale?: boolean }) {
  const state = contact(value, now, stale)
  return <span className={`badge ${state.tone}`}><span className="dot" />{state.label}</span>
}

function useMutation(api: ApiClient, intents: NodeIntents, scope: string, done: (id: string) => void) {
  const [error, setError] = useState<unknown>()
  const [success, setSuccess] = useState(false)
  const [, redraw] = useState(0)
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const submit = async (request?: AccessRequest) => {
    if (intents.busy.has(scope)) return
    const pending = intents.get(scope)
    if (!pending && !request) return
    const intent = pending ?? intents.begin(scope, request!)
    intents.busy.add(scope); setError(undefined); setSuccess(false); redraw(n => n + 1)
    try {
      const result = await api.request<unknown>(intent.path, { method: intent.method, body: intent.body, headers: { 'Idempotency-Key': intent.key, ...(intent.revision == null ? {} : { 'If-Match': `"${intent.revision}"` }) } })
      let id = scope
      if (intent.path.endsWith('/enrollment')) intents.saveSecret(enrollment(result as { node: Node; enrollment: Enrollment }, scope))
      else if (intent.path.endsWith('/config')) {
        const r = result as { node_id: string; node_revision: number; command: SignedCommand }
        if (!r || r.node_id !== scope || !Number.isSafeInteger(r.node_revision) || r.node_revision !== intent.revision! + 1) throw new ApiError('invalid_response')
        if (command(r.command, scope).payload.heartbeat_interval_seconds !== (intent.body as { heartbeat_interval_seconds: number }).heartbeat_interval_seconds) throw new ApiError('invalid_response')
      } else {
        id = node(result as Node, scope.startsWith('create') ? undefined : scope).id
        if (intent.path.endsWith('/revoke')) intents.forgetSecret(scope)
      }
      intents.finish(scope, intent.key)
      if (alive.current) { setSuccess(true); done(id) }
    } catch (e) { intents.failed(scope, intent.key, e); if (alive.current) setError(e) }
    finally { intents.busy.delete(scope); if (alive.current) redraw(n => n + 1) }
  }
  return { submit, error, success, pending: intents.get(scope), busy: intents.busy.has(scope) }
}
function MutationStatus({ mutation }: { mutation: ReturnType<typeof useMutation> }) {
  return <>{mutation.error != null && <Notice error={mutation.error} />}{mutation.pending && <Notice kind="info">{mutation.pending.unknown ? 'Исход изменения пока неизвестен.' : 'Запрос ожидает подтверждения.'} Повтор отправит то же действие с исходными параметрами.<p className="pending-description">{mutation.pending.label}</p><button className="button secondary small" disabled={mutation.busy} onClick={() => void mutation.submit()}>Повторить изменение</button></Notice>}{mutation.success && <Notice kind="success">Изменение сохранено в панели. Применение настройки агентом показано отдельно.</Notice>}</>
}
export function Nodes({ api, canWrite, intents, serverID, serverName }: { api: ApiClient; canWrite: boolean; intents: NodeIntents; serverID?: string; serverName?: string }) {
  const now = useNow()
  const [selected, setSelected] = useState<string>()
  const createScope = serverID ? `create:${serverID}` : 'create'
  const [adding, setAdding] = useState(Boolean(intents.get(createScope)))
  const [cursors, setCursors] = useState<string[]>([])
  const cursor = cursors.at(-1)
  const load = useCallback(async (signal: AbortSignal) => nodesPage(await api.request<Page<Node>>(serverID ? `/servers/${serverID}/connections${cursor ? `?after=${encodeURIComponent(cursor)}` : ''}` : `/nodes?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, { signal })), [api, cursor, serverID])
  const resource = useResource(load, 15_000)
  return <><PageHeading eyebrow="ВАША ИНФРАСТРУКТУРА" title={serverName ? serverName : serverID ? "Подключения сервера" : "Серверы"} action={canWrite && serverID !== 'unassigned' && <button className="button primary" onClick={() => setAdding(!adding)}><Icon name="plus" size={17} />{serverID ? 'Добавить подключение' : 'Добавить сервер'}</button>}>Подключайте агенты и следите за выполнением настроек.</PageHeading>
    {!canWrite && <Notice kind="info">Изменять узлы могут владелец и оператор инфраструктуры. Вашей роли доступен просмотр.</Notice>}
    <div className="access-boundary"><Icon name="server" size={18} /><p><strong>Связь с агентом и работа VPN показаны отдельно.</strong> В карточке узла доступны настройка VPN и подтверждение движка.</p></div>
    {adding && canWrite && <Modal title={serverID ? "Добавить подключение" : "Добавить сервер"} close={() => setAdding(false)}><CreateNode api={api} intents={intents} scope={createScope} path={serverID ? `/servers/${serverID}/connections` : '/nodes'} close={() => setAdding(false)} done={id => { setAdding(false); setSelected(id); setCursors([]); resource.refresh() }} /></Modal>}
    {selected && <button className="button secondary small" onClick={() => setSelected(undefined)}>{serverID ? "← Все подключения" : "← Все серверы"}</button>}<div className={`access-layout server-layout ${selected ? 'server-selected' : 'server-overview'}`}><aside className="card user-directory" aria-label="Список узлов"><div className="directory-heading"><h2>Узлы</h2><Freshness resource={resource} /></div>{resource.error != null && <Notice error={resource.error} />}
      {resource.data?.items.length ? <div className="user-list">{resource.data.items.map(n => <button key={n.id} className={`user-choice ${selected === n.id ? 'selected' : ''}`} aria-pressed={selected === n.id} onClick={() => setSelected(n.id)}><span className="user-initial"><Icon name="server" size={17} /></span><span><strong>{n.name}</strong><small>{contact(n, now, !!resource.error).label}</small></span><Icon name="arrow" size={15} /></button>)}</div> : <Empty icon="server" title={resource.data ? 'Узлов пока нет' : resource.loading ? 'Получаем узлы' : 'Список недоступен'}>Создайте узел, затем подключите его агент.</Empty>}
      {(resource.data?.next_cursor || cursors.length > 0) && <div className="pagination"><button className="button secondary small" disabled={!cursors.length || resource.loading} onClick={() => setCursors(c => c.slice(0, -1))}>Назад</button><button className="button secondary small" disabled={!resource.data?.next_cursor || resource.loading} onClick={() => { if (resource.data?.next_cursor) setCursors(c => [...c, resource.data!.next_cursor!]) }}>Далее</button></div>}
    </aside><section className="user-workspace" aria-label="Карточка узла">{selected ? <NodeDetail key={selected} api={api} id={selected} canWrite={canWrite} intents={intents} now={now} changed={resource.refresh} /> : <div className="card"><Empty icon="server" title="Выберите узел">В карточке видны связь, версия агента и результат применения настроек.</Empty></div>}</section></div>
  </>
}
function CreateNode({ api, intents, close, done, scope, path }: { api: ApiClient; intents: NodeIntents; scope: string; path: string; close: () => void; done: (id: string) => void }) {
  const [name, setName] = useState('')
  const mutation = useMutation(api, intents, scope, done)
  return <section className="card form-card"><p className="section-description">После создания скачайте файл подключения агента. Сервер появится в составе подписок, когда его VPN-подключение будет настроено.</p><MutationStatus mutation={mutation} /><form className="create-user-form" onSubmit={e => { e.preventDefault(); if (!mutation.pending) void mutation.submit({ path, method: 'POST', body: { name: name.trim() }, label: `Создать узел: ${name.trim()}` }) }}><label>Название узла<input autoFocus required minLength={2} maxLength={80} value={name} onChange={e => setName(e.target.value)} disabled={mutation.busy || !!mutation.pending} /></label><div className="form-actions"><button type="button" className="button secondary" onClick={close}>Закрыть</button><button className="button primary" disabled={mutation.busy || !!mutation.pending}>Создать узел</button></div></form></section>
}

type Editor = { kind: 'config' | 'enrollment' | 'revoke'; revision: number }
function NodeDetail({ api, id, canWrite, intents, now, changed }: { api: ApiClient; id: string; canWrite: boolean; intents: NodeIntents; now: number; changed: () => void }) {
  const load = useCallback(async (signal: AbortSignal) => {
    const [n, c] = await Promise.all([api.request<Node>(`/nodes/${id}`, { signal }), api.request<Control>(`/nodes/${id}/control`, { signal })])
    node(n, id); control(c, id)
    if (n.revision !== c.node_revision) throw new ApiError('revision_conflict', 412)
    return { node: n, control: c }
  }, [api, id])
  const resource = useResource(load, 5000)
  const [editor, setEditor] = useState<Editor>()
  const [interval, setInterval] = useState(15)
  const [, redraw] = useState(0)
  const mutation = useMutation(api, intents, id, () => { setEditor(undefined); resource.refresh(); changed() })
  const n = resource.data?.node
  // A successful delayed enrollment response is retained in session memory, but
  // can no longer be downloaded once the node is active, revoked or expired.
  const secret = intents.secret(id)
  useEffect(() => { if (n && n.state !== 'pending') intents.forgetSecret(id) }, [n?.state, id, intents])
  if (!n) return <><Freshness resource={resource} />{resource.error != null && <Notice error={resource.error} />}<div className="card"><Empty title={resource.loading ? 'Получаем узел' : 'Узел недоступен'}>Дождитесь ответа или обновите данные.</Empty></div></>
  const c = resource.data!.control
  const desired = c.desired && command(c.desired, id)
  const disabled = mutation.busy || !!mutation.pending || !!resource.error || resource.loading
  const expired = !!n.certificate_expires_at && now >= Date.parse(n.certificate_expires_at)
  const open = (kind: Editor['kind']) => { setEditor({ kind, revision: n.revision }); setInterval(desired?.payload.heartbeat_interval_seconds ?? 15) }
  const stateLabels = { pending: 'Ожидает подключения', active: 'Зарегистрирован', revoked: 'Доступ отозван' }
  return <><div className="detail-header"><div><h2>{n.name}</h2><Contact value={n} now={now} stale={!!resource.error} /></div></div><Freshness resource={resource} />{resource.error != null && <Notice error={resource.error} />}
    <MutationStatus mutation={mutation} />
    <section className="card access-section"><div className="access-section-heading"><h3>Агент узла</h3><span className="badge neutral">{stateLabels[n.state]}</span></div><dl className="access-facts"><div><dt>Последняя связь</dt><dd>{formatDate(n.last_seen_at ?? undefined)}</dd></div><div><dt>Сертификат действует до</dt><dd>{formatDate(n.certificate_expires_at ?? undefined)}</dd></div><div><dt>Версия агента</dt><dd>{n.inventory?.version ?? 'Нет данных'}</dd></div><div><dt>Система</dt><dd>{n.inventory ? `${n.inventory.platform} · ${n.inventory.arch}` : 'Нет данных'}</dd></div></dl><p className="section-description">{n.inventory?.capabilities.includes('certificate_renewal') ? 'Агент поддерживает автоматическое продление сертификата.' : n.inventory ? 'Для автоматического продления сертификата обновите агент.' : 'После подключения здесь появятся версия агента и поддерживаемые возможности.'}</p>{canWrite && <div className="access-actions">{n.state === 'pending' && <button className="button secondary" disabled={disabled} onClick={() => open('enrollment')}>Подключить агент</button>}{n.state === 'active' && <button className="button secondary" disabled={disabled || expired} onClick={() => open('config')}>Настроить отчёты</button>}{n.state !== 'revoked' && <button className="button secondary danger-text" disabled={disabled} onClick={() => open('revoke')}>Отозвать доступ узла</button>}</div>}</section>
    {canWrite && editor && <section className="card form-card access-editor"><h2>{editor.kind === 'config' ? 'Частота отчётов агента' : editor.kind === 'enrollment' ? 'Подключение агента' : 'Отзыв доступа узла'}</h2><p className="editor-explanation">{editor.kind === 'config' ? 'Агент получит настройку при следующей связи. Дождитесь отдельного подтверждения применения.' : editor.kind === 'enrollment' ? 'Создаём файл подключения на 10 минут. Прежний неиспользованный файл станет недействителен.' : 'Агент потеряет доступ к панели. Это не подтверждает остановку процессов VPN на сервере.'}</p>{editor.revision !== n.revision && <Notice kind="info">Запись изменилась после открытия формы. Исходная версия сохранена; закройте и откройте форму для нового действия.</Notice>}<form onSubmit={e => { e.preventDefault(); if (!mutation.pending) void mutation.submit({ path: `/nodes/${id}/${editor.kind}`, method: 'POST', body: editor.kind === 'config' ? { heartbeat_interval_seconds: interval } : {}, revision: editor.revision, label: `${n.name}: ${editor.kind === 'config' ? `отчёты каждые ${interval} с` : editor.kind === 'enrollment' ? 'файл подключения' : 'отзыв доступа'}` }) }}>
      {editor.kind === 'config' && <label>Интервал, секунды<input type="number" min={5} max={30} step={1} required value={interval} onChange={e => setInterval(Number(e.target.value))} disabled={mutation.busy || !!mutation.pending} /></label>}
      <div className="form-actions"><button type="button" className="button secondary" disabled={mutation.busy} onClick={() => setEditor(undefined)}>Закрыть</button><button className="button primary" disabled={disabled}>{editor.kind === 'config' ? 'Отправить настройку' : editor.kind === 'enrollment' ? 'Создать файл подключения' : 'Подтвердить отзыв'}</button></div></form></section>}
    {canWrite && secret && n.state === 'pending' && <section className="card access-section"><h3>Файл подключения готов</h3><p className="section-description">Действует до {formatDate(secret.expires_at)}. Содержит секрет: передайте только на этот сервер, ограничьте права файла до 0600 и удалите после подключения. Корень TLS и открытый ключ подписи передаются отдельно по инструкции установки агента.</p><div className="access-actions"><button className="button primary" disabled={!!resource.error} onClick={() => { const current = intents.secret(id); if (current) downloadEnrollment(current); else redraw(n => n + 1) }}>Скачать файл подключения</button><button className="button secondary" onClick={() => { intents.forgetSecret(id); redraw(n => n + 1) }}>Скрыть файл</button></div></section>}
    {canWrite && n.state === 'pending' && <section className="card access-section"><h3>Как подключить сервер</h3><ol><li>Нажмите «Подключить агент» и скачайте одноразовый файл.</li><li>Передайте на сервер проверенный Linux-пакет агента, файл подключения и публичные CA/ключ подписи панели. Для VPN подготовьте отдельный порт и TLS-сертификат.</li><li>В пакете заполните приватный <code>node.json</code>: ID узла, UUID установки, адрес панели и пути к файлам. У каждого подключения своё имя службы и каталог.</li><li>Проверьте план, затем установите службу. После регистрации укажите те же UUID и параметры в карточке VPN и отдельно активируйте службу.</li></ol><pre className="config-preview">{'python3 install-node.py plan --package . --spec ./node.json\nsudo python3 install-node.py install --package . --spec ./node.json\nsudo python3 install-node.py activate --instance de-vless'}</pre><p className="field-hint">Имя de-vless должно совпадать с instance в вашем файле. Панель не получает SSH-пароль. Установщик не меняет firewall и чужие службы. Регистрация агента ещё не подтверждает работу VPN.</p></section>}
    <NodeVPN api={api} node={n} canWrite={canWrite} intents={intents} now={now} changed={() => { resource.refresh(); changed() }} />
    <section className="card access-section node-control" aria-label="Настройки агента"><h3>Доставка настроек</h3><div className="node-command-columns"><div><span className="eyebrow">ЗАПРОШЕНО</span>{desired ? <><strong>Каждые {desired.payload.heartbeat_interval_seconds} с</strong><p>Настройка №{desired.generation} · {formatDate(desired.created_at)}</p><p>Первое применение до {formatDate(desired.deadline_at)}</p></> : <p>Настройки ещё не отправлялись</p>}</div><div><span className="eyebrow">ОТВЕТ АГЕНТА</span>{c.observed ? <><strong>{c.observed.status === 'applied' ? `Применено: каждые ${c.observed.config!.heartbeat_interval_seconds} с` : 'Ошибка применения'}</strong><p>Настройка №{c.observed.generation} · {formatDate(c.observed.completed_at)}</p>{c.observed.status === 'failed' && <p className="inline-error">{receiptErrors[c.observed.error_code!]}. Текущая действующая настройка этим ответом не подтверждена.</p>}</> : <p>Подтверждение ещё не получено</p>}</div></div>
      {desired && (!c.observed || c.observed.generation < desired.generation) && <Notice kind="info">{now >= Date.parse(desired.deadline_at) ? 'Срок первого применения прошёл. Результат пока неизвестен: агент мог применить настройку и ещё не передать ответ.' : 'Ожидаем ответ на новую настройку. Принятый запрос ещё не означает применение.'}</Notice>}
      {resource.error != null && <p className="section-description">Показан последний полученный ответ. Текущее состояние не подтверждено.</p>}
    </section></>
}
function downloadEnrollment(secret: Enrollment) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(secret, null, 2) + '\n'], { type: 'application/json' }))
  const link = document.createElement('a'); link.href = url; link.download = `node-${secret.node_id}-enrollment.json`; link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
