import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiClient, ApiError } from './api'
import type { Role } from './api'
import { Empty, Icon, Notice } from './components'
import { DiagnosticInvite } from './diagnosticInvite'
import { AccessIntents } from './accessIntent'

type Device = { id: string; platform: string; revoked: number; provider_freshness?: string; latest_metadata?: { app_version?: string; build_number?: number }; last_error?: { code: string; occurred_at_ms?: number } }
type Tester = { id: string; name: string | null; devices: Device[] }
type Event = { event_id: string; kind: string; process: string; process_run_id: string; sequence: number; occurred_at_ms: number; received_at_ms: number; device_id: string; command_id?: string; session_id?: string; build_number: number | null; payload: Record<string, unknown> }
type Overview = { testers: Tester[]; generated_at_ms: number }
type Detail = { tester: { id: string; name: string | null }; devices: Device[]; events: Event[]; next_cursor: string | null; raw_retention_days: number; fact_retention_days: number; evidence: unknown; process_observations: unknown; memory: unknown }
export const canReadDiagnostics = (role: Role) => ['owner', 'support', 'infrastructure_operator', 'auditor'].includes(role)
const names: Record<string, string> = { ping_trace: 'Проверка подключения', ping_result: 'Результат пинга', subscription_update: 'Обновление подписки', vpn_status: 'Состояние VPN', network_change: 'Смена сети', app_lifecycle: 'Работа приложения', app_action: 'Действие в приложении', problem: 'Сообщение о проблеме', core_state: 'Состояние соединения', extension_start: 'Запуск VPN', provider_stop: 'Остановка VPN', recovery: 'Восстановление соединения', heartbeat: 'Проверка состояния', preferences: 'Настройки', start_gate: 'Подготовка запуска', cleanup: 'Завершение подключения' }
const errors: Record<string, string> = { timeout: 'Превышено время ожидания', connection_lost: 'Соединение потеряно', verification_failed: 'Проверка подключения не пройдена', provider_unavailable: 'Служба VPN недоступна', engine_busy: 'Ядро занято другой операцией' }
const eventName = (kind: string) => names[kind] ?? kind
const errorName = (code: unknown) => typeof code === 'string' ? errors[code] ?? code : ''
const hasError = (e: Event) => e.payload.error_code != null || e.payload.outcome === 'failure' || e.payload.stage === 'failed'
const time = (n: number) => Number.isFinite(n) ? new Date(n).toLocaleString('ru-RU') : 'Неизвестно'
function overview(v: Overview): Overview {
  if (!v || !Array.isArray(v.testers) || !v.testers.every(t => t && typeof t.id === 'string' && Array.isArray(t.devices))) throw new ApiError('invalid_response')
  return v
}
function detail(v: Detail): Detail {
  if (!v?.tester || typeof v.tester.id !== 'string' || !Array.isArray(v.devices) || !Array.isArray(v.events) || !v.events.every(e => e && typeof e.event_id === 'string' && e.payload && typeof e.payload === 'object') || !(v.next_cursor === null || typeof v.next_cursor === 'string')) throw new ApiError('invalid_response')
  return v
}
function useRead<T>(api: ApiClient, path: string, parse: (v: T) => T, live: boolean) {
  const [data, setData] = useState<T | null>(null), [error, setError] = useState<unknown>(), [loading, setLoading] = useState(true), [revision, setRevision] = useState(0)
  const liveRef = useRef(live), previousPath = useRef('')
  useEffect(() => { liveRef.current = live }, [live])
  useEffect(() => {
    const controller = new AbortController(); let timer: ReturnType<typeof setTimeout>
    if (previousPath.current !== path) setData(null)
    previousPath.current = path
    setError(undefined); setLoading(true)
    const read = async (initial = false) => {
      if (!initial && (!liveRef.current || document.visibilityState === 'hidden')) { timer = setTimeout(() => void read(), 5000); return }
      try { const value = parse(await api.request<T>(path, { signal: controller.signal })); if (!controller.signal.aborted) { setData(value); setError(undefined) } }
      catch (e) { if (!controller.signal.aborted) setError(e) }
      finally { if (!controller.signal.aborted) { setLoading(false); timer = setTimeout(() => void read(), 5000) } }
    }
    void read(true); return () => { controller.abort(); clearTimeout(timer) }
  }, [api, path, parse, revision])
  return { data, error, loading, refresh: () => setRevision(n => n + 1) }
}
export function Diagnostics({ api, owner = false, intents }: { api: ApiClient; owner?: boolean; intents?: AccessIntents }) {
  const [selected, setSelected] = useState(''), [search, setSearch] = useState(''), [live, setLive] = useState(true)
  const state = useRead<Overview>(api, '/diagnostics/testers', overview, live)
  const testers = state.data?.testers.filter(t => `${t.name ?? ''} ${t.id}`.toLowerCase().includes(search.toLowerCase())) ?? []
  return <section className="diagnostics"><div className="page-heading"><div><h1>Диагностика тестеров</h1><p>Выберите тестера, чтобы увидеть, что происходило с подключением.</p></div><button className="button secondary" disabled={state.loading} onClick={state.refresh}><Icon name="refresh" size={16} />Обновить список</button></div>
    {owner && intents && <DiagnosticInvite api={api} intents={intents} />}
    <div className="diagnostic-toolbar"><label>Найти тестера<input value={search} onChange={e => setSearch(e.target.value)} placeholder="Имя или ID тестера" /></label><label className="diagnostic-check"><input type="checkbox" checked={live} onChange={e => setLive(e.target.checked)} /> Автообновление каждые 5 секунд</label></div>
    {!live && <p role="status" className="diagnostic-caption">Обновление на паузе. Уже полученные события сохранены на экране.</p>}
    {state.error != null && <><Notice error={state.error} /><p role="status">Свежесть данных не подтверждена. Ранее загруженные сведения могут устареть.</p></>}
    {state.loading && <p role="status">Загружаем тестеров…</p>}
    {state.data && <p className="diagnostic-caption">Обновлено: {time(state.data.generated_at_ms)} · Тестеров: {state.data.testers.length}</p>}
    {state.data && testers.length === 0 && <Empty title="Тестеры не найдены">{search ? 'Попробуйте другое имя или ID.' : 'Создайте приглашение в службе диагностики и активируйте его в настройках приложения.'}</Empty>}
    <div className="diagnostic-directory">{testers.map(t => <button key={t.id} aria-label={t.name || t.id} aria-pressed={selected === t.id} className={`tester-choice ${selected === t.id ? 'selected' : ''}`} onClick={() => setSelected(t.id)}><strong>{t.name || 'Тестер без имени'}</strong>{t.devices.length === 0 && <small>Ожидаем активацию</small>}{t.devices.map(d => <div key={d.id}><small>{d.platform} · {d.latest_metadata?.app_version ?? 'Версия неизвестна'} · сборка {d.latest_metadata?.build_number ?? '—'}</small><div className={`tester-status ${!d.revoked && d.provider_freshness === 'fresh' ? 'fresh' : ''}`}><span className="dot" />{d.revoked ? 'Диагностика отозвана' : d.provider_freshness === 'fresh' ? 'Есть свежие события туннеля' : 'Нет свежих данных туннеля'}</div>{d.last_error && <small>Последняя ошибка: {errorName(d.last_error.code)}{d.last_error.occurred_at_ms != null ? ` · ${time(d.last_error.occurred_at_ms)}` : ''}</small>}</div>)}</button>)}</div>
    <details><summary>Как поступают события</summary><p className="diagnostic-caption">Тестер один раз активирует приглашение и разрешает отправку в приложении. После этого события поступают автоматически. Ключи, ссылки подписок, содержимое трафика и посещённые сайты не передаются. Нет свежих данных — ещё не доказательство обрыва VPN.</p></details>
    {selected ? <DiagnosticDetail key={selected} api={api} tester={selected} live={live} /> : testers.length > 0 && <Empty title="Выберите тестера">Здесь появятся события приложения и подключения.</Empty>}
  </section>
}
function DiagnosticDetail({ api, tester, live }: { api: ApiClient; tester: string; live: boolean }) {
  const [cursor, setCursor] = useState(''), [kind, setKind] = useState(''), [device, setDevice] = useState(''), [correlation, setCorrelation] = useState(''), [errorsOnly, setErrorsOnly] = useState(false)
  const parse = useCallback((value: Detail) => { const result = detail(value); if (result.tester.id !== tester) throw new ApiError('invalid_response'); return result }, [tester])
  const state = useRead<Detail>(api, `/diagnostics/testers/${encodeURIComponent(tester)}${cursor ? '?before=' + encodeURIComponent(cursor) : ''}`, parse, live && !cursor)
  const events = state.data?.events.filter(e => (!kind || e.kind === kind) && (!device || e.device_id === device) && (!correlation || [e.command_id, e.session_id, e.process_run_id].includes(correlation)) && (!errorsOnly || hasError(e))) ?? []
  const filtered = Boolean(kind || device || correlation || errorsOnly)
  return <section aria-label="История тестера"><h2>{state.data?.tester.name || 'История тестера'}</h2><p className="diagnostic-caption">Фильтры применяются к текущей странице (до 200 событий).</p>
    {state.error != null && <><Notice error={state.error} /><p>Журнал не обновлён. Показана предыдущая загруженная страница.</p></>}
    {state.loading && <p role="status">Загружаем журнал…</p>}
    <div className="diagnostic-controls"><label className="diagnostic-check"><input type="checkbox" checked={errorsOnly} onChange={e => setErrorsOnly(e.target.checked)} /> Только ошибки</label>{filtered && <button className="button ghost small" onClick={() => { setKind(''); setDevice(''); setCorrelation(''); setErrorsOnly(false) }}>Сбросить фильтры</button>}<span className="diagnostic-caption">Показано: {events.length}{state.data ? ` из ${state.data.events.length}` : ''}</span></div>
    <details><summary>Настроить фильтры</summary><div className="filters"><label>Устройство<select value={device} onChange={e => setDevice(e.target.value)}><option value="">Все устройства</option>{state.data?.devices.map((d, i) => <option key={d.id} value={d.id}>{d.platform} · устройство {i + 1} · {d.id.slice(0, 8)}</option>)}</select></label>
    <label>Тип события<select value={kind} onChange={e => setKind(e.target.value)}><option value="">Все события</option>{[...new Set(state.data?.events.map(e => e.kind))].sort().map(k => <option key={k} value={k}>{eventName(k)}</option>)}</select></label>
    <label className="correlation-filter">ID попытки, сеанса или процесса<input value={correlation} onChange={e => setCorrelation(e.target.value.trim())} /></label></div></details>
    <div className="diagnostic-controls"><button className="button secondary" disabled={state.loading} onClick={() => { setCursor(''); state.refresh() }}>Последние события</button>{state.data?.next_cursor && <button className="button secondary" disabled={state.loading} onClick={() => setCursor(state.data!.next_cursor!)}>Более ранние события</button>}</div>
    {cursor && <p>Открыта история. Автообновление этой страницы остановлено.</p>}
    {state.data && events.length === 0 && <Empty title="Подходящих событий нет">Проверьте фильтры или перейдите к более ранним событиям.</Empty>}
    <div className="diagnostic-events">{events.map(e => <article key={e.event_id} aria-label={eventName(e.kind)} className={`diagnostic-event ${hasError(e) ? 'has-error' : ''}`}><div className="event-top"><div><h3 className="event-title">{eventName(e.kind)}</h3><p className="event-meta">{e.process === 'app' ? 'Приложение' : e.process === 'extension' ? 'VPN' : e.process} · сборка {e.build_number ?? 'неизвестна'}</p></div><time className="event-time">{time(e.occurred_at_ms)}</time></div>{hasError(e) && <p className="event-error">{errorName(e.payload.error_code) || 'Операция завершилась с ошибкой'}</p>}
    <details className="event-technical"><summary>Показать событие</summary><p>Получено: {time(e.received_at_ms)}<br />Тип: {e.kind} · № {e.sequence}<br />Этап: {String(e.payload.stage ?? 'не указан')}<br />Устройство: {e.device_id}<br />Попытка: {e.command_id ?? 'неизвестна'}<br />Сеанс: {e.session_id ?? 'неизвестен'}<br />Процесс: {e.process_run_id}</p><pre>{JSON.stringify(e.payload, null, 2)}</pre></details></article>)}</div>
    {state.data && <details><summary>Техническая сводка и полнота данных</summary><p className="diagnostic-caption">ID тестера: {tester}. Полные события хранятся {state.data.raw_retention_days} дней, сводные наблюдения — {state.data.fact_retention_days} дней.</p><details><summary>Пробелы и полнота наблюдений</summary><pre>{JSON.stringify(state.data.evidence, null, 2)}</pre></details><details><summary>История процессов туннеля</summary><pre>{JSON.stringify(state.data.process_observations, null, 2)}</pre></details><details><summary>Память: измерения и ограничения окна</summary><pre>{JSON.stringify(state.data.memory, null, 2)}</pre></details></details>}
  </section>
}
