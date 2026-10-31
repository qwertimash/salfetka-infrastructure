import { useEffect, useState } from 'react'
import { ApiClient, ApiError } from './api'
import type { Role } from './api'
import { Empty, Notice } from './components'

type Policy = { revision: number; incident_id: number | null; limited: boolean; until_ms: number | null; state: string; required_nodes: string[]; confirmed_nodes: string[]; failed_nodes: string[] }
type Account = { account_id: string; plan: string; candidate_bytes: number; download_lower_bytes: number; download_upper_bytes: number | null; coverage_complete: boolean; quality_reasons: string[]; policy: Policy; notification_state: string; incident: null | { id: number; triggered_at: number; threshold_bytes: number; evidence_bytes: number; ended_by: string | null; end_reason: string | null } }
type Page = { items: Account[]; next_cursor: string; generated_at_ms: number; coverage_scope: string; aggregate_bps: number }
export const canReadAntifraud = (role: Role) => ['owner', 'support', 'auditor'].includes(role)
const states: Record<string, string> = { clear: 'Без ограничения', limited: 'Ограничен до 1 Мбит/с', pending_apply: 'Ожидаем применения', pending_release: 'Ожидаем снятия', apply_failed: 'Ошибка на узлах' }
const notifications: Record<string, string> = { none: 'Не отправлялось', queued: 'В очереди', sending: 'Отправка начата', delivered: 'Доставлено', forbidden: 'Бот недоступен пользователю', unknown: 'Доставка не подтверждена — нужен разбор', cancelled: 'Отменено' }
const reasons: Record<string, string> = { missing_baseline: 'Нет начального замера', unobserved_tail: 'Последние данные ещё не поступили', stale_or_missing_meter: 'Есть узлы без свежих данных', missing_counter: 'Нет счётчика скачивания', window_boundary_interval: 'Часть замера пересекает границу суток', counter_reset: 'Счётчик перезапускался', epoch_changed: 'Сменился процесс' }
const gb = (v: number) => `${(v / 1e9).toLocaleString('ru-RU', { maximumFractionDigits: 2 })} ГБ`
const time = (v: number) => new Date(v).toLocaleString('ru-RU')
function parse(v: Page): Page {
  if (!v || !Array.isArray(v.items) || typeof v.next_cursor !== 'string' || !Number.isSafeInteger(v.generated_at_ms) || v.aggregate_bps !== 1000000 || v.coverage_scope !== 'declared_client_ingress_meters_only' || !v.items.every(a => a && typeof a.account_id === 'string' && Number.isSafeInteger(a.download_lower_bytes) && a.download_lower_bytes >= 0 && Number.isSafeInteger(a.candidate_bytes) && a.candidate_bytes > 0 && Array.isArray(a.quality_reasons) && a.policy && typeof a.policy.limited === 'boolean' && states[a.policy.state] && Array.isArray(a.policy.required_nodes) && Array.isArray(a.policy.confirmed_nodes) && Array.isArray(a.policy.failed_nodes) && (!a.policy.limited || a.policy.incident_id != null && a.policy.until_ms != null && a.incident?.id === a.policy.incident_id))) throw new ApiError('invalid_response')
  return v
}
export function Antifraud({ api, owner }: { api: ApiClient; owner: boolean }) {
  const [data, setData] = useState<Page | null>(null), [error, setError] = useState<unknown>(), [loading, setLoading] = useState(true)
  const [cursor, setCursor] = useState(''), [revision, setRevision] = useState(0), [search, setSearch] = useState('')
  const [selected, setSelected] = useState<{ account: string; incident: number } | null>(null), [busy, setBusy] = useState(false), [message, setMessage] = useState('')
  useEffect(() => {
    const abort = new AbortController(); let timer: ReturnType<typeof setTimeout>
    const read = async () => {
      setLoading(true)
      try {
        const page = parse(await api.request<Page>(`/antifraud/accounts${cursor ? '?after=' + encodeURIComponent(cursor) : ''}`, { signal: abort.signal }))
        if (!abort.signal.aborted) { setData(page); setError(undefined) }
      } catch (e) { if (!abort.signal.aborted) setError(e) }
      finally { if (!abort.signal.aborted) { setLoading(false); timer = setTimeout(() => void read(), 15000) } }
    }
    void read()
    return () => { abort.abort(); clearTimeout(timer) }
  }, [api, cursor, revision])
  const rows = data?.items.filter(a => a.account_id.toLowerCase().includes(search.toLowerCase())) ?? []
  const refresh = () => setRevision(n => n + 1)
  const page = (after: string) => { setData(null); setSelected(null); setCursor(after); setSearch(''); setMessage(''); refresh() }
  return <section className="diagnostics"><div className="page-heading"><div><h1>Защита от перерасхода</h1><p>20 ГБ для пробного доступа, 50 ГБ для платного. Считаем скачивание всех устройств аккаунта за последние 24 часа.</p></div><button className="button secondary" disabled={loading || busy} onClick={refresh}>Обновить</button></div>
    <p>После превышения — 1 Мбит/с на скачивание и отправку вместе на 24 часа. Снятие ограничения начинает новый отсчёт. Охват — только подключённые к учёту узлы.</p>
    {error != null && <><Notice error={error} /><p role="status">Свежесть данных не подтверждена. Снятие ограничения недоступно до успешного обновления.</p></>}
    {loading && <p role="status">Обновляем данные…</p>}{message && <p role="status">{message}</p>}
    {data && <><p className="diagnostic-caption">Обновлено: {time(data.generated_at_ms)} · Страница: {data.items.length} аккаунтов · Автообновление каждые 15 секунд</p><label>Найти аккаунт на этой странице<input value={search} onChange={e => setSearch(e.target.value)} /></label></>}
    {data && !rows.length && <Empty title="Аккаунты не найдены">Проверьте поиск или состав подключённого учёта. Аккаунты здесь автоматически не создаются.</Empty>}
    <div className="diagnostic-events">{rows.map(a => <article key={a.account_id} className={`diagnostic-event ${a.policy.state === 'apply_failed' ? 'has-error' : ''}`} aria-label={`Аккаунт ${a.account_id}`}><div className="event-top"><h2>{a.account_id}</h2><strong>{states[a.policy.state]}</strong></div>
      <p>{a.plan === 'trial' ? 'Пробный доступ' : 'Платный доступ'} · {a.coverage_complete ? '' : 'Учтено не менее '}{gb(a.download_lower_bytes)} из {gb(a.candidate_bytes)}</p>
      <progress aria-label={`Расход ${a.account_id}`} max={a.candidate_bytes} value={Math.min(a.download_lower_bytes, a.candidate_bytes)} />
      {!a.coverage_complete && <p>Расход неполный: {a.quality_reasons.map(r => reasons[r] ?? r).join('; ')}. Пропуски не считаются нулевым трафиком.</p>}
      {a.policy.until_ms && <p>Назначено до {time(a.policy.until_ms)}. {a.policy.state !== 'limited' && 'Применение на всех узлах пока не подтверждено.'}</p>}
      {a.policy.revision > 0 && <p>Подтвердили: {a.policy.confirmed_nodes.length} из {a.policy.required_nodes.length} узлов{a.policy.failed_nodes.length > 0 && ` · Ошибка: ${a.policy.failed_nodes.join(', ')}`}</p>}
      <p>Уведомление в боте: {notifications[a.notification_state] ?? 'Состояние неизвестно'}</p>
      {a.incident && <details><summary>Основание решения</summary><p>Случай № {a.incident.id} · {time(a.incident.triggered_at)}<br />Доказанный расход: {gb(a.incident.evidence_bytes)} при пороге {gb(a.incident.threshold_bytes)}.{a.incident.ended_by && ` Снял: ${a.incident.ended_by}.`}</p></details>}
      {owner && a.policy.limited && <button className="button secondary" disabled={loading || busy || error != null} onClick={() => { setSelected({ account: a.account_id, incident: a.policy.incident_id! }); setMessage('') }}>Снять ограничение с {a.account_id}</button>}
    </article>)}</div>
    {selected && <section role="dialog" aria-modal="false" aria-labelledby="antifraud-confirm"><h2 id="antifraud-confirm">Снять ограничение с {selected.account}?</h2><p>Случай № {selected.incident}. Расход начнёт считаться заново. Остальные аккаунты сохранят своё состояние.</p><button className="button primary" disabled={busy || loading || error != null} onClick={async () => {
      if (busy) return
      setBusy(true); setMessage('')
      try {
        await api.request('/antifraud/release', { method: 'POST', body: { account_id: selected.account, incident_id: selected.incident } })
        setMessage('Команда принята. Снятие подтвердится после ответа узлов.'); setSelected(null); refresh()
      } catch (e) { setError(e); setMessage('Результат не подтверждён. Обновите данные; повтор для этого же случая безопасен.') }
      finally { setBusy(false) }
    }}>{busy ? 'Отправляем…' : 'Подтвердить снятие'}</button><button className="button ghost" disabled={busy} onClick={() => setSelected(null)}>Отмена</button></section>}
    {data && <div className="diagnostic-controls"><button className="button secondary" disabled={!cursor || loading || busy} onClick={() => page('')}>Первая страница</button>{data.next_cursor && <button className="button secondary" disabled={loading || busy} onClick={() => page(data.next_cursor)}>Следующие аккаунты</button>}</div>}
  </section>
}
