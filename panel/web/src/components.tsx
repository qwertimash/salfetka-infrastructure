import type { ReactNode } from 'react'
import { safeError } from './api'
import type { Resource } from './useResource'

export function Icon({ name, size = 20 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></>,
    operations: <><path d="m13 2-9 12h7l-1 8 10-13h-7z" /></>,
    admins: <><circle cx="9" cy="8" r="3" /><path d="M3 21v-3a6 6 0 0 1 12 0v3M17 4a3 3 0 0 1 0 6m2 11v-3a6 6 0 0 0-2-4" /></>,
    audit: <><path d="M8 4H5v17h14V4h-3" /><rect x="8" y="2" width="8" height="4" rx="1" /><path d="M8 11h8m-8 5h5" /></>,
    server: <><rect x="3" y="3" width="18" height="7" rx="2" /><rect x="3" y="14" width="18" height="7" rx="2" /><path d="M7 6.5h.01M7 17.5h.01m5-11h5m-5 11h5" /></>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" /></>,
    layers: <><path d="m12 3 10 5-10 5L2 8zm-9 9 9 5 9-5M3 17l9 5 9-5" /></>,
    route: <><circle cx="5" cy="5" r="2" /><circle cx="19" cy="19" r="2" /><path d="M7 5h8a4 4 0 0 1 0 8H9a4 4 0 0 0 0 8h8" /></>,
    refresh: <><path d="M20 7v5h-5M4 17v-5h5" /><path d="M6 6a8 8 0 0 1 13 2M5 16a8 8 0 0 0 13 2" /></>,
    arrow: <><path d="M5 12h14m-5-5 5 5-5 5" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    exit: <><path d="M9 4H4v16h5m3-8h9m-4-4 4 4-4 4" /></>,
    plus: <path d="M12 5v14M5 12h14" />,
    info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v6m0-10h.01" /></>,
  }
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] ?? paths.info}</svg>
}

export function Brand() {
  return <div className="brand"><img src="/mark.svg" width="35" height="35" alt="" /><div><strong>САЛФЕТКА</strong><span>Управление</span></div></div>
}

export function Notice({ error, children, kind = 'error' }: { error?: unknown; children?: ReactNode; kind?: 'error' | 'info' | 'success' }) {
  return <div className={`notice ${kind}`} role={kind === 'error' ? 'alert' : 'status'}><Icon name={kind === 'success' ? 'check' : 'info'} /><div>{error ? safeError(error) : children}</div></div>
}

export function StateBadge({ state }: { state: string }) {
  const states: Record<string, [string, string]> = {
    healthy: ['Работает', 'good'], ok: ['Работает', 'good'], ready: ['Готово', 'good'], connected: ['Подключена', 'good'],
    pending: ['В очереди', 'pending'], running: ['Выполняется', 'pending'], succeeded: ['Завершено', 'good'],
    failed: ['Ошибка', 'bad'], unavailable: ['Недоступно', 'bad'], degraded: ['Есть ограничения', 'pending'], unknown: ['Нет данных', 'neutral'],
    accepted: ['Принято', 'pending'],
  }
  const [label, tone] = states[state] ?? states.unknown
  return <span className={`badge ${tone}`}><span className="dot" />{label}</span>
}

export function formatDate(value?: string | Date) {
  if (!value) return 'Нет данных'
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? 'Нет данных' : new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).format(date)
}

export function Freshness<T>({ resource, label = 'Обновить' }: { resource: Resource<T>; label?: string }) {
  return <div className="freshness" aria-live="polite"><span className={resource.error ? 'stale-label' : ''}>{resource.error ? resource.updatedAt ? 'Не обновлено · показаны последние данные' : 'Данные не получены' : resource.loading ? 'Обновляем данные…' : resource.updatedAt ? `Обновлено ${formatDate(resource.updatedAt)}` : 'Данные ещё не получены'}</span><button className="button ghost small" onClick={resource.refresh} disabled={resource.loading}><Icon name="refresh" size={15} />{label}</button></div>
}

export function Empty({ icon = 'layers', title, children }: { icon?: string; title: string; children: ReactNode }) {
  return <div className="empty"><div className="empty-icon"><Icon name={icon} size={25} /></div><h3>{title}</h3><p>{children}</p></div>
}

export function PageHeading({ eyebrow, title, children, action }: { eyebrow: string; title: string; children: ReactNode; action?: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{children}</p></div>{action}</div>
}
