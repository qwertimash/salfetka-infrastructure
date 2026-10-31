import { useCallback, useEffect, useRef, useState } from 'react'
import { Antifraud, canReadAntifraud } from './antifraud'
import { Diagnostics, canReadDiagnostics } from './diagnostics'
import { Constructor } from './constructor'
import { BuilderSession } from './constructorModel'
import { ApiClient, ApiError, OperationIntent, parseSession, roles, validateNewPassword } from './api'
import type { Session } from './api'
import { Brand, Icon, Notice } from './components'
import { Admins, Audit, Operations, OverviewPage } from './pages'
import { Users } from './access'
import { Servers } from './servers'
import { Sources, SourceIntents } from './sources'
import { Subscriptions, SubscriptionIntents } from './subscriptions'
import { SubscriptionSets } from './subscriptionSets'
import { SetSession } from './subscriptionSetModel'
import { NodeIntents } from './nodeIntent'
import { canWriteNodes } from './nodeApi'
import { AccessIntents } from './accessIntent'
import { canReadAccess, canWriteAccess } from './accessApi'

type Auth = { view: 'loading' | 'setup' | 'login' | 'failed'; error?: unknown } | { view: 'authenticated'; session: Session }
type View = 'antifraud' | 'diagnostics' | 'overview' | 'operations' | 'admins' | 'audit' | 'users' | 'nodes' | 'sources' | 'subscriptions' | 'constructor' | 'legacy-subscriptions'

export function App({ client }: { client?: ApiClient }) {
  const [api] = useState(() => client ?? new ApiClient())
  const [auth, setAuth] = useState<Auth>({ view: 'loading' })
  const [reload, setReload] = useState(0)
  const signIn = useCallback((session: Session) => { api.setSession(session); setAuth({ view: 'authenticated', session }) }, [api])
  const leave = useCallback((error?: unknown) => { api.clear(); setAuth({ view: 'login', error }) }, [api])
  useEffect(() => {
    api.onUnauthorized = () => leave(new ApiError('unauthenticated', 401))
    return () => { api.onUnauthorized = undefined }
  }, [api, leave])
  useEffect(() => {
    const controller = new AbortController()
    setAuth({ view: 'loading' })
    void (async () => {
      try {
        const status = await api.request<{ setup_required: boolean }>('/setup/status', { signal: controller.signal })
        if (typeof status?.setup_required !== 'boolean') throw new ApiError('invalid_response')
        if (status.setup_required) { if (!controller.signal.aborted) setAuth({ view: 'setup' }); return }
        const session = parseSession(await api.request('/auth/session', { signal: controller.signal }))
        if (!controller.signal.aborted) signIn(session)
      } catch (error) {
        if (controller.signal.aborted) return
        setAuth(error instanceof ApiError && error.status === 401 ? { view: 'login' } : { view: 'failed', error })
      }
    })()
    return () => controller.abort()
  }, [api, reload, signIn])
  if (auth.view === 'authenticated') return <Shell api={api} session={auth.session} leave={leave} />
  return <div className="auth-layout"><aside className="auth-aside"><Brand /><div className="auth-story"><span className="eyebrow">ВАША ИНФРАСТРУКТУРА</span><h1>Ваш VPN.<br />Всё под контролем.</h1><p>Пользователи, подключения и диагностика в одном месте.</p><div className="auth-lines" aria-hidden="true"><span /><span /><span /><span /></div></div><div className="auth-footer"><Icon name="lock" size={16} />Самостоятельная установка</div></aside><main className="auth-main"><div className="auth-card">
    {auth.view === 'loading' ? <div role="status" className="auth-wait"><span className="spinner" />Подключаемся к панели…</div> : auth.view === 'failed' ? <><h1>Не удалось открыть панель</h1><Notice error={auth.error} /><button className="button primary full" onClick={() => setReload(n => n + 1)}>Попробовать снова</button></> : <AuthForm key={auth.view} api={api} setup={auth.view === 'setup'} initialError={auth.error} onSignIn={signIn} onLogin={() => setAuth({ view: 'login' })} />}
    <p className="auth-note">Данные доступа используются только для входа в эту панель.</p>
  </div></main></div>
}

function AuthForm({ api, setup, initialError, onSignIn, onLogin }: { api: ApiClient; setup: boolean; initialError?: unknown; onSignIn: (s: Session) => void; onLogin: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(initialError)
  return <><div className="eyebrow">{setup ? 'ПЕРВЫЙ ЗАПУСК' : 'С ВОЗВРАЩЕНИЕМ'}</div><h1>{setup ? 'Настройте вашу панель' : 'Вход в управление'}</h1><p className="auth-description">{setup ? 'Создайте первый аккаунт владельца. Одноразовый токен доступен в локальной настройке сервера.' : 'Используйте аккаунт, созданный владельцем панели.'}</p>{error != null && <Notice error={error} />}
    <form onSubmit={async event => {
      event.preventDefault(); if (busy) return; setBusy(true); setError(undefined)
      try {
        if (setup) {
          validateNewPassword(password)
          await api.request('/setup', { method: 'POST', body: { token, username: username.trim(), password } })
          setPassword(''); setToken(''); onLogin()
        } else {
          const session = parseSession(await api.request('/auth/login', { method: 'POST', body: { username: username.trim(), password } }))
          setPassword(''); onSignIn(session)
        }
      } catch (error) { setError(error) } finally { setBusy(false) }
    }}>
      {setup && <label>Одноразовый токен<input autoFocus type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} required disabled={busy} /></label>}
      <label>Имя пользователя<input autoFocus={!setup} autoComplete="username" autoCapitalize="none" value={username} onChange={e => setUsername(e.target.value)} maxLength={64} minLength={setup ? 3 : undefined} pattern={setup ? '[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}' : undefined} required disabled={busy} spellCheck={false} /></label>
      <label>Пароль<input type="password" autoComplete={setup ? 'new-password' : 'current-password'} value={password} onChange={e => setPassword(e.target.value)} minLength={setup ? 12 : undefined} maxLength={128} required disabled={busy} />{setup && <span className="field-hint">Не менее 12 символов. Сохраните пароль в надёжном месте.</span>}</label>
      <button className="button primary full" disabled={busy}>{busy ? 'Подождите…' : setup ? 'Создать владельца' : 'Войти'}<Icon name="arrow" size={17} /></button>
    </form>{setup && <button className="button link full" onClick={onLogin} disabled={busy}>Уже есть аккаунт? Войти</button>}</>
}

function Shell({ api, session, leave }: { api: ApiClient; session: Session; leave: (error?: unknown) => void }) {
  const pathView = useCallback((): View => {
    const path = window.location.pathname.slice(1)
    if (path === 'antifraud' && canReadAntifraud(session.user.role) || path === 'diagnostics' && canReadDiagnostics(session.user.role) || path === 'constructor' && ['owner', 'infrastructure_operator', 'access_operator'].includes(session.user.role) || path === 'subscriptions' && ['owner', 'access_operator', 'infrastructure_operator'].includes(session.user.role) || path === 'legacy-subscriptions' && canReadAccess(session.user.role) || path === 'sources' || path === 'nodes' || path === 'operations' || path === 'users' && canReadAccess(session.user.role) || path === 'admins' && session.user.role === 'owner' || path === 'audit' && ['owner', 'auditor'].includes(session.user.role)) return path as View
    return 'overview'
  }, [session.user.role])
  const [view, setView] = useState<View>(pathView)
  useEffect(() => {
    const pop = () => setView(pathView())
    window.addEventListener('popstate', pop)
    return () => window.removeEventListener('popstate', pop)
  }, [pathView])
  const [menuOpen, setMenuOpen] = useState(false)
  const [navQuery, setNavQuery] = useState('')
  const [toolsOpen, setToolsOpen] = useState(false)
  const searchRef = useRef<HTMLInputElement>(null)
  const navigate = (next: View) => {
    window.history.pushState({}, '', next === 'overview' ? '/' : `/${next}`)
    setView(next); setMenuOpen(false); setNavQuery(''); setAccountOpen(false)
    requestAnimationFrame(() => document.getElementById('content')?.focus())
  }
  useEffect(() => {
    const shortcut = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault(); setMenuOpen(true); requestAnimationFrame(() => searchRef.current?.focus())
      }
      if (e.key === 'Escape') { setMenuOpen(false); setNavQuery(''); setAccountOpen(false) }
    }
    window.addEventListener('keydown', shortcut)
    return () => window.removeEventListener('keydown', shortcut)
  }, [])
  const [accountOpen, setAccountOpen] = useState(false)
  const [leaving, setLeaving] = useState(false)
  const intent = useRef(new OperationIntent()).current
  const accessIntents = useRef(new AccessIntents()).current
  const nodeIntents = useRef(new NodeIntents()).current
  const subscriptionIntents = useRef(new SubscriptionIntents()).current
  const sourceIntents = useRef(new SourceIntents()).current
  const setSession = useRef(new SetSession()).current
  const builderSession = useRef(new BuilderSession()).current
  const user = session.user
  const nav: { id: View; label: string }[] = [{ id: 'overview', label: 'Обзор' }, { id: 'operations', label: 'Операции' }]
  if (canReadAccess(user.role)) nav.push({ id: 'users', label: 'Пользователи' }, { id: 'legacy-subscriptions', label: 'Выдача устройствам' })
  if (['owner', 'access_operator', 'infrastructure_operator'].includes(user.role)) nav.push({ id: 'subscriptions', label: 'Подписки' })
  nav.push({ id: 'nodes', label: 'Серверы' }, { id: 'sources', label: 'Источники' })
  if (['owner', 'infrastructure_operator', 'access_operator'].includes(user.role)) nav.push({ id: 'constructor', label: 'Конструктор' })
  if (user.role === 'owner') nav.push({ id: 'admins', label: 'Администраторы' })
  if (user.role === 'owner' || user.role === 'auditor') nav.push({ id: 'audit', label: 'Журнал действий' })
  if (canReadDiagnostics(user.role)) nav.push({ id: 'diagnostics', label: 'Логи' })
  if (canReadAntifraud(user.role)) nav.push({ id: 'antifraud', label: 'Защита от перерасхода' })
  const groups = [
    { title: 'Рабочая область', ids: ['subscriptions', 'users', 'nodes', 'diagnostics'] },
    { title: 'Инструменты', ids: ['overview', 'sources', 'constructor', 'legacy-subscriptions', 'antifraud', 'operations', 'audit', 'admins'] },
  ]
  const hints: Partial<Record<View, string>> = { nodes: 'серверы vpn', diagnostics: 'логи ошибки тестеры', subscriptions: 'ссылки доступ', constructor: 'конфиги локации маршруты обходы', sources: 'импорт настроек', admins: 'команда права' }
  const matches = nav.filter(n => `${n.label} ${hints[n.id] ?? ''}`.toLowerCase().includes(navQuery.trim().toLowerCase()))
  const quickActions = [
    { id: 'users', title: 'Добавить пользователя', description: 'Выдать доступ и подключить устройство' },
    { id: 'constructor', title: 'Собрать подключение', description: 'Локации, маршруты и обходы' },
    { id: 'subscriptions', title: 'Открыть подписки', description: 'Опубликовать настройки и получить ссылку' },
    { id: 'diagnostics', title: 'Проверить подключение тестера', description: 'События приложения и причины ошибок' },
  ].filter(item => nav.some(n => n.id === item.id)).map(item => ({ ...item, onClick: () => navigate(item.id as View) }))
  const title = nav.find(n => n.id === view)?.label ?? 'Обзор'
  const logout = async (all = false) => {
    if (leaving) return
    setLeaving(true)
    try { await api.request(all ? '/auth/revoke-sessions' : '/auth/logout', { method: 'POST', body: {} }); leave() }
    catch { leave(new ApiError('logout_unconfirmed')) }
    finally { intent.finish(); setLeaving(false) }
  }
  return <div className="app-layout"><a href="#content" className="skip-link">К содержимому</a><aside className={`sidebar ${menuOpen ? 'menu-open' : ''}`}><Brand /><button className="button menu-toggle" aria-label="Разделы панели" aria-expanded={menuOpen} aria-controls="panel-navigation" onClick={() => setMenuOpen(!menuOpen)}>{menuOpen ? 'Закрыть' : 'Меню'}</button>
      <label className="nav-search"><span className="sr-only">Найти раздел</span><input ref={searchRef} value={navQuery} onChange={e => setNavQuery(e.target.value)} placeholder="Найти раздел…" aria-keyshortcuts="Meta+K Control+K" />{navQuery && <button aria-label="Очистить поиск разделов" onClick={() => { setNavQuery(''); searchRef.current?.focus() }}>×</button>}</label>
      <nav id="panel-navigation" aria-label="Главная навигация">{groups.map(group => {
        const entries = group.ids.flatMap(id => matches.filter(n => n.id === id))
        if (group.title === 'Инструменты' && !toolsOpen && !navQuery) return null
        return entries.length > 0 && <div key={group.title} className="nav-group"><div className="nav-group-title">{group.title}</div>{entries.map(n => <button key={n.id} className={`nav-item ${view === n.id ? 'selected' : ''}`} aria-current={view === n.id ? 'page' : undefined} onClick={() => navigate(n.id)}><Icon name={n.id === 'diagnostics' || n.id === 'antifraud' ? 'audit' : n.id === 'constructor' ? 'route' : n.id === 'subscriptions' || n.id === 'sources' ? 'layers' : n.id === 'users' ? 'admins' : n.id === 'nodes' ? 'server' : n.id} />{n.label}{view === n.id && <span className="nav-active-mark" />}</button>)}</div>
      })}{!navQuery && <button className="nav-item tools-toggle" aria-expanded={toolsOpen} onClick={() => setToolsOpen(!toolsOpen)}><Icon name="overview" />Настройки и инструменты</button>}{matches.length === 0 && <p className="nav-empty" role="status">Раздел не найден. Попробуйте «подписки» или «логи».</p>}</nav><div className="sidebar-bottom"><div className="installation"><span className="installation-mark"><Icon name="server" size={17} /></span><div><strong>Своя установка</strong><span>Данные на вашем сервере</span></div></div></div></aside>
    <div className="main-area"><header className="topbar"><div className="breadcrumb">Панель<span>/</span><strong>{title}</strong></div><div className="topbar-actions"><div className="account"><button className="account-button" onClick={() => setAccountOpen(!accountOpen)} aria-expanded={accountOpen} aria-label="Меню аккаунта"><span className="avatar">{user.username.slice(0, 1).toUpperCase()}</span><span><strong>{user.username}</strong><small>{roles[user.role]}</small></span><span className="chevron">⌄</span></button>{accountOpen && <div className="account-menu"><button onClick={() => void logout()} disabled={leaving}><Icon name="exit" size={16} />Выйти</button><button onClick={() => void logout(true)} disabled={leaving}>Завершить все мои сессии</button></div>}</div></div></header>
    <main id="content" className="content" tabIndex={-1}>{view === 'antifraud' && canReadAntifraud(user.role) && <Antifraud api={api} owner={user.role === 'owner'} />}{view === 'diagnostics' && canReadDiagnostics(user.role) && <Diagnostics api={api} owner={user.role === 'owner'} intents={accessIntents} />}{view === 'overview' && <OverviewPage api={api} openOperations={() => navigate('operations')} quickActions={quickActions} />}{view === 'operations' && <Operations api={api} canCreate={user.role === 'owner' || user.role === 'infrastructure_operator'} intent={intent} />}{view === 'users' && canReadAccess(user.role) && <Users api={api} canWrite={canWriteAccess(user.role)} intents={accessIntents} />}{view === 'subscriptions' && ['owner', 'access_operator', 'infrastructure_operator'].includes(user.role) && <SubscriptionSets api={api} canEdit={canWriteNodes(user.role)} canPublish={canWriteAccess(user.role)} session={setSession} openServers={() => navigate('nodes')} openSources={() => navigate('sources')} />}{view === 'legacy-subscriptions' && canReadAccess(user.role) && <Subscriptions api={api} canWrite={canWriteAccess(user.role)} intents={subscriptionIntents} />}{view === 'constructor' && <Constructor api={api} canEdit={canWriteNodes(user.role)} canPublish={canWriteAccess(user.role)} session={builderSession} />}{view === 'sources' && <Sources api={api} canWrite={canWriteNodes(user.role)} intents={sourceIntents} />}{view === 'nodes' && <Servers api={api} canWrite={canWriteNodes(user.role)} intents={nodeIntents} />}{view === 'admins' && user.role === 'owner' && <Admins api={api} currentUser={user} onSelfChanged={() => leave(new ApiError('unauthenticated', 401))} />}{view === 'audit' && (user.role === 'owner' || user.role === 'auditor') && <Audit api={api} />}</main><footer className="page-footer"><span>САЛФЕТКА · Управление</span><span>Самостоятельная панель</span></footer></div></div>
}
