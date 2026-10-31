export type Role = 'owner' | 'access_operator' | 'infrastructure_operator' | 'support' | 'auditor'
export type User = { id: string; username: string; role: Role; disabled?: boolean; revision?: number }
export type Session = { user: User; csrf_token: string }
export type Admin = User & { disabled: boolean; revision: number; created_at: string; updated_at: string }
export type Overview = { service_status: string; database_status: string; counts: { admins: number; jobs_pending: number; jobs_failed: number }; vpn_status: 'not_configured' | 'per_node' }
export type Operation = { id: string; kind: string; status: string; created_at: string; updated_at?: string; error_code?: string | null; attempts?: number; max_attempts?: number; finished_at?: string }
export type AuditItem = { id: string; action: string; actor_id?: string; target_id?: string; outcome?: string; created_at: string }
export type Page<T> = { items: T[]; next_cursor?: string | null }

const messages: Record<string, string> = {
  subscription_set_invalid: 'Проверьте состав подписки. Общие пользовательские ключи в наборах запрещены.',
  subscription_set_conflict: 'Подписка уже изменилась. Ваши правки остались в форме; отмените их и откройте актуальную версию.',
  subscription_set_not_found: 'Набор или назначение не найдено. Обновите список.',
  subscription_set_capacity: 'Достигнут предел наборов или версий.',
  publication_unavailable: 'Публикация пока недоступна. Проверьте состав и права доступа.',
  publication_conflict: 'Версия изменилась. Откройте актуальный набор перед публикацией.',
  release_unavailable: 'У сервера ещё нет включённого подключения VPN. Настройте его в разделе «Серверы».',
  clipboard_unavailable: 'Копирование недоступно. Выделите ссылку и скопируйте вручную.',
  antifraud_not_configured: 'Защита от перерасхода ещё не подключена к этой панели. Ограничения этим разделом не включены.',
  antifraud_unavailable: 'Нет связи со службой защиты от перерасхода. Состояние ограничений неизвестно.',
  antifraud_conflict: 'Состояние случая изменилось. Обновите данные перед повтором.',
  subscription_denied: 'Доступ пользователя или устройства закрыт. Проверьте срок и блокировки.',
  subscription_unavailable: 'Подписка пока не готова к выдаче. Проверьте версию, ключ устройства и узлы.',
  release_conflict: 'Права или настройки изменились после сборки. Обновите данные и соберите новую версию.',
  release_capacity: 'Достигнут предел 100 версий для этого устройства.',
  release_policy_conflict: 'Правила конфликтуют. Проверьте владельца маршрутов, совместимость источников и порядок исключений. Прежняя опубликованная версия сохранена.',
  release_mapping_required: 'Для этого источника нужно явно настроить локации и проверку соединения. Это будет доступно в конструкторе.',
  release_capability: 'Клиент не поддерживает полный состав подписки. Версия не опубликована.',

  source_invalid_json: 'Некорректный JSON: проверьте синтаксис, повторяющиеся поля и вложенность.',
  source_size: 'Источник превышает предел 512 КБ или 32 подключения. Сохранение не выполнено.',
  source_unsupported: 'Источник содержит неподдерживаемый формат, транспорт или неизвестные параметры. Настройки не были удалены или сохранены частично.',
  source_routing_invalid: 'Маршруты или группы источника несовместимы: проверьте ссылки на подключения, Auto, DNS и владельца правил.',
  source_invalid: 'Источник не прошёл проверку. Проверьте формат, параметры и полноту конфига. Ни одно подключение не сохранено.',
  source_expired: 'Срок источника истёк. Нужна действующая версия; прежние настройки сохранены.',
  source_tls_required: 'Источник отключает проверку TLS. Исправьте параметры безопасности.',
  source_address_denied: 'Нужна публичная HTTPS-ссылка без логина и пароля в адресе. Локальные и служебные адреса запрещены.',
  source_fetch_failed: 'Не удалось загрузить подписку. Проверьте ссылку и доступность сервера источника.',
  source_draft_expired: 'Предпросмотр устарел. Проверьте источник заново перед сохранением.',
  source_capacity: 'Достигнут предел источников или версий. Новые данные не заменили сохранённые настройки.',

  builder_conflict: 'Черновик уже изменён. Ваши правки сохранены в форме; откройте актуальную версию после отмены или сохраните отдельную копию.',
  builder_capacity: 'Достигнут предел конфигураций или сохранённых версий. Существующие документы сохранены.',
  builder_network_required: 'Сначала задайте сетевые настройки и проверку HTTPS в разделе «Маршруты и DNS» или выберите источник с готовыми параметрами.',
  builder_model_invalid: 'JSON модели некорректен. Исходный черновик сохранён.',
  diagnostics_not_configured: 'Сборщик диагностики ещё не подключён к этой панели. Нужна серверная настройка защищённого чтения.',
  diagnostics_unavailable: 'Нет связи со сборщиком диагностики. Данные могут быть устаревшими; это не означает отказ VPN.',
  server_name_invalid: 'Название должно содержать от 2 до 80 символов без управляющих символов.',
  server_address_invalid: 'Введите IP сервера в формате IPv4 или IPv6, без https://, порта и маски сети.',
  server_address_multicast: 'Это адрес групповой рассылки (multicast). Укажите публичный IP вашего VPS из кабинета хостинга.',
  server_address_unspecified: 'Это адрес прослушивания всех интерфейсов. Укажите конкретный IP вашего сервера.',
  server_domain_invalid: 'Введите поддомен, например pol.example.com, без https://, порта и пути. Кириллический домен укажите в punycode.',
  invalid_request: 'Проверьте заполненные поля и повторите попытку.',
  invalid_credentials: 'Неверное имя пользователя или пароль.',
  unauthenticated: 'Сессия завершена. Войдите снова.',
  forbidden: 'У вашей роли нет доступа к этому действию.',
  csrf_failed: 'Проверка сессии не пройдена. Войдите снова.',
  origin_failed: 'Адрес панели не соответствует настройкам сервера.',
  rate_limited: 'Слишком много попыток. Подождите и повторите позже.',
  setup_unavailable: 'Первоначальная настройка недоступна. Проверьте токен или перейдите ко входу.',
  revision_conflict: 'Запись уже изменена. Обновите список перед сохранением.',
  last_owner: 'Нельзя отключить или изменить роль последнего владельца.',
  conflict: 'Такая запись уже существует или операция конфликтует с текущим состоянием.',
  not_found: 'Запись больше не найдена. Обновите список.',
  unavailable: 'Сервер временно недоступен. Попробуйте снова.',
  internal_error: 'Не удалось выполнить действие. Попробуйте снова.',
  network_error: 'Нет связи с панелью. Проверьте соединение и повторите попытку.',
  request_timeout: 'Сервер не ответил вовремя. Попробуйте снова.',
  invalid_response: 'Сервер вернул неожиданный ответ. Попробуйте обновить данные.',
  logout_unconfirmed: 'Выход на сервере не подтверждён. Данные панели скрыты; сессия на сервере ещё может действовать.',
  worker_error: 'Обработчик не смог завершить проверку.',
  lease_expired: 'Обработчик не подтвердил выполнение задачи вовремя.',
  terminal_entitlement: 'Это право уже отозвано или возвращено. Для нового доступа используйте явное восстановление.',
  device_limit: 'Лимит устройств исчерпан. Измените лимит или отзовите старое устройство.',
  device_bound: 'Ключ установки уже принадлежит другому пользователю.',
  proof_invalid: 'Не удалось подтвердить ключ устройства.',
  challenge_expired: 'Подтверждение устройства просрочено. Запросите новое.',
  challenge_used: 'Подтверждение устройства уже использовано.',
  node_vpn_capacity: 'Группа превышает текущий предел: 128 устройств или 512 пользователей.',
  node_configuration_unavailable: 'Ключи управления узлами недоступны. Проверьте настройку сервера.',
  node_enrollment_expired: 'Срок файла подключения истёк. Создайте новый.',
  node_enrollment_invalid: 'Файл подключения уже использован или отозван.',
  key_unavailable: 'Ключ установки недоступен. Изменение не подтверждено; проверьте настройку сервера.',
}

export class ApiError extends Error {
  constructor(public code: string, public status = 0, public requestId?: string) {
    super(messages[code] ?? 'Не удалось выполнить действие. Попробуйте снова.')
  }
  get outcomeUnknown() { return this.status === 0 || this.status >= 500 }
}

export function safeError(error: unknown): string {
  if (!(error instanceof ApiError)) return messages.internal_error
  return error.message + (error.requestId ? ` Код обращения: ${error.requestId}.` : '')
}

export function parseSession(value: unknown): Session {
  const s = value as Session
  const roles: Role[] = ['owner', 'access_operator', 'infrastructure_operator', 'support', 'auditor']
  if (!s || typeof s.csrf_token !== 'string' || !s.csrf_token || !s.user || typeof s.user.id !== 'string' || typeof s.user.username !== 'string' || !roles.includes(s.user.role)) throw new ApiError('invalid_response')
  return s
}

export function validateNewPassword(password: string) {
  const bytes = new TextEncoder().encode(password).length
  if (bytes < 12 || bytes > 128) throw new ApiError('invalid_request')
}

export class ApiClient {
  private csrf = ''
  private controllers = new Set<AbortController>()
  onUnauthorized?: () => void
  setSession(s: Session) { this.csrf = s.csrf_token }
  clear() {
    this.csrf = ''
    for (const controller of this.controllers) controller.abort()
    this.controllers.clear()
  }

  async request<T>(path: string, options: { method?: string; body?: unknown; signal?: AbortSignal; headers?: Record<string, string> } = {}): Promise<T> {
    const controller = new AbortController()
    this.controllers.add(controller)
    const externalAbort = () => controller.abort(options.signal?.reason)
    if (options.signal?.aborted) externalAbort()
    else options.signal?.addEventListener('abort', externalAbort, { once: true })
    let timedOut = false
    const timeout = setTimeout(() => { timedOut = true; controller.abort() }, 12_000)
    const method = options.method ?? 'GET'
    const headers: Record<string, string> = { Accept: 'application/json', ...options.headers }
    if (options.body !== undefined) headers['Content-Type'] = 'application/json'
    if (method !== 'GET' && path !== '/setup' && path !== '/auth/login') headers['X-CSRF-Token'] = this.csrf
    try {
      const response = await fetch(`/api/v1${path}`, { method, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body), credentials: 'same-origin', cache: 'no-store', signal: controller.signal })
      if (!response.ok) {
        let body: { error?: { code?: unknown; request_id?: unknown } } = {}
        try { body = await response.json() } catch { /* Never render server text/HTML. */ }
        const code = typeof body.error?.code === 'string' && body.error.code in messages ? body.error.code : response.status === 401 ? 'unauthenticated' : 'internal_error'
        const id = typeof body.error?.request_id === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(body.error.request_id) ? body.error.request_id : undefined
        if (response.status === 401 && path !== '/auth/login' && path !== '/auth/session') this.onUnauthorized?.()
        throw new ApiError(code, response.status, id)
      }
      if (response.status === 204) return undefined as T
      try { return await response.json() as T } catch { throw new ApiError('invalid_response') }
    } catch (error) {
      if (error instanceof ApiError) throw error
      if (options.signal?.aborted || controller.signal.aborted && !timedOut) throw new DOMException('Cancelled', 'AbortError')
      throw new ApiError(timedOut ? 'request_timeout' : 'network_error')
    } finally {
      clearTimeout(timeout)
      options.signal?.removeEventListener('abort', externalAbort)
      this.controllers.delete(controller)
    }
  }
}

// Kept in memory by the authenticated shell, so navigation and a lost response
// do not create a second job. Only a confirmed job response releases the key:
// a rejected retry cannot disprove an earlier commit whose response was lost.
export class OperationIntent {
  private pendingKey: string | null = null
  private unknownOutcome = false
  key() { return this.pendingKey ??= crypto.randomUUID() }
  failed(key: string, unknown: boolean) { if (this.pendingKey === key) this.unknownOutcome ||= unknown }
  finish(key?: string) { if (key === undefined || this.pendingKey === key) { this.pendingKey = null; this.unknownOutcome = false } }
  get uncertain() { return this.pendingKey !== null }
  get outcomeUnknown() { return this.unknownOutcome }
}

export const roles: Record<Role, string> = {
  owner: 'Владелец', access_operator: 'Оператор доступа', infrastructure_operator: 'Оператор инфраструктуры', support: 'Поддержка', auditor: 'Аудитор',
}
