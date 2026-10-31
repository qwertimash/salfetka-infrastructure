import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiClient } from './api'
import type { Page } from './api'
import { AccessIntents } from './accessIntent'
import type { UserDetail } from './accessApi'
import { nodesPage } from './nodeApi'
import type { Node } from './nodeApi'
import { downloadConfig, vpnStatus, vpnFresh, bytes } from './vpnApi'
import type { VPNStatus } from './vpnApi'
import { registerTrial, trialPending, trialBusy } from './trialDevice'
import { Freshness, Notice, formatDate } from './components'
import { useResource } from './useResource'

export function TrialVPN({ api, detail, intents, canWrite, changed }: { api: ApiClient; detail: UserDetail; intents: AccessIntents; canWrite: boolean; changed: () => void }) {
  const [nodeID, setNodeID] = useState(''), [deviceID, setDeviceID] = useState('')
  const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(), [downloaded, setDownloaded] = useState(false)
  const alive = useRef(true), inFlight = useRef(false)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const load = useCallback(async (signal: AbortSignal) => nodesPage(await api.request<Page<Node>>('/nodes?limit=100', { signal })), [api])
  const list = useResource(load, 15000)
  const loadStatus = useCallback(async (signal: AbortSignal) => nodeID ? vpnStatus(await api.request<VPNStatus>(`/nodes/${nodeID}/vpn`, { signal }), nodeID) : null, [api, nodeID])
  const status = useResource(loadStatus, 5000)
  const eligible = detail.devices.filter(d => d.state === 'registered' && d.decision.allowed)
  const selected = eligible.find(d => d.id === deviceID)
  const fresh = status.data && vpnFresh(status.data, Date.now(), status.error)
  const observed = status.data?.observed?.usage.find(u => u.grant_id === selected?.credential?.id)
  const perform = async (fn: () => Promise<void>) => {
    if (inFlight.current) return
    inFlight.current = true; setBusy(true); setError(undefined); setDownloaded(false)
    try { await fn() } catch (e) { if (alive.current) setError(e) } finally { inFlight.current = false; if (alive.current) setBusy(false) }
  }
  const pending = trialPending(intents, detail.user.id)
  return <section className="card access-section" aria-label="Тестовое VPN-подключение"><h3>Тестовое VPN-подключение</h3><p className="section-description">Создайте тестовое устройство, выберите настроенный узел и скачайте конфигурацию подключения. Файл содержит личный ключ доступа.</p>{error != null && <Notice error={error} />}{pending && <Notice kind="info">Регистрация ещё не подтверждена. Повтор использует прежний ключ и запрос.</Notice>}
    {canWrite && <button className="button secondary" disabled={busy || trialBusy(intents, detail.user.id) || !!intents.get(detail.user.id) || (!pending && (!(detail.decision.allowed || detail.decision.reason === 'no_eligible_device') || !detail.entitlement || Date.parse(detail.entitlement.expires_at) <= Date.now()))} onClick={() => void perform(async () => { const d = await registerTrial(api, intents, detail); if (alive.current) { setDeviceID(d.devices.find(v => v.name === 'Тестовый Xray' && v.state === 'registered')?.id ?? ''); changed() } })}>{pending ? 'Повторить регистрацию' : 'Добавить тестовое устройство'}</button>}
    <div className="entitlement-form"><label>Устройство<select value={deviceID} onChange={e => { setDeviceID(e.target.value); setDownloaded(false) }} disabled={busy}><option value="">Выберите устройство</option>{eligible.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}</select></label><label>VPN-узел<select value={nodeID} onChange={e => { setNodeID(e.target.value); setDownloaded(false) }} disabled={busy || !!list.error}><option value="">Выберите узел</option>{list.data?.items.filter(n => n.state === 'active').map(n => <option key={n.id} value={n.id}>{n.name}</option>)}</select></label></div>
    {list.error != null && <Notice error={list.error} />}{list.data?.next_cursor && <Notice kind="info">Показаны первые 100 узлов. Полный поиск появится в следующем этапе.</Notice>}{nodeID && <><Freshness resource={status} label="Обновить подключение" />{status.error != null && <Notice error={status.error} />}<p className="section-description">{fresh && observed?.active ? 'Движок подтвердил доступ устройства.' : 'Свежего подтверждения доступа устройства пока нет.'}</p>{observed && <p className="field-hint">Последний снимок {formatDate(status.data?.received_at ?? undefined)}: отправлено {bytes(observed.uplink)}, получено {bytes(observed.downlink)}. Счётчики текущего запуска.</p>}</>}
    {canWrite && <button className="button primary" disabled={busy || !selected || !nodeID || !fresh || !observed?.active || !status.data?.installation?.enabled || !status.data?.installation?.endpoint || !!list.error} onClick={() => void perform(async () => { const config = await api.request<unknown>(`/access/users/${detail.user.id}/devices/${deviceID}/vpn-config`, { method: 'POST', body: { node_id: nodeID } }); if (alive.current) { downloadConfig(config); setDownloaded(true) } })}>Скачать конфигурацию {status.data?.installation?.endpoint?.backend === 'olcrtc' ? 'olcRTC' : 'Xray'}</button>}
    {downloaded && <Notice kind="success">Конфигурация скачана. Локальный SOCKS-прокси: 127.0.0.1:10808. Передавайте файл только владельцу устройства.</Notice>}
  </section>
}
