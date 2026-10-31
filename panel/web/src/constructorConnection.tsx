import { useState } from 'react'
import { ApiClient, ApiError } from './api'
import { Notice } from './components'
import { source } from './sources'
import type { Source } from './sources'
import type { BuilderSession, Network } from './constructorModel'

// Credentials exist only inside this form and the encrypted source API.
export function ConnectionForm({ api, session, network, added, close }: { api: ApiClient; session: BuilderSession; network?: Network; added: (s: Source) => Promise<void>; close: () => void }) {
 const [engine, setEngine] = useState('xray'), [name, setName] = useState('Новое подключение'), [host, setHost] = useState(''), [port, setPort] = useState('443'), [key, setKey] = useState(''), [sni, setSNI] = useState(''), [room, setRoom] = useState(''), [provider, setProvider] = useState('jitsi'), [transport, setTransport] = useState('datachannel'), [dns, setDNS] = useState('1.1.1.1:53'), [carrier, setCarrier] = useState('yandex'), [error, setError] = useState<unknown>(), [busy, setBusy] = useState(false)
 const pending = session.get('builder-source')
 const submit = async () => {
  let savedMutation = false
  if (busy) return; setBusy(true); setError(undefined)
  try {
   let intent = session.get('builder-source')
   if (!intent) {
    if (!network?.probe.url || !network.probe.ipv4 || !network.probe.body_sha256) throw new ApiError('builder_network_required')
    const settings = engine === 'xray' ? { outbound: { protocol: 'vless', settings: { vnext: [{ address: host, port: Number(port), users: [{ id: key, encryption: 'none' }] }] }, streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: sni || host, allowInsecure: false } } } } : engine === 'olcrtc' ? { provider, transport, room, key_hex: key, bootstrap_dns: dns } : { encryption_secret: key, transport: carrier, document_url: room }
    const id = crypto.randomUUID()
    const manifest = { format: 'salfetka.subscription', version: 1, id, revision: 1, subscription: { title: name }, network, connections: [{ id: 'connection', engine, settings }], locations: [{ id: 'location', title: name, mode: engine === 'xray' ? 'vpn' : 'bypass', kind: 'location', connection_ids: ['connection'], selection: { type: 'first_working' } }] }
    const d = await api.request<{ id: string }>('/sources/preview', { method: 'POST', body: { name, kind: 'upload', input: JSON.stringify(manifest) } })
    if (!/^[0-9a-f-]{36}$/.test(d?.id)) throw new ApiError('invalid_response')
    intent = session.begin('builder-source', { path: '/sources/mutate', method: 'POST', label: 'Создание подключения', body: { operation: 'create', id: '', revision: 0, draft_id: d.id, version_id: '', paused: false } })
   }
   const saved = source(await api.request<Source>(intent.path, { method: intent.method, body: intent.body, headers: { 'Idempotency-Key': intent.key } }))
   savedMutation = true; setKey(''); setRoom(''); await added(saved); session.finish('builder-source', intent.key); close()
  } catch (e) { const intent = session.get('builder-source'); if (intent && !savedMutation) session.failed('builder-source', intent.key, e); setError(e) } finally { setBusy(false) }
 }
 return <section className="card form-card builder-connection"><h2>Новое внешнее подключение</h2><p>Сохраняется отдельным зашифрованным источником. Его сервером и ключами управляет владелец внешнего сервера.</p>{error != null && <Notice error={error} />}{pending && <Notice kind="info">Результат сохранения неизвестен. Повтор использует тот же запрос.</Notice>}<fieldset disabled={busy || !!pending}>
 <label>Название подключения<input value={name} maxLength={80} onChange={e => setName(e.target.value)} /></label><label>Тип подключения<select value={engine} onChange={e => { setEngine(e.target.value); setKey('') }}><option value="xray">VPN · VLESS TCP/TLS</option><option value="olcrtc">Обход · olcRTC</option><option value="openflux">Обход · OpenFlux</option></select></label>
 {engine === 'xray' ? <div className="builder-grid"><label>Адрес сервера<input value={host} onChange={e => setHost(e.target.value)} /></label><label>Порт<input type="number" value={port} onChange={e => setPort(e.target.value)} /></label><label>SNI<input value={sni} onChange={e => setSNI(e.target.value)} /></label></div> : <><label>Адрес комнаты или документа<input value={room} onChange={e => setRoom(e.target.value)} autoComplete="off" /></label>{engine === 'olcrtc' ? <div className="builder-grid"><label>Провайдер<select value={provider} onChange={e => setProvider(e.target.value)}>{['jitsi', 'telemost', 'wbstream', 'salutejazz', 'vkcalls'].map(v => <option key={v}>{v}</option>)}</select></label><label>Канал<select value={transport} onChange={e => setTransport(e.target.value)}>{['datachannel', 'vp8channel', 'seichannel'].map(v => <option key={v}>{v}</option>)}</select></label><label>Bootstrap DNS<input value={dns} onChange={e => setDNS(e.target.value)} /></label></div> : <label>Провайдер OpenFlux<select value={carrier} onChange={e => setCarrier(e.target.value)}>{['yandex', 'vyandex', 'boards', 'mailru', 'cupsonline'].map(v => <option key={v}>{v}</option>)}</select></label>}</>}
 <label>{engine === 'xray' ? 'UUID подключения' : engine === 'olcrtc' ? 'Ключ hex (64 символа)' : 'Секрет канала'}<input type="password" autoComplete="off" value={key} onChange={e => setKey(e.target.value)} /></label></fieldset>
 <p className="field-hint">Проверяется совместимость формата. Подключение к внешнему серверу и индивидуальный отзыв его ключей этим не подтверждаются. Другие транспорты и полные native JSON можно импортировать в «Источниках».</p><div className="builder-actions"><button className="button primary" disabled={busy} onClick={() => void submit()}>{pending ? 'Повторить сохранение подключения' : 'Проверить и сохранить подключение'}</button><button className="button secondary" disabled={busy || !!pending} onClick={() => { setKey(''); setRoom(''); close() }}>Отменить создание подключения</button></div></section>
}
