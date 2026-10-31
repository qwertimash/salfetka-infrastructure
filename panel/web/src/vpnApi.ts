import { ApiError } from './api'
export type VPNEndpoint = { backend?: string; account_session?: boolean; personal_rooms?: boolean; provider?: string; transport?: string; room?: string; bootstrap_dns?: string; host: string; port: number; server_name: string; trusted_ca_pem?: string }
export type VPNInstallation = { node_id: string; installation_id: string; group_id: string; enabled: boolean; node_revision: number; endpoint: VPNEndpoint | null }
export type VPNUsage = { grant_id: string; instance_epoch: string; generation: number; active: boolean; ready?: boolean; uplink: number | null; downlink: number | null }
export type VPNStatus = { node_id: string; installation: VPNInstallation | null; desired_generation: number; policy_expires_at: string | null; state: 'not_configured' | 'pending' | 'applied' | 'stale' | 'node_revoked'; received_at: string | null; observed: null | { engine_epoch: string; sequence: number; observed_at: string; usage: VPNUsage[]; receipt: { generation: number; completed_at: string; status: string } } }
const id = (s: unknown) => typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)
const date = (s: unknown) => typeof s === 'string' && Number.isFinite(Date.parse(s))
const integer = (n: unknown) => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0
function check(value: unknown): asserts value { if (!value) throw new ApiError('invalid_response') }
export function installation(v: VPNInstallation, node: string) {
  check(v && v.node_id === node && id(v.installation_id) && id(v.group_id) && typeof v.enabled === 'boolean' && integer(v.node_revision) && v.node_revision > 0)
  const e = v.endpoint
  check(e === null || e && ['', 'hysteria2', 'olcrtc'].includes(e.backend ?? ''))
  if(e) { check((e.account_session === undefined || typeof e.account_session === 'boolean') && (e.personal_rooms === undefined || typeof e.personal_rooms === 'boolean') && (!e.personal_rooms || e.backend === 'olcrtc' && e.account_session === true)); if(e.backend === 'olcrtc') check(typeof e.room === 'string' && typeof e.provider === 'string' && typeof e.transport === 'string' && typeof e.bootstrap_dns === 'string' && e.host === '' && e.port === 0 && e.server_name === '')
  else check(typeof e.host === 'string' && typeof e.server_name === 'string' && integer(e.port) && e.port >= 1 && e.port <= 65535 && (e.trusted_ca_pem === undefined || typeof e.trusted_ca_pem === 'string')) }

  return v
}
export function vpnStatus(v: VPNStatus, node: string) {
  check(v && v.node_id === node && integer(v.desired_generation) && ['not_configured', 'pending', 'applied', 'stale', 'node_revoked'].includes(v.state))
  if (v.installation !== null) installation(v.installation, node)
  check(v.policy_expires_at === null || date(v.policy_expires_at)); check(v.received_at === null || date(v.received_at))
  if (v.observed !== null) {
    const o = v.observed
    check(o && /^[0-9a-f]{32}$/.test(o.engine_epoch) && integer(o.sequence) && o.sequence > 0 && date(o.observed_at) && o.receipt && integer(o.receipt.generation) && o.receipt.status === 'applied' && date(o.receipt.completed_at) && Array.isArray(o.usage))
    const seen = new Set<string>()
    for (const u of o.usage) { check(id(u.grant_id) && !seen.has(u.grant_id) && u.instance_epoch === o.engine_epoch && u.generation === o.receipt.generation && typeof u.active === 'boolean' && (u.ready === undefined || typeof u.ready === 'boolean') && (u.uplink === null || integer(u.uplink)) && (u.downlink === null || integer(u.downlink))); seen.add(u.grant_id) }
  }
  return v
}
export function vpnFresh(v: VPNStatus, now: number, error?: unknown) {
  return !error && v.state === 'applied' && v.received_at !== null && now - Date.parse(v.received_at) >= -5000 && now - Date.parse(v.received_at) < 20_000 && v.observed !== null && now - Date.parse(v.observed.observed_at) >= -5000 && now - Date.parse(v.observed.observed_at) < 25_000 && v.policy_expires_at !== null && now < Date.parse(v.policy_expires_at)
}
export function bytes(value: number | null) { return value === null ? 'Нет данных' : `${value.toLocaleString('ru-RU')} Б` }
export function downloadConfig(config: unknown) {
  const c = config as { key_hex?: string; room?: string; inbounds?: unknown[]; outbounds?: { protocol?: string }[] }
  if (!c || !(typeof c.key_hex === 'string' && /^[0-9a-f]{64}$/.test(c.key_hex) && typeof c.room === 'string') && (!Array.isArray(c.inbounds) || !Array.isArray(c.outbounds) || c.outbounds.length !== 1 || !['vless','hysteria'].includes(c.outbounds[0].protocol ?? ''))) throw new ApiError('invalid_response')
  const url = URL.createObjectURL(new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' }))
  const a = document.createElement('a'); a.href = url; a.download = c.key_hex ? 'salfetka-trial-olcrtc.json' : 'salfetka-trial-xray.json'; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000)
}
