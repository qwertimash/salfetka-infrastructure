import { ApiError } from './api'
import { AccessIntents } from './accessIntent'
import type { Preview } from './sources'
export type Mode = 'vpn' | 'bypass'
export type Network = { dns_servers: string[]; probe: { url: string; ipv4: string; expected_status: number; body_sha256: string } }
export type Rule = { id: string; action: 'direct' | 'tunnel'; match: { type: 'domain_exact' | 'domain_suffix' | 'ip_cidr' | 'geosite' | 'geoip'; value: string } }
export type Policy = { id: string; title: string; default_action: 'tunnel'; rules: Rule[] }
export type Choice = { authority: 'source' | 'personal' | 'custom'; source_id?: string; value?: Network | Policy }
export type Member = { source_id?: string; connection_id?: string; node_id?: string }
export type Location = { id: string; title: string; country?: string; icon?: string; mode: Mode; kind: 'location' | 'auto'; selection: 'native' | 'first_working'; members: Member[] }
export type Blueprint = { version: 1; network: Choice; routing: Record<Mode, Choice>; locations: Location[] }
export type Recipe = { source_id: string; version_id: string; sources: { id: string; version_id: string }[]; node_ids: string[]; external_credentials: boolean; max_version: number; engines: string[]; blueprint: Blueprint }
export type Document = { title: string; recipe: Recipe }
export type Draft = { id: string; revision: number; document: Document; updated_at: string }
export type Outline = { id: string; version_id: string; profiles: Preview['profiles']; network?: Network; routing?: Record<Mode, Policy>; locations?: { id: string; title: string; country?: string; icon?: string; mode: Mode; kind: Location['kind']; selection: { type: Location['selection'] }; connection_ids: string[] }[] }
export type WireLocation = { id: string; title: string; country?: string; mode: Mode; kind: string; selection: { type: string }; connection_ids: string[] }
export type Layout = { version: number; network: Network; routing: Partial<Record<Mode, Policy>>; locations: WireLocation[]; profiles: Preview['profiles']; policy_digest: string }
export type ReleasePreview = { candidate: Layout; current: Layout | null; user_id: string; device_id: string; node_ids: string[]; access_changed: false; server_restart: false; checks: { node_id: string; state: string }[] }
export const emptyNetwork = (): Network => ({ dns_servers: ['1.1.1.1', '8.8.8.8'], probe: { url: '', ipv4: '', expected_status: 204, body_sha256: '' } })
export const emptyDocument = (): Document => ({ title: 'Новая конфигурация', recipe: { source_id: '', version_id: '', sources: [], node_ids: [], external_credentials: false, max_version: 2, engines: ['xray', 'olcrtc', 'openflux'], blueprint: { version: 1, network: { authority: 'custom', value: emptyNetwork() }, routing: { vpn: { authority: 'personal' }, bypass: { authority: 'personal' } }, locations: [] } } })
export class BuilderSession extends AccessIntents { busy = false; saved?: Draft; document = emptyDocument(); outlines: Record<string, Outline> = {} }
export const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/
export const memberKey = (m: Member) => m.node_id ? `n:${m.node_id}` : `s:${m.source_id}:${m.connection_id}`
export function move<T>(items: T[], from: number, delta: number) { const result = [...items]; const to = from + delta; if (to >= 0 && to < items.length) [result[from], result[to]] = [result[to], result[from]]; return result }
export function parseDocument(v: Document): Document {
  const r = v?.recipe, b = r?.blueprint
  // The API omits an empty source list for drafts containing only owned nodes.
  if (r && r.sources === undefined) r.sources = []
  if (b?.routing) for (const mode of ['vpn', 'bypass'] as const) if (b.routing[mode] === undefined) b.routing[mode] = { authority: 'personal' }
  if (!v || typeof v.title !== 'string' || !r || !b || b.version !== 1 || !Array.isArray(r.sources) || r.sources.length > 16 || !Array.isArray(r.node_ids) || r.node_ids.length > 32 || !Array.isArray(r.engines) || ![1, 2].includes(r.max_version) || typeof r.external_credentials !== 'boolean' || !b.network || !b.routing || !Array.isArray(b.locations) || b.locations.length > 64) throw new ApiError('invalid_response')
  for (const ref of r.sources) if (!ref || !uuid.test(ref.id) || !uuid.test(ref.version_id)) throw new ApiError('invalid_response')
  for (const id of r.node_ids) if (!uuid.test(id)) throw new ApiError('invalid_response')
  for (const p of [b.network, b.routing.vpn, b.routing.bypass]) {
    if (!p || !['source', 'personal', 'custom'].includes(p.authority) || p.source_id !== undefined && typeof p.source_id !== 'string') throw new ApiError('invalid_response')
    if (p.authority === 'custom') {
      if (p === b.network) { const n = p.value as Network; if (!n || !Array.isArray(n.dns_servers) || n.dns_servers.some(s => typeof s !== 'string') || !n.probe || ['url', 'ipv4', 'body_sha256'].some(k => typeof n.probe[k as 'url'] !== 'string') || typeof n.probe.expected_status !== 'number') throw new ApiError('invalid_response') }
      else { const policy = p.value as Policy; if (!policy || typeof policy.id !== 'string' || typeof policy.title !== 'string' || policy.default_action !== 'tunnel' || !Array.isArray(policy.rules) || policy.rules.length > 256 || policy.rules.some(r => !r || typeof r.id !== 'string' || !['direct', 'tunnel'].includes(r.action) || !r.match || !['domain_exact', 'domain_suffix', 'ip_cidr', 'geosite', 'geoip'].includes(r.match.type) || typeof r.match.value !== 'string')) throw new ApiError('invalid_response') }
    }
  }
  for (const l of b.locations) if (!l || typeof l.id !== 'string' || typeof l.title !== 'string' || l.country !== undefined && typeof l.country !== 'string' || l.icon !== undefined && typeof l.icon !== 'string' || !['vpn', 'bypass'].includes(l.mode) || !['location', 'auto'].includes(l.kind) || !['first_working', 'native'].includes(l.selection) || !Array.isArray(l.members) || l.members.length > 32 || l.members.some(m => !m || typeof m !== 'object' || m.node_id !== undefined && typeof m.node_id !== 'string' || m.source_id !== undefined && typeof m.source_id !== 'string' || m.connection_id !== undefined && typeof m.connection_id !== 'string')) throw new ApiError('invalid_response')
  return v
}
export function parseDraft(v: Draft) { if (!v || !uuid.test(v.id) || !Number.isSafeInteger(v.revision) || v.revision < 1 || !Number.isFinite(Date.parse(v.updated_at))) throw new ApiError('invalid_response'); parseDocument(v.document); return v }
export function parseOutline(v: Outline) { if (!v || !uuid.test(v.id) || !uuid.test(v.version_id) || !Array.isArray(v.profiles) || v.profiles.length > 32 || v.profiles.some(p => !p || typeof p.id !== 'string' || !['xray', 'olcrtc', 'openflux'].includes(p.engine))) throw new ApiError('invalid_response'); return v }
export function parseReleasePreview(v: ReleasePreview, user: string, device: string) {
  if (!v || v.user_id !== user || v.device_id !== device || v.access_changed !== false || v.server_restart !== false || !Array.isArray(v.checks)) throw new ApiError('invalid_response')
  for (const l of [v.candidate, v.current]) if (l && (!/^[a-f0-9]{64}$/.test(l.policy_digest) || !Array.isArray(l.locations) || !Array.isArray(l.profiles) || !l.network || !l.routing)) throw new ApiError('invalid_response')
  if (!v.candidate) throw new ApiError('invalid_response'); return v
}
export function fromOutline(o: Outline): Location[] {
  if (o.locations) return o.locations.map(l => ({ ...l, id: crypto.randomUUID(), selection: l.selection.type, members: l.connection_ids.map(id => ({ source_id: o.id, connection_id: id })) })).map(({ connection_ids: _unused, ...l }) => l)
  return o.profiles.map((p, i) => ({ id: crypto.randomUUID(), title: `Подключение ${i + 1}`, mode: p.mode, kind: p.auto ? 'auto' : 'location', selection: p.native ? 'native' : 'first_working', members: [{ source_id: o.id, connection_id: p.id }] }))
}
