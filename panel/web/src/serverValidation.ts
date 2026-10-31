import { ApiError } from './api'

export type ServerField = 'name' | 'address' | 'domain'
export type ServerValues = Record<ServerField, string>
export type ServerErrors = Partial<Record<ServerField, string>>
export const serverFields: ServerField[] = ['name', 'address', 'domain']
const fields: Record<string, ServerField> = {
 server_name_invalid: 'name', server_address_invalid: 'address',
 server_address_multicast: 'address', server_address_unspecified: 'address', server_domain_invalid: 'domain',
}
export function serverErrorField(error: unknown) {
 return error instanceof ApiError ? fields[error.code] : undefined
}
function ipv4(value: string): number[] | undefined {
 const parts = value.split('.')
 if (parts.length !== 4 || parts.some(p => !/^(0|[1-9][0-9]{0,2})$/.test(p) || Number(p) > 255)) return
 return parts.map(Number)
}
function ip(value: string): number[] | undefined {
 if (!value.includes(':')) return ipv4(value)
 if (!/^[0-9a-f:.]+$/i.test(value)) return
 if (value.includes('.') && !ipv4(value.slice(value.lastIndexOf(':') + 1))) return
 try {
  // URL parses IPv6 locally; no request is made. It also normalizes embedded IPv4.
  const host = new URL(`https://[${value}]/`).hostname.slice(1, -1)
  const halves = host.split('::'), left = halves[0] ? halves[0].split(':') : []
  const right = halves[1] ? halves[1].split(':') : []
  const parts = halves.length === 2 ? [...left, ...Array(8-left.length-right.length).fill('0'), ...right] : left
  const words = parts.map(p => parseInt(p,16))
  if (words.length !== 8 || words.some(Number.isNaN)) return
  if (words.slice(0,5).every(w => w === 0) && words[5] === 65535) return [words[6]>>8, words[6]&255, words[7]>>8, words[7]&255]
  return words
 } catch { return }
}
export function validateServer(values: ServerValues): ServerErrors {
 const errors: ServerErrors = {}, name = values.name.trim(), address = values.address.trim()
 const domain = values.domain.trim().toLowerCase().replace(/\.$/,'')
 const message = (code: string) => new ApiError(code).message
 if ([...name].length < 2 || [...name].length > 80 || /[\u0000-\u001f\u007f-\u009f]/u.test(name)) errors.name = message('server_name_invalid')
 const parts = ip(address)
 if (!parts) errors.address = message('server_address_invalid')
 else if (parts.every(p => p === 0)) errors.address = message('server_address_unspecified')
 else if (parts.length === 4 ? parts[0] >= 224 && parts[0] <= 239 : parts[0] >= 0xff00) errors.address = message('server_address_multicast')
 if (domain.length > 253 || !domain.includes('.') || ip(domain) || domain.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) errors.domain = message('server_domain_invalid')
 return errors
}
