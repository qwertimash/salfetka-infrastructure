import { AccessIntents } from './accessIntent'
import type { Enrollment } from './nodeApi'

// Separate from access mutations, owned by the authenticated shell. In-flight
// requests and one-time secrets survive route changes, never session storage.
export class NodeIntents extends AccessIntents {
  busy = new Set<string>()
  private secrets = new Map<string, Enrollment>()
  saveSecret(value: Enrollment) { this.secrets.set(value.node_id, value) }
  secret(id: string) {
    const value = this.secrets.get(id)
    if (value && Date.parse(value.expires_at) <= Date.now()) { this.secrets.delete(id); return undefined }
    return value
  }
  forgetSecret(id: string) { this.secrets.delete(id) }
}
