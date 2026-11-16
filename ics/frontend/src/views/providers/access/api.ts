// Client for the connection / access-management wizard (ADR-0016). The password and the second-factor code are sent once and never kept here.
// Everything that changes Proxmox is a typed action (plan -> approval -> job) posted to /plans with `admin_session`.
import { get, post, request } from '../../../api'
import type { PlanCreated } from '../../../api'

export interface TlsLookup { presented_fingerprint_sha256?: string; subject?: string; not_after?: string; public_ca: boolean; verify_hint: string; error?: string }
export interface PveSession {
  id: string; base_url: string; trust: 'public_ca' | 'ca' | 'fingerprint'; username: string
  state: 'need_tfa' | 'ready' | 'used' | 'cancelled' | 'expired' | 'failed'
  tfa_methods: ('totp' | 'recovery' | 'yubico' | 'webauthn')[]; webauthn_only: boolean; expires_at: string
}
export type Authz = 'operated' | 'template' | 'deployment_pool' | 'protected' | 'authorized' | 'not_authorized'
export interface InvGuest { vmid: number; type: 'qemu' | 'lxc'; name: string; node: string; status: string; cpus: number; cpu: number; mem: number; maxmem: number; maxdisk: number; pool: string | null; template: boolean; tags: string; authorization?: Authz; seen?: boolean }
export interface InvNode { name: string; status: string; cpu: number; maxcpu: number; mem: number; maxmem: number; uptime: number; audited: boolean; guests: number[]; authorization?: Authz; seen?: boolean }
export interface InvStorage { storage: string; type: string; content: string; shared: boolean; nodes: string[]; used: number; total: number; authorization?: Authz; seen?: boolean }
export interface InvNetwork { name: string; kind: 'bridge' | 'vnet'; zone: string | null; nodes: string[]; comment?: string; authorization?: Authz; seen?: boolean }
export interface Inventory {
  cluster: { name: string; standalone: boolean; quorate: boolean; version: string; nodes_total: number; nodes_online: number; cpu: { used: number; total: number }; mem: { used: number; total: number }; storage: { used: number; total: number }; guests: number; vms: number; containers: number }
  nodes: InvNode[]; guests: InvGuest[]; storages: InvStorage[]; networks: InvNetwork[]; pools: string[]
  account: { ok: boolean; missing: { path: string; privilege: string }[]; remediation: string | null }
  notes: string[]
  missing?: { kind: string; key: string }[]
  approved_scope?: { nodes: string[]; pools: string[]; storages: string[]; networks: string[]; templates: number[]; managed_vmids: number[]; protected_vmids: number[]; preset?: string | null; allow_migrate?: boolean }
}
export interface AccessRow { kind: 'node' | 'guest' | 'storage' | 'network'; key: string; name: string | null; node: string | null; type: string | null; pool: string | null; authorization: Authz; state: 'new' | 'known' | 'missing' | 'renamed' | 'moved' | 'identity_changed'; change: unknown; first_seen: string; last_seen: string; missing_since: string | null }
export interface AccessView { endpoint_id: string; counts: { new: number; changed: number; missing: number; authorized: number }; resources: AccessRow[]; visibility: string }

export const accessApi = {
  tls: (base_url: string) => post<TlsLookup>('pve-sessions/tls', { base_url }),
  signIn: (b: { base_url: string; trust: string; ca_pem?: string; fingerprint_sha256?: string; username: string; realm: string; password: string; customer_id?: string }) =>
    post<PveSession>('pve-sessions', b),
  tfa: (id: string, method: string, code: string) => post<PveSession>(`pve-sessions/${id}/tfa`, { method, code }),
  session: (id: string) => get<PveSession>(`pve-sessions/${id}`),
  inventory: (id: string, endpointId?: string) => get<Inventory>(`pve-sessions/${id}/inventory${endpointId ? `?endpoint_id=${endpointId}` : ''}`),
  signOut: (id: string) => request<unknown>('DELETE', `pve-sessions/${id}`),
  access: (endpointId: string) => get<AccessView>(`endpoints/${endpointId}/access`),
  acknowledge: (endpointId: string, keys?: [string, string][]) => post<{ acknowledged: number }>(`endpoints/${endpointId}/access/acknowledge`, keys ? { keys } : {}),
  submit: (action: string, params: Record<string, unknown>) => post<PlanCreated>('plans', { action, params }),
}
