// ADR-0021: tenants (customers) as the console shows them. Read side only; changes stay typed actions.
import { get } from '../../api'

export interface TenantVm {
  name: string; role: string | null; components: string[]; cores: number | null; memory_mb: number | null; disk_gb: number; storage: string[]
  endpoint: string | null; node: string | null; vmid: number | null; state: string
  agent: { status: string; version: string | null; address: string; last_seen_at: string | null } | null
  health: { status: string; checks: number; failing: string[] }
}
export interface TenantDeployment { slug: string; status: string; domain: string | null; components: string[]; vms?: TenantVm[] }
export interface Tenant {
  id: string; slug: string; name: string; provisioning_mode: 'auto' | 'customer_approval' | 'monitoring_only'; msp_owned: boolean; disabled: boolean
  deployments: TenantDeployment[]; domains: string[]
  contact_name?: string | null; contact_email?: string | null; created_at?: string
}
export interface DnsRow {
  group: string; name: string; type: string; expected: string; status: 'ok' | 'missing' | 'differs' | 'unknown' | 'not_available'
  found: string[]; why: string; how: string; required: boolean
}
export interface DnsResult {
  deployment: string; domain: string | null; available: boolean; reason?: string; rows: DnsRow[]; checked_at: string | null
  cached?: boolean; public_ipv4?: string | null; summary?: Record<string, number>; note?: string
}

export const tenantsApi = {
  list: () => get<{ mode: 'single' | 'multi' | null; tenants: Tenant[] }>('tenants'),
  one: (id: string) => get<Tenant>(`tenants/${encodeURIComponent(id)}`),
  deploymentDns: (deployment: string, refresh = false) =>
    get<DnsResult>(`deployments/${encodeURIComponent(deployment)}/dns${refresh ? '?refresh=true' : ''}`),
  dns: (id: string, deployment: string, refresh = false) =>
    get<DnsResult>(`tenants/${encodeURIComponent(id)}/dns?deployment=${encodeURIComponent(deployment)}${refresh ? '&refresh=true' : ''}`),
}

export const MODE_LABEL: Record<Tenant['provisioning_mode'], string> = {
  auto: 'Changes run after your own approval', customer_approval: 'The tenant approves changes too', monitoring_only: 'Monitoring only',
}

/** Display of one DNS row: a missing optional record is a suggestion, not a failure. */
export function dnsTone(r: DnsRow): { s: string; text: string } {
  if (r.status === 'ok') return { s: 'ok', text: 'OK' }
  if (r.status === 'not_available') return { s: 'disabled', text: 'Not available' }
  if (r.status === 'unknown') return { s: 'unknown', text: 'Could not check' }
  const word = r.status === 'missing' ? 'Missing' : 'Different'
  return r.required ? { s: 'failed', text: word } : { s: 'pending', text: word + ' (optional)' }
}

export const DNS_GROUPS = ['Web names', 'Mail', 'Client setup', 'Certificates']
