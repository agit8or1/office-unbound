// SSH onboarding (ADR-0014): pure model + API helpers. The Vue page holds no logic beyond rendering this.
// Secrets (SSH password / private key / passphrase) live only in a non-reactive bag that is wiped right after the request that stores them.
import { post, get, request } from '../../api'
import type { PlanPreviewOut } from './model'

export type SshAuth = 'password' | 'key'
export type Rights = 'inventory' | 'deploy' | 'import' | 'custom'
export type ScopeMode = 'single_node' | 'whole_cluster'

export interface SshSecrets { password: string; privateKey: string; passphrase: string }
export const newSshSecrets = (): SshSecrets => ({ password: '', privateKey: '', passphrase: '' })
export function wipeSsh(s: SshSecrets): void { s.password = ''; s.privateKey = ''; s.passphrase = '' }

export interface SshSessionView {
  id: string; state: string; host: string; port: number; username: string; use_sudo: boolean; expires_at: string
  hostkey_candidate: string | null; hostkey_verify_command: string | null; hk_algo: string | null
  api_url?: string | null; api_trust?: string | null; api_proxy?: 'none' | 'pending' | 'confirmed'
}
export interface ApiCertificate {
  url: string; mode: 'public_ca' | 'cluster_ca' | 'fingerprint' | 'proxy_public'; explanation: string; node_leaf: string; seen_leaf: string
  ca_sha256: string | null; needs_confirmation: boolean; cross_check: string
}
export const TRUST_LABEL: Record<string, string> = {
  public_ca: 'Publicly trusted certificate: the issuing CA and the host name are pinned (renewals keep working)',
  cluster_ca: 'Cluster CA: the cluster\'s own CA and the host name are pinned',
  fingerprint: 'Certificate fingerprint pinned',
  proxy_public: 'Reverse proxy with a publicly trusted certificate (confirmed by you)',
}
export interface Overview {
  cluster_name: string | null; connected_node: string | null; pve_version: string; pve_major: number
  nodes: { name: string; status: string; ip: string | null; local: boolean }[]
  storages: { name: string; type: string; shared: boolean; content: string; nodes: string[] }[]
  networks: { name: string; zone: string; nodes: string[] }[]
  pools: string[]; templates: { vmid: number; name: string | null; node: string }[]
  guests: { total: number; running: number; templates: number; managed_by_ics: number }
  existing: { service_user: boolean; roles: string[]; pools: string[] }
  storage_usage?: {
    thin_pools: { vg: string; pool: string; storages: string[]; physical_bytes: number; data_percent: number | null; metadata_percent: number | null; provisioned_bytes: number; overprovision_ratio: number; warnings: string[] }[]
    zfs: { storage: string; pool: string; physical_bytes: number; used_bytes: number; provisioned_bytes: number; overprovision_ratio: number | null; warnings: string[] }[]
    note: string
  }
  firewall?: {
    datacenter_enabled: boolean; nodes: { name: string; node_firewall_option: number; rules: number; rules_enabled: number }[]
    nodes_with_rules: string[]; rules_would_become_active_on: string[]; note: string
  }
}
export const tib = (b: number): string => (b / 1024 ** 4).toFixed(2) + ' TiB'
export interface Identity {
  account: string; node: string; key_fingerprint: string; authorized_keys_line: string; helper_path: string; helper_sha256: string; conf_sha256: string
  sudoers_path: string; sudoers: string; sudoers_sha256: string
}
export interface SshPreviewOut extends Omit<PlanPreviewOut, 'plan_hash'> {
  bind_hash: string; risk: 'normal' | 'high'; commands: string[]; identity: Identity; blocked: string[]; rotates: string[]; approvals_required?: number; widening_note: string
  ssh: { host: string; port: number; username: string; host_key: string; api_url: string; api_trust: string; api_ca_sha256: string | null; api_leaf_pinned: string | null }
  plan: PlanPreviewOut['plan'] & { plan_hash: string }
}

export interface Choice {
  mode: ScopeMode; nodes: string[]; poolMode: 'new' | 'existing'; pool: string; storages: string[]; networks: string[]; templates: number[]
  rights: Rights; advanced: string[]
}
export const DEFAULT_POOL = 'officeunbound'
export const newChoice = (): Choice => ({ mode: 'single_node', nodes: [], poolMode: 'new', pool: DEFAULT_POOL, storages: [], networks: [], templates: [], rights: 'deploy', advanced: [] })

export const RIGHTS: { id: Rights; title: string; text: string }[] = [
  { id: 'inventory', title: 'See inventory only', text: 'Read nodes, storage, networks and guests. Cannot create or change anything.' },
  { id: 'deploy', title: 'Deploy into this pool', text: 'Create and operate VMs inside one pool, using the storage, networks and templates you choose.' },
  { id: 'import', title: 'Import images', text: 'Deploy, plus upload and use disk images on the chosen storage.' },
  { id: 'custom', title: 'Advanced: choose privileges', text: 'Tick the permission groups yourself. The exact Proxmox privileges are shown before anything runs.' },
]
export const ADVANCED = [
  { id: 'monitor', title: 'Monitor' }, { id: 'deploy', title: 'Deploy and manage VMs' }, { id: 'template_clone', title: 'Clone from templates' },
  { id: 'storage', title: 'Manage storage' }, { id: 'network', title: 'Manage networks' }, { id: 'backup', title: 'Back up guests' },
]

/** The backend Policy for a choice; the existing permission-plan generator turns it into roles, ACL paths and privileges. */
export function policyOf(c: Choice) {
  const caps = c.rights === 'import' ? ['monitor', 'deploy', 'storage', 'template_clone'] : c.rights === 'custom' ? c.advanced : []
  const preset = c.rights === 'inventory' ? 'monitoring' : c.rights === 'deploy' ? 'deploy' : 'custom'
  return {
    preset, ...(caps.length && preset === 'custom' ? { capabilities: caps } : {}), scope_mode: c.mode, service_user: 'officeunbound',
    scope: {
      nodes: c.mode === 'single_node' ? c.nodes : [], storages: c.storages, networks: c.networks, template_vmids: c.templates,
      pools: c.rights === 'inventory' ? [] : [c.pool],
    },
  }
}

export function validateChoice(c: Choice): Record<string, string> {
  const e: Record<string, string> = {}
  if (c.mode === 'single_node' && c.nodes.length < 1) e.nodes = 'Choose the node.'
  if (c.rights !== 'inventory' && !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/.test(c.pool)) e.pool = 'Use letters, digits, . _ - only.'
  if (c.rights !== 'inventory' && !c.storages.length) e.storages = 'Choose at least one storage.'
  if (c.rights === 'custom' && !c.advanced.length) e.advanced = 'Tick at least one permission group.'
  if (c.rights === 'inventory' && c.mode === 'whole_cluster' && !c.nodes.length && !c.storages.length) { /* whole-cluster monitoring needs no names */ }
  return e
}

export interface SshForm { host: string; port: number; username: string; auth: SshAuth; apiUrl: string; icsAddress: string }
export const newForm = (): SshForm => ({ host: '', port: 22, username: 'root', auth: 'password', apiUrl: '', icsAddress: '' })

export function validateForm(f: SshForm, s: SshSecrets): Record<string, string> {
  const e: Record<string, string> = {}
  if (!/^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$/.test(f.host.trim())) e.host = 'Enter the node\'s host name or IP address.'
  if (!Number.isInteger(f.port) || f.port < 1 || f.port > 65535) e.port = 'Port 1-65535.'
  if (!/^[a-z_][a-z0-9_.-]{0,31}$/.test(f.username.trim())) e.username = 'A Linux user name, for example root.'
  if (f.auth === 'password' && !s.password) e.password = 'Enter the password.'
  if (f.auth === 'key' && !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(s.privateKey)) e.privateKey = 'Paste the private key (the whole text including the BEGIN and END lines).'
  if (f.apiUrl && !/^https:\/\/[A-Za-z0-9.:[\]-]{1,260}$/.test(f.apiUrl.trim())) e.apiUrl = 'Must look like https://host:8006'
  if (f.icsAddress && !/^[0-9A-Fa-f:.]{3,45}$/.test(f.icsAddress.trim())) e.icsAddress = 'An IP address.'
  return e
}

export function sessionBody(f: SshForm, s: SshSecrets) {
  return {
    host: f.host.trim(), port: f.port, username: f.username.trim(), ...(f.auth === 'password' ? { password: s.password } : { private_key: s.privateKey, ...(s.passphrase ? { passphrase: s.passphrase } : {}) }),
    ...(f.apiUrl.trim() ? { api_url: f.apiUrl.trim() } : {}),
  }
}

/** Fingerprints compare character for character; whitespace around a pasted value is ignored, nothing else. */
export const sameFingerprint = (typed: string, shown: string | null) => !!shown && typed.trim() === shown
export const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}$/

export const sshApi = {
  create: (f: SshForm, s: SshSecrets) => post<SshSessionView>('ssh-sessions', sessionBody(f, s)),
  hostkey: (id: string) => post<SshSessionView>(`ssh-sessions/${id}/hostkey`),
  confirm: (id: string, fingerprint: string) => post<SshSessionView>(`ssh-sessions/${id}/confirm`, { fingerprint }),
  confirmProxy: (id: string, fingerprint: string) => post<SshSessionView>(`ssh-sessions/${id}/confirm-proxy`, { fingerprint }),
  cancel: (id: string) => request<{ status: string }>('DELETE', `ssh-sessions/${id}`),
  get: (id: string) => get<SshSessionView>(`ssh-sessions/${id}`),
}

export function previewParams(sessionId: string, c: Choice, name: string, endpointId: string | null, icsAddress: string) {
  return { ssh_session_id: sessionId, policy: policyOf(c), ...(endpointId ? { endpoint_id: endpointId } : { name }), ...(icsAddress.trim() ? { ics_address: icsAddress.trim() } : {}) }
}
export const onboardParams = (sessionId: string, pv: SshPreviewOut & { preview_id: string }, name: string, endpointId: string | null) =>
  ({ ssh_session_id: sessionId, preview_id: pv.preview_id, bind_hash: pv.bind_hash, ...(endpointId ? { endpoint_id: endpointId } : { name }) })
export const offboardParams = (sessionId: string, endpointId: string, confirmName: string, deletePool: boolean) =>
  ({ ssh_session_id: sessionId, endpoint_id: endpointId, confirm_name: confirmName, delete_pool: deletePool })

export const suggestName = (host: string) => host.trim().toLowerCase().replace(/\..*$/, '').replace(/[^a-z0-9_-]/g, '-').replace(/^-+/, '').slice(0, 40) || 'proxmox'
