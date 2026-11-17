// Pure logic for the Proxmox provider screens: wizard state, request builders, policy validation, plan/diff rendering helpers.
// Nothing here talks to the network or touches the DOM, so it is unit-tested directly (model.test.ts).
// SECRETS: token secrets and temporary admin credentials never live in the reactive wizard model. They are held in a `SecretBag`
// (a plain object that is never serialised), copied into exactly one request body, and wiped right after the request is sent.
import { normalizeFingerprint, isHost, intIn, looksLikePem, TOKEN_ID_RE, TOKEN_SECRET_RE, SLUG_RE, type Errors } from '../../wizards/kit'

export type Preset = 'monitoring' | 'deploy' | 'custom' | 'full_admin'
export type AuthMethod = 'token' | 'admin' | 'package'
export type Capability = 'monitor' | 'deploy' | 'storage' | 'template_clone' | 'network' | 'backup' | 'custom'
export type Tone = 'ok' | 'warn' | 'bad' | 'info' | 'idle'

export interface Scope {
  nodes: string[]; storages: string[]; pools: string[]; networks: string[]; template_vmids: number[]
  vmid_ranges: [number, number][]; guest_types: ('qemu' | 'lxc')[]; backup_storages: string[]; protected_vmids: number[]
  max_cores: number | null; max_memory_mb: number | null; max_disk_gb: number | null
}
export interface Grant { path: string; privileges: string[]; why: string }
export interface Policy {
  provider: 'proxmox'; preset: Preset; capabilities: Capability[]; scope: Scope; realm: 'pve'
  service_user: string; token_base: string; role_prefix: string; custom_grants: Grant[]
  allow_cicustom: boolean; allow_migrate: boolean; guest_agent: boolean; acknowledge_full_admin: boolean; approve_elevated: string[]
  scope_mode?: ScopeMode | null; scope_risk_overrides?: string[]
}
export type ScopeMode = 'single_node' | 'whole_cluster'

export const emptyScope = (): Scope => ({
  nodes: [], storages: [], pools: [], networks: [], template_vmids: [], vmid_ranges: [], guest_types: ['qemu'], backup_storages: [], protected_vmids: [],
  max_cores: null, max_memory_mb: null, max_disk_gb: null,
})

// ---------------------------------------------------------------------------------------------------- presets
export interface PresetInfo { id: Preset; title: string; blurb: string; risk: 'low' | 'normal' | 'high'; can: string[]; cannot: string[] }
export const PRESETS: PresetInfo[] = [
  { id: 'monitoring', title: 'Monitoring only', risk: 'low',
    blurb: 'Look, never touch. Office Unbound reads nodes, storage, guests and metrics so you get dashboards and health checks.',
    can: ['See nodes, storage, networks, VMs and containers', 'Collect CPU, memory and storage history'],
    cannot: ['Create, change, start, stop or delete anything'] },
  { id: 'deploy', title: 'Deployment & management', risk: 'normal',
    blurb: 'Build and look after the virtual machines Office Unbound deploys, inside a pool, storage and networks that you choose.',
    can: ['Clone approved templates and configure the new VMs', 'Start, stop, snapshot and resize those VMs', 'Use only the storage and bridges you select'],
    cannot: ['Touch guests outside the chosen pool', 'Use storage or networks you did not select', 'Change Proxmox users, roles or permissions'] },
  { id: 'custom', title: 'Custom', risk: 'normal',
    blurb: 'Pick exactly which kinds of permission to grant. Best when your organisation has its own rules.',
    can: ['Combine monitoring, deployment, storage, network and backup permissions'],
    cannot: ['Anything marked as never granted below'] },
  { id: 'full_admin', title: 'Full cluster administration', risk: 'high',
    blurb: 'Office Unbound may manage everything in the cluster. Not recommended; use only if you accept the consequences.',
    can: ['Create, change and delete any VM, container, storage content and network'],
    cannot: ['Change Proxmox users, roles and permissions (still never granted)'] },
]
export const CAPABILITIES: { id: Capability; title: string; text: string }[] = [
  { id: 'monitor', title: 'Monitor', text: 'Read nodes, storage, guests and metrics.' },
  { id: 'deploy', title: 'Deploy and manage VMs', text: 'Create, configure and operate VMs in the chosen pools.' },
  { id: 'template_clone', title: 'Clone from templates', text: 'Clone only the template VMs you list.' },
  { id: 'storage', title: 'Manage storage', text: 'Allocate and free space on the chosen storage.' },
  { id: 'network', title: 'Manage networks', text: 'Attach VMs to the chosen bridges or SDN networks.' },
  { id: 'backup', title: 'Back up guests', text: 'Run backups for guests in the chosen pools.' },
  { id: 'custom', title: 'Custom permissions', text: 'Extra privileges on paths you specify (needs approval).' },
]
export const NEVER_GRANTED = [
  ['Permissions.Modify', 'change who can do what in Proxmox'],
  ['User.Modify, Group.Allocate, Realm.*', 'create or change Proxmox users, groups and login realms'],
  ['Sys.Modify', 'change node-level system settings (only as a clearly marked exception)'],
  ['The built-in Administrator and PVEAdmin roles', 'blanket administrator rights'],
]
export const FULL_ADMIN_CONSEQUENCES = [
  'The Office Unbound service account can create, change and delete every VM and container in the cluster, not only the ones it deployed.',
  'It can read, write and free space on every storage, and attach to every network.',
  'Proxmox can no longer limit it to a pool, storage or bridge. Only the ICS rules (ownership tags, protected guests) stand between a mistake and your other workloads.',
  'It still cannot change Proxmox users, roles or permissions. That is never granted.',
  'Plans that grant this need two approvers and are written to the audit log.',
]

// ---------------------------------------------------------------------------------------------------- discovery model
export interface DiscNode { name: string; status: string; managed: boolean; cpu_total: number | null; mem_total: number | null; mem_used: number | null; cpu_pct: number | null }
export interface DiscStorage { name: string; node: string; type: string | null; content: string[]; shared: boolean; total: number | null; used: number | null; active: boolean }
export interface DiscNetwork { name: string; node: string; kind: string; vlan_aware: boolean | null; tag: number | null; zone: string | null }
export interface DiscGuest { vmid: number; name: string | null; kind: string; node: string; status: string; pool: string | null }
export interface DiscTemplate { vmid: number; name: string | null; kind: string; node: string; pool: string | null }
export interface Discovery { nodes: DiscNode[]; storage: DiscStorage[]; networks: DiscNetwork[]; guests: DiscGuest[]; templates: DiscTemplate[]; warnings: string[]; pools?: string[] }

/** The setup probe returns raw provider rows; tolerate missing sections instead of inventing values. */
export function normDiscovery(raw: unknown): Discovery | null {
  if (!raw || typeof raw !== 'object') return null
  const o = raw as Record<string, unknown>
  const arr = <T>(k: string): T[] => (Array.isArray(o[k]) ? (o[k] as T[]) : [])
  return {
    nodes: arr<DiscNode>('nodes').map((n) => ({ name: String(n.name), status: String(n.status ?? 'unknown'), managed: n.managed !== false,
      cpu_total: n.cpu_total ?? null, mem_total: n.mem_total ?? null, mem_used: n.mem_used ?? null, cpu_pct: n.cpu_pct ?? null })),
    storage: arr<DiscStorage>('storage').map((s) => ({ name: String(s.name), node: String(s.node ?? ''), type: s.type ?? null, content: s.content ?? [], shared: !!s.shared,
      total: s.total ?? null, used: s.used ?? null, active: s.active !== false })),
    networks: arr<DiscNetwork>('networks').map((n) => ({ name: String(n.name), node: String(n.node ?? ''), kind: String(n.kind ?? 'bridge'), vlan_aware: n.vlan_aware ?? null, tag: n.tag ?? null, zone: n.zone ?? null })),
    guests: arr<DiscGuest>('guests'), templates: arr<DiscTemplate>('templates'),
    warnings: arr<string>('warnings'),
  }
}
/** Body of the read-only discovery with a TEMPORARY administrator credential (POST /setup/probe, stage "discover"). Held in memory by the server for
 * this one request; the caller wipes the SecretBag afterwards. */
export function discoverRequest(m: WizardModel, s: SecretBag) {
  const c = adminCreds(m, s)
  return { stage: 'discover' as const, base_url: baseUrl(m), ...trustFields(m), username: c.admin_username, password: c.admin_password, token_id: c.admin_token_id, token_secret: c.admin_token_secret }
}
/** The admin discovery answers with cluster-level lists (node names, storages with their content and node list, bridges, templates, pools). */
export function fromAdminDiscovery(raw: unknown): Discovery | null {
  if (!raw || typeof raw !== 'object') return null
  const o = raw as { nodes?: { name: string; status: string }[]; storages?: { name: string; type?: string | null; shared?: boolean; content?: string; nodes?: string[] }[]
    bridges?: { name: string; zone?: string | null }[]; templates?: { vmid: number; name: string | null; node: string; pool: string | null }[]; pools?: string[]; guests?: number; notes?: string[] }
  return {
    nodes: (o.nodes ?? []).map((n) => ({ name: n.name, status: n.status, managed: true, cpu_total: null, mem_total: null, mem_used: null, cpu_pct: null })),
    storage: (o.storages ?? []).flatMap((s) => (s.nodes?.length ? s.nodes : ['']).map((node) => ({ name: s.name, node, type: s.type ?? null,
      content: (s.content ?? '').split(',').filter(Boolean), shared: !!s.shared, total: null, used: null, active: true }))),
    networks: (o.bridges ?? []).map((b) => ({ name: b.name, node: '', kind: 'bridge', vlan_aware: null, tag: null, zone: b.zone ?? null })),
    guests: [], pools: o.pools ?? [],
    templates: (o.templates ?? []).map((t) => ({ vmid: t.vmid, name: t.name, kind: 'vm', node: t.node, pool: t.pool })),
    warnings: o.notes ?? [],
  }
}
/** Storage is reported once per node; shared storage appears on every node. Merge to one row per storage name. */
export function mergeStorage(rows: DiscStorage[]): (DiscStorage & { nodes: string[] })[] {
  const by = new Map<string, DiscStorage & { nodes: string[] }>()
  for (const r of rows) {
    const cur = by.get(r.name)
    if (!cur) by.set(r.name, { ...r, nodes: r.node ? [r.node] : [] })
    else {
      if (r.node) cur.nodes.push(r.node)
      if (!r.shared) { cur.total = (cur.total ?? 0) + (r.total ?? 0); cur.used = (cur.used ?? 0) + (r.used ?? 0) }
    }
  }
  return [...by.values()].sort((a, b) => a.name.localeCompare(b.name))
}
export const poolsOf = (d: Discovery): string[] => [...new Set([...(d.pools ?? []), ...d.guests.map((g) => g.pool), ...d.templates.map((t) => t.pool)].filter((p): p is string => !!p))].sort()
export const bridgesOf = (d: Discovery): { name: string; kind: string; vlan_aware: boolean | null }[] => {
  const seen = new Map<string, { name: string; kind: string; vlan_aware: boolean | null }>()
  for (const n of d.networks) if (n.kind !== 'sdn_zone' && !seen.has(n.name)) seen.set(n.name, { name: n.name, kind: n.kind === 'sdn_vnet' ? 'SDN network' : 'bridge', vlan_aware: n.vlan_aware })
  return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name))
}
export function discoverySummary(d: Discovery): { label: string; value: number }[] {
  return [
    { label: 'Nodes', value: d.nodes.length }, { label: 'Storage', value: mergeStorage(d.storage).length }, { label: 'Networks', value: bridgesOf(d).length },
    { label: 'Templates', value: d.templates.length }, { label: 'Pools', value: poolsOf(d).length }, { label: 'Guests', value: d.guests.length },
  ]
}
export const hasUnmanaged = (d: Discovery) => d.nodes.filter((n) => !n.managed).map((n) => n.name)

export const DEFAULT_POOL = 'office-unbound'
/** Suggested scope for the Express path. Shown pre-filled but clearly marked "suggested"; the Review step lists the exact outcome. */
export function suggestScope(d: Discovery | null, preset: Preset, mode: ScopeMode = 'whole_cluster'): Scope {
  const s = emptyScope()
  if (!d) return s
  const online = d.nodes.filter((n) => n.status === 'online' && n.managed).map((n) => n.name)
  // one node only: exactly one node (the first that is online and visible), and only storage that cannot reach any other node
  s.nodes = mode === 'single_node' ? online.slice(0, 1) : online
  const usable = (x: MergedStorage) => mode !== 'single_node' || !x.content.some((c) => c === 'images' || c === 'rootdir') || storageLocality(x, s.nodes).local
  if (preset === 'monitoring') { s.storages = mergeStorage(d.storage).filter(usable).map((x) => x.name); return s }
  const imgs = mergeStorage(d.storage).filter((x) => x.content.includes('images') && x.active && x.total && usable(x)).sort((a, b) => ((b.total ?? 0) - (b.used ?? 0)) - ((a.total ?? 0) - (a.used ?? 0)))
  if (imgs[0]) s.storages = [imgs[0].name]
  const br = bridgesOf(d)
  if (br[0]) s.networks = [br[0].name]
  s.pools = [DEFAULT_POOL]
  return s
}

// ---------------------------------------------------------------------------------------------------- wizard model
export interface TlsResult { ok: boolean; verified_by?: string; presented_fingerprint_sha256?: string; subject?: string; not_after?: string; error?: string }
export interface PermRow { ok: boolean; missing: { path: string; privilege: string }[]; unnecessary?: { path: string; privilege: string }[]; fix_commands?: string[] }
export interface ProbeResult {
  ok: boolean; version?: string; cluster_name?: string | null; tls: TlsResult; error?: string; warnings?: string[]
  permissions?: { inventory: PermRow; provision: PermRow }; discovery?: unknown; self_vm?: { vmid: number; node: string; mutable: boolean } | null
  capabilities?: { name: string; ok: boolean; blocking: boolean; detail: string }[]
}
export interface PlanStep { kind: string; op: 'create' | 'modify' | 'noop' | 'remove' | 'conflict'; target: string; detail: Record<string, unknown>; reason: string; risk: 'normal' | 'high' }
export interface EnforcementNote { control: string; enforced_by: 'proxmox' | 'ics' | 'both' | 'not_enforced'; detail: string }
export interface PlanPreviewOut {
  plan_hash: string; risk: 'normal' | 'high' | string; summary: Record<string, number>
  plan: { steps: PlanStep[]; conflicts: string[]; warnings: string[]; elevated: { privilege: string; path: string; why: string; what_it_grants?: string; approved?: boolean }[]
    consequences: string[]; enforcement: EnforcementNote[]; blocked: string[]; facts: Record<string, unknown> }
  preview_id: string
}

export interface WizardModel {
  host: string; port: number; name: string; displayName: string
  trust: 'fingerprint' | 'ca'; fingerprint: string; caPem: string
  tls: TlsResult | null; tlsKey: string | null
  method: AuthMethod; pveMajor: 8 | 9
  tokenId: string; provisionTokenId: string
  probe: ProbeResult | null; probedKey: string | null
  discovery: Discovery | null
  customerId: string | null
  preset: Preset; capabilities: Capability[]; scope: Scope; scopeSuggested: boolean
  serviceUser: string; tokenBase: string; rolePrefix: string; customGrants: Grant[]
  allowCicustom: boolean; allowMigrate: boolean; guestAgent: boolean
  acknowledgeFullAdmin: boolean; approveElevated: string[]
  scopeMode: ScopeMode; riskOverrides: string[]
  adminKind: 'password' | 'token'; adminUser: string; adminTokenId: string
  preview: PlanPreviewOut | null; previewKey: string | null
  packageId: string | null; endpointId: string | null
  packageTokens: Record<string, string>; packageUser: string; riskAck: boolean
}
export const newModel = (): WizardModel => ({
  host: '', port: 8006, name: '', displayName: '', trust: 'fingerprint', fingerprint: '', caPem: '', tls: null, tlsKey: null,
  method: 'token', pveMajor: 9, tokenId: '', provisionTokenId: '', probe: null, probedKey: null, discovery: null, customerId: null,
  preset: 'deploy', capabilities: [], scope: emptyScope(), scopeSuggested: false,
  serviceUser: 'ics-svc', tokenBase: 'ics', rolePrefix: 'OfficeUnbound', customGrants: [], allowCicustom: false, allowMigrate: false, guestAgent: false,
  acknowledgeFullAdmin: false, approveElevated: [], scopeMode: 'single_node', riskOverrides: [], adminKind: 'password', adminUser: 'root@pam', adminTokenId: '',
  preview: null, previewKey: null, packageId: null, endpointId: null, packageTokens: {}, packageUser: '', riskAck: false,
})

/** Secrets that exist only for the length of one request. Not reactive, never serialised. */
export interface SecretBag { tokenSecret: string; provisionSecret: string; adminPassword: string; adminTokenSecret: string; importInventory: string; importProvision: string }
export const newSecrets = (): SecretBag => ({ tokenSecret: '', provisionSecret: '', adminPassword: '', adminTokenSecret: '', importInventory: '', importProvision: '' })
export function wipeAdmin(b: SecretBag): void { b.adminPassword = ''; b.adminTokenSecret = '' }
export function wipe(b: SecretBag): void { for (const k of Object.keys(b) as (keyof SecretBag)[]) b[k] = '' }

export const baseUrl = (m: Pick<WizardModel, 'host' | 'port'>) => `https://${m.host.trim()}:${m.port}`
export const suggestName = (host: string) => host.trim().toLowerCase().replace(/\..*$/, '').replace(/[^a-z0-9_-]/g, '-').replace(/^-+/, '').slice(0, 40)

/** Identity of the connection details; any change invalidates the certificate check and the probe. */
export const identityKey = (m: WizardModel) => [baseUrl(m), m.trust, m.trust === 'ca' ? m.caPem.trim() : (normalizeFingerprint(m.fingerprint) ?? m.fingerprint.trim())].join('|')
export const connectionKey = (m: WizardModel) => [identityKey(m), m.tokenId, m.provisionTokenId].join('|')

export function tlsRequest(m: WizardModel) {
  return { stage: 'tls' as const, base_url: baseUrl(m), ...(m.trust === 'ca' ? { ca_pem: m.caPem.trim() } : { fingerprint_sha256: normalizeFingerprint(m.fingerprint) ?? '' }) }
}
export function trustFields(m: WizardModel): { ca_pem?: string; fingerprint_sha256?: string } {
  return m.trust === 'ca' ? { ca_pem: m.caPem.trim() } : { fingerprint_sha256: normalizeFingerprint(m.fingerprint) ?? '' }
}
/** Full probe body. The secrets are copied in here and nowhere else. */
export function probeRequest(m: WizardModel, s: SecretBag) {
  return {
    base_url: baseUrl(m), token_id: m.tokenId.trim(), token_secret: s.tokenSecret, ...trustFields(m),
    ...(m.provisionTokenId.trim() ? { provision_token_id: m.provisionTokenId.trim(), provision_token_secret: s.provisionSecret } : {}),
    ...(m.scope.pools.length ? { allowed_pools: m.scope.pools } : {}),
    ...(m.scope.storages.length ? { allowed_storage: m.scope.storages } : {}),
    ...(m.scope.networks.length ? { allowed_networks: m.scope.networks } : {}),
  }
}

export function identityVerified(m: WizardModel): boolean {
  return !!m.tls && m.tls.ok === true && m.tlsKey === identityKey(m)
}
export function fingerprintMismatch(m: WizardModel): boolean {
  const e = normalizeFingerprint(m.fingerprint), p = m.tls?.presented_fingerprint_sha256 ? normalizeFingerprint(m.tls.presented_fingerprint_sha256) : null
  return m.trust === 'fingerprint' && !!m.tls && !!e && !!p && e !== p
}

export const FINGERPRINT_CMD = 'openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256'

export function validateIdentity(m: WizardModel): Errors {
  const e: Errors = {}
  if (!isHost(m.host.trim())) e.host = 'Enter the name or IP address of a Proxmox node, for example pve1.example.com.'
  if (!intIn(m.port, 1, 65535)) e.port = 'Port must be 1-65535 (Proxmox uses 8006).'
  if (m.trust === 'fingerprint' && !normalizeFingerprint(m.fingerprint)) e.fingerprint = 'Paste the SHA-256 fingerprint you read on the node (32 pairs of hex digits).'
  if (m.trust === 'ca' && !looksLikePem(m.caPem)) e.caPem = 'Paste the cluster CA certificate, including the BEGIN and END lines.'
  return e
}
export function validateConnect(m: WizardModel, s: SecretBag): Errors {
  const e = validateIdentity(m)
  if (!SLUG_RE.test(m.name)) e.name = 'Use lowercase letters, digits, - or _ (this is the short ID, not the display name).'
  if (!identityVerified(m)) e.identity = 'Check the server certificate first. Nothing secret is sent before this passes.'
  if (m.method === 'token') {
    if (!TOKEN_ID_RE.test(m.tokenId.trim())) e.tokenId = 'Token ID looks like user@realm!tokenname.'
    if (!TOKEN_SECRET_RE.test(s.tokenSecret.trim()) && !(m.probe && m.probedKey === connectionKey(m))) e.tokenSecret = 'Paste the token secret (shown once when the token was created).'
    if (m.provisionTokenId.trim() && !TOKEN_ID_RE.test(m.provisionTokenId.trim())) e.provisionTokenId = 'Token ID looks like user@realm!tokenname.'
    if (!m.probe || m.probedKey !== connectionKey(m)) e.probe = 'Run "Test connection" so we can discover your cluster.'
    else if (!m.probe.ok || !m.probe.permissions?.inventory.ok) e.probe = 'The connection test did not pass. Fix the items shown, then test again.'
  }
  return e
}

// ---------------------------------------------------------------------------------------------------- policy
export function buildPolicy(m: WizardModel): Policy {
  const full = m.preset === 'full_admin'
  // full cluster administration is granted on "/", so it is always a whole-cluster scope
  const mode: ScopeMode = full ? 'whole_cluster' : m.scopeMode
  const single = mode === 'single_node'
  const overrides = single ? [...new Set(m.riskOverrides)].sort() : []
  return {
    provider: 'proxmox', preset: m.preset, capabilities: m.preset === 'custom' ? [...m.capabilities] : [],
    scope_mode: mode, scope_risk_overrides: overrides,
    scope: { ...m.scope, nodes: single ? [...m.scope.nodes] : [], storages: [...m.scope.storages], pools: [...m.scope.pools], networks: [...m.scope.networks] },
    realm: 'pve', service_user: m.serviceUser, token_base: m.tokenBase, role_prefix: m.rolePrefix,
    custom_grants: m.preset === 'custom' && m.capabilities.includes('custom') ? m.customGrants.filter((g) => g.path && g.privileges.length) : [],
    allow_cicustom: single ? false : m.allowCicustom, allow_migrate: single ? overrides.includes('migrate') && m.allowMigrate : m.allowMigrate, guest_agent: m.guestAgent,
    acknowledge_full_admin: full && m.acknowledgeFullAdmin, approve_elevated: [...m.approveElevated],
  }
}
/** The API wants nulls omitted and the empty vmid list absent; send only what is set. */
export function policyForApi(p: Policy) {
  const s: Record<string, unknown> = { ...p.scope }
  for (const k of ['max_cores', 'max_memory_mb', 'max_disk_gb'] as const) if (s[k] === null) delete s[k]
  return { ...p, scope: s }
}

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/
export function validateScope(m: WizardModel): Errors {
  const e: Errors = {}
  const s = m.scope
  if (m.preset === 'full_admin') {
    if (!m.acknowledgeFullAdmin) e.ack = 'Confirm that you understand the consequences to continue.'
    return e
  }
  if (m.preset === 'custom' && !m.capabilities.length) e.capabilities = 'Choose at least one kind of permission.'
  if (m.scopeMode === 'single_node' && !s.nodes.length) e.nodes = 'Choose the node Office Unbound may use.'
  if (m.scopeMode === 'single_node' && m.discovery) {
    const bad = blockedStorages(m)
    if (bad.length) e.storages = `${bad.map((b) => b.name).join(', ')} can place disks on other nodes. Pick a storage that exists only on the chosen node, or accept the high-risk exception under Advanced.`
  }
  if (!(s.nodes.length || s.pools.length || s.storages.length || s.template_vmids.length)) e.scope = 'Choose at least one node, pool, storage or template. Nothing is allowed by default.'
  const wantsDeploy = m.preset === 'deploy' || (m.preset === 'custom' && (m.capabilities.includes('deploy') || m.capabilities.includes('template_clone')))
  if (wantsDeploy && !s.pools.length) e.pools = 'Deployment needs a pool to work in. Pick an existing one or name a new one.'
  if (wantsDeploy && !s.storages.length) e.storages = 'Choose at least one storage for new disks.'
  if (wantsDeploy && !s.networks.length) e.networks = 'Choose at least one bridge or network for new VMs.'
  if (m.preset === 'custom' && m.capabilities.includes('template_clone') && !s.template_vmids.length) e.templates = 'List at least one template VM that may be cloned.'
  if (m.preset === 'custom' && m.capabilities.includes('backup') && !s.backup_storages.length) e.backup = 'Choose the backup storage.'
  for (const n of [...s.pools, ...s.storages, ...s.networks]) if (!NAME_RE.test(n)) e.names = `"${n}" is not a valid name (letters, digits, . _ - only).`
  for (const [a, b] of s.vmid_ranges) if (!(a >= 100 && a <= b && b <= 999999999)) e.vmid = 'VMID ranges need 100 <= low <= high.'
  if (s.max_cores !== null && !intIn(s.max_cores, 1, 1024)) e.max_cores = 'Whole number from 1 to 1024.'
  if (s.max_memory_mb !== null && !(Number.isInteger(s.max_memory_mb) && s.max_memory_mb >= 128)) e.max_memory = 'At least 128 MB.'
  if (s.max_disk_gb !== null && !(Number.isInteger(s.max_disk_gb) && s.max_disk_gb >= 1)) e.max_disk = 'At least 1 GB.'
  if (m.customGrants.some((g) => g.path && !/^\/[A-Za-z0-9/._:@+-]{0,200}$/.test(g.path))) e.grants = 'ACL paths start with / (for example /storage/local).'
  return e
}
export const parseNames = (s: string): string[] => [...new Set(s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean))]
export const parseVmids = (s: string): number[] => [...new Set(parseNames(s).map(Number).filter((n) => Number.isInteger(n) && n >= 100))].sort((a, b) => a - b)
export function parseRanges(s: string): [number, number][] {
  return parseNames(s).map((t): [number, number] | null => { const m = /^(\d+)-(\d+)$/.exec(t); return m ? [Number(m[1]), Number(m[2])] : null }).filter((x): x is [number, number] => !!x)
}
export const fmtRanges = (r: [number, number][]) => r.map(([a, b]) => `${a}-${b}`).join(', ')

export function riskOf(m: WizardModel): 'low' | 'normal' | 'high' {
  if (m.preset === 'full_admin') return 'high'
  if (m.preset === 'monitoring') return 'low'
  return m.approveElevated.length || (m.preset === 'custom' && m.capabilities.includes('custom')) ? 'high' : 'normal'
}

// ---------------------------------------------------------------------------------------------------- action parameters
export interface Creds { admin_username?: string; admin_password?: string; admin_token_id?: string; admin_token_secret?: string }
export function adminCreds(m: WizardModel, s: SecretBag): Creds {
  return m.adminKind === 'password'
    ? { admin_username: m.adminUser.trim(), admin_password: s.adminPassword }
    : { admin_token_id: m.adminTokenId.trim(), admin_token_secret: s.adminTokenSecret }
}
export function validateCreds(m: WizardModel, s: SecretBag): Errors {
  const e: Errors = {}
  if (m.adminKind === 'password') {
    if (!/^[^@\s!:/]{1,64}@[A-Za-z0-9._-]{1,32}$/.test(m.adminUser.trim())) e.adminUser = 'Use the form user@realm, for example root@pam.'
    if (!s.adminPassword) e.adminPassword = 'Enter the password.'
  } else {
    if (!TOKEN_ID_RE.test(m.adminTokenId.trim())) e.adminTokenId = 'Token ID looks like user@realm!tokenname.'
    if (!TOKEN_SECRET_RE.test(s.adminTokenSecret.trim())) e.adminTokenSecret = 'Paste the token secret.'
  }
  return e
}
/** Connection part shared by every provisioning action: an existing endpoint, or a new cluster by name + URL + exactly one trust anchor. */
export function connParams(m: WizardModel) {
  if (m.endpointId) return { endpoint_id: m.endpointId }
  return { name: m.name, base_url: baseUrl(m), ...trustFields(m) }
}
export const previewKeyOf = (m: WizardModel) => JSON.stringify([identityKey(m), m.name, buildPolicy(m), m.method, m.pveMajor])

export function previewParams(m: WizardModel, s: SecretBag) {
  const online = m.method === 'admin'
  return {
    purpose: 'provision' as const, policy: policyForApi(buildPolicy(m)), ...(online ? { ...connParams(m), ...adminCreds(m, s) } : { pve_major: m.pveMajor }),
  }
}
export function applyParams(m: WizardModel, s: SecretBag) {
  if (!m.preview) throw new Error('no preview to apply')
  return { ...connParams(m), preview_id: m.preview.preview_id, plan_hash: m.preview.plan_hash, ...adminCreds(m, s) }
}
export function packageParams(m: WizardModel) {
  return { policy: policyForApi(buildPolicy(m)), ...(m.endpointId ? { endpoint_id: m.endpointId } : { pve_major: m.pveMajor }) }
}
export function importParams(m: WizardModel, s: SecretBag) {
  if (!m.packageId) throw new Error('no package')
  const prov = s.importProvision.trim()
  return {
    ...connParams(m), package_id: m.packageId,
    inventory_token_id: inventoryTokenId(m), inventory_token_secret: s.importInventory.trim(),
    ...(prov ? { provision_token_id: provisionTokenIdFor(m), provision_token_secret: prov } : {}),
  }
}
/** Token IDs the customer's script creates. Prefer what the generated package says; otherwise derive them from the policy names. */
export const inventoryTokenId = (m: WizardModel) => `${m.packageUser || `${m.serviceUser}@pve`}!${m.packageTokens.inventory ?? `${m.tokenBase}-inv`}`
export const provisionTokenIdFor = (m: WizardModel) => `${m.packageUser || `${m.serviceUser}@pve`}!${m.packageTokens.provision ?? `${m.tokenBase}-prov`}`
export const needsProvisionToken = (m: WizardModel) => ('provision' in m.packageTokens) || (!Object.keys(m.packageTokens).length && m.preset !== 'monitoring')

/** Existing-token path: no change is made in Proxmox; ICS registers the token and keeps its own allowlists. */
export function registerParams(m: WizardModel, s: SecretBag) {
  const prov = m.provisionTokenId.trim()
  const sc = m.scope
  return {
    name: m.name, type: 'proxmox' as const, base_url: baseUrl(m), ...trustFields(m),
    ...(m.displayName.trim() ? { display_name: m.displayName.trim() } : {}),
    token_id: m.tokenId.trim(), token_secret: s.tokenSecret.trim(),
    ...(prov ? { provision_token_id: prov, provision_token_secret: s.provisionSecret.trim() } : {}),
    allowed_pools: sc.pools, allowed_storage: [...new Set([...sc.storages, ...sc.backup_storages])], allowed_networks: sc.networks, allowed_templates: sc.template_vmids,
    allow_cicustom: m.allowCicustom, protected_vmids: sc.protected_vmids,
    ...(m.customerId ? { customer_id: m.customerId } : {}),
  }
}

// ---------------------------------------------------------------------------------------------------- plan display
export const OP_LABEL: Record<string, string> = { create: 'Create', modify: 'Change', noop: 'Already in place', remove: 'Remove', conflict: 'Conflict' }
export const KIND_LABEL: Record<string, string> = { pool: 'Pool', role: 'Role', user: 'Service account', token: 'API token', acl: 'Permission (ACL)' }
export interface StepRow { kind: string; kindLabel: string; op: PlanStep['op']; opLabel: string; target: string; what: string; reason: string; high: boolean; tone: Tone }
export function describeStep(s: PlanStep): string {
  const d = s.detail ?? {}
  const list = (x: unknown) => (Array.isArray(x) ? (x as string[]) : [])
  if (s.kind === 'role' && s.op === 'modify' && (list(d.added).length || list(d.removed).length))
    return [list(d.added).length ? `Adds ${list(d.added).join(', ')}` : '', list(d.removed).length ? `Removes ${list(d.removed).join(', ')}` : ''].filter(Boolean).join('. ')
      + (list(d.affects).length ? `. Also changes the rights of: ${list(d.affects).join('; ')}` : '')
  if (s.kind === 'role' && s.op === 'remove') return `Pre-existing role with ${list(d.privileges).join(', ') || 'no privileges'} is deleted`
  if (s.kind === 'role') return `Privileges: ${list(d.privileges).join(', ') || 'none listed'}` + (list(d.withheld).length ? `. Used as is: Office Unbound will not have ${list(d.withheld).join(', ')}` : '')
  if (s.kind === 'acl') {
    const parts = s.target.split('|')
    if (parts.length === 3 && s.op === 'remove') return `On ${parts[0]}: ${parts[1]} loses role ${parts[2]}`
    return parts.length === 3 ? `On ${parts[0]}: ${parts[1]} gets role ${parts[2]}` : s.target
  }
  if (s.op === 'remove' && (s.kind === 'token' || s.kind === 'user' || s.kind === 'pool')) return 'Pre-existing Office Unbound object is deleted'
  if (s.kind === 'token') return d.privsep === false ? 'Not privilege-separated' : 'Privilege-separated (cannot exceed the account\'s own rights)'
  if (s.kind === 'user') return 'No password, no shell login; exists only to own the API tokens'
  if (s.kind === 'pool') return 'Container that limits which guests the account can reach'
  return ''
}
export function stepRows(steps: PlanStep[], includeNoop = false): StepRow[] {
  const tone = (o: string): Tone => (o === 'create' ? 'info' : o === 'modify' ? 'warn' : o === 'remove' || o === 'conflict' ? 'bad' : 'idle')
  return steps.filter((s) => includeNoop || s.op !== 'noop').map((s) => ({
    kind: s.kind, kindLabel: KIND_LABEL[s.kind] ?? s.kind, op: s.op, opLabel: OP_LABEL[s.op] ?? s.op, target: s.kind === 'acl' ? (s.target.split('|')[0] ?? s.target) : s.target,
    what: describeStep(s), reason: s.reason, high: s.risk === 'high', tone: tone(s.op),
  }))
}
export const ENFORCER_LABEL: Record<EnforcementNote['enforced_by'], string> = { proxmox: 'Enforced by Proxmox', ics: 'Enforced by Office Unbound only', both: 'Both', not_enforced: 'Not enforced yet' }
/** Honest split: what Proxmox itself guarantees vs what only ICS enforces (and what is not enforced at all). */
export function splitEnforcement(list: EnforcementNote[]) {
  return {
    proxmox: list.filter((x) => x.enforced_by === 'proxmox' || x.enforced_by === 'both'),
    ics: list.filter((x) => x.enforced_by === 'ics'),
    notEnforced: list.filter((x) => x.enforced_by === 'not_enforced'),
  }
}
/** Local equivalent for the existing-token path (no provisioning plan): Proxmox enforces whatever the token already has; ICS adds its allowlists. */
export function tokenPathEnforcement(m: WizardModel): EnforcementNote[] {
  const out: EnforcementNote[] = [
    { control: 'What the token can do in Proxmox', enforced_by: 'proxmox', detail: 'Decided by the token\'s existing roles and ACLs. Office Unbound changes nothing in Proxmox on this path.' },
    { control: 'Pool, storage, bridge and template allowlists', enforced_by: 'ics', detail: 'Office Unbound refuses any change outside the lists you chose. Proxmox may still allow more to this token.' },
    { control: 'Ownership tags and protected guests', enforced_by: 'ics', detail: 'Only guests that Office Unbound created and tagged can be changed. The Office Unbound VM itself is always protected.' },
  ]
  const s = m.scope
  if (s.nodes.length) out.push({ control: `Node allowlist (${s.nodes.join(', ')})`, enforced_by: 'ics', detail: 'Proxmox pool permissions do not limit which node a guest lands on. Application-enforced.' })
  if (s.vmid_ranges.length || s.max_cores || s.max_memory_mb || s.max_disk_gb || s.guest_types.length < 2) {
    out.push({ control: 'VMID ranges, guest types, CPU/RAM/disk caps', enforced_by: 'not_enforced', detail: 'Proxmox cannot express these. Saved with the policy, but the deployment engine does not apply them yet.' })
  }
  return out
}
export function reviewVerdict(p: PlanPreviewOut | null): { ok: boolean; blockers: string[]; warnings: string[] } {
  if (!p) return { ok: false, blockers: ['Run the preview first.'], warnings: [] }
  const blockers = [...(p.plan.blocked ?? [])]
  const unapproved = (p.plan.elevated ?? []).filter((x) => !x.approved)
  if (unapproved.length) blockers.push(`Elevated privileges need explicit approval: ${unapproved.map((x) => x.privilege).join(', ')}.`)
  return { ok: blockers.length === 0, blockers, warnings: [...(p.plan.conflicts ?? []), ...(p.plan.warnings ?? [])] }
}

// ---------------------------------------------------------------------------------------------------- policy diff (permissions page)
export interface DiffRow { field: string; before: string; after: string; changed: boolean }
const list = (a: string[]) => (a.length ? a.join(', ') : '(none)')
export function diffPolicies(a: Policy, b: Policy): DiffRow[] {
  const rows: [string, string, string][] = [
    ['Access level', a.preset, b.preset], ['Permission types', list(a.capabilities), list(b.capabilities)],
    ['Nodes', list(a.scope.nodes), list(b.scope.nodes)], ['Storage', list(a.scope.storages), list(b.scope.storages)], ['Pools', list(a.scope.pools), list(b.scope.pools)],
    ['Networks', list(a.scope.networks), list(b.scope.networks)], ['Templates', list(a.scope.template_vmids.map(String)), list(b.scope.template_vmids.map(String))],
    ['Backup storage', list(a.scope.backup_storages), list(b.scope.backup_storages)], ['VMID ranges', fmtRanges(a.scope.vmid_ranges) || '(any)', fmtRanges(b.scope.vmid_ranges) || '(any)'],
    ['Guest types', list(a.scope.guest_types), list(b.scope.guest_types)],
    ['CPU cap', String(a.scope.max_cores ?? 'none'), String(b.scope.max_cores ?? 'none')], ['Memory cap (MB)', String(a.scope.max_memory_mb ?? 'none'), String(b.scope.max_memory_mb ?? 'none')],
    ['Disk cap (GB)', String(a.scope.max_disk_gb ?? 'none'), String(b.scope.max_disk_gb ?? 'none')],
    ['Custom grants', list(a.custom_grants.map((g) => `${g.path}: ${g.privileges.join('+')}`)), list(b.custom_grants.map((g) => `${g.path}: ${g.privileges.join('+')}`))],
    ['Allow migration', String(a.allow_migrate), String(b.allow_migrate)], ['Allow cloud-init snippets', String(a.allow_cicustom), String(b.allow_cicustom)],
  ]
  return rows.map(([field, before, after]) => ({ field, before, after, changed: before !== after }))
}
export const changedOnly = (r: DiffRow[]) => r.filter((x) => x.changed)

/** Rebuild an editable policy from what GET /providers/{id}/permissions returns. */
export function policyFromView(v: PermissionsView): Policy | null {
  if (!v.managed_by_provisioning || !v.scope || !v.preset) return null
  const sc = v.scope as Partial<Scope>
  const caps = (Object.keys(v.roles ?? {}) as string[]).filter((c) => c !== 'full_admin') as Capability[]
  const p = (v.preset ?? 'deploy') as Preset
  const user = (v.service_user ?? 'ics-svc@pve').split('@')[0] ?? 'ics-svc'
  return {
    provider: 'proxmox', preset: p, capabilities: p === 'custom' ? caps : [], realm: 'pve', service_user: user, token_base: 'ics', role_prefix: 'OfficeUnbound', custom_grants: [],
    allow_cicustom: false, allow_migrate: !!(v.scope_risk_overrides ?? []).includes('migrate'), guest_agent: false, acknowledge_full_admin: p === 'full_admin', approve_elevated: [],
    scope_mode: (v.scope_mode === 'single_node' || v.scope_mode === 'whole_cluster' ? v.scope_mode : null), scope_risk_overrides: [...(v.scope_risk_overrides ?? [])],
    scope: { ...emptyScope(), ...sc, guest_types: (sc.guest_types as Scope['guest_types']) ?? ['qemu'] },
  }
}

// ---------------------------------------------------------------------------------------------------- permissions view + drift
export interface PermissionsView {
  endpoint_id: string; managed_by_provisioning: boolean; note?: string; mode?: 'A' | 'B'; status?: string; preset?: string; service_user?: string
  tokens?: Record<string, { id: string; gen?: number; [k: string]: unknown }>; plan_hash?: string
  roles?: Record<string, { name: string; privileges: string[] }>; expected?: Record<string, Record<string, string[]>>
  last_verification?: { ok?: boolean; [k: string]: unknown } | null; last_verified_at?: string | null; last_drift?: DriftReport | null; last_drift_at?: string | null
  grants?: { path: string; capability: string; role: string; privileges: string[]; propagate: boolean; tokens: string[]; enforced_by: 'proxmox' | 'ics'; note: string }[]
  custom_grants?: unknown[]; ics_enforced?: EnforcementNote[]
  enforcement?: EnforcementNote[]; scope?: Partial<Scope>; scope_mode?: ScopeMode | 'nodes' | null; scope_risk_overrides?: string[]; scope_enforcement?: EnforcementNote[]; never_granted?: string[]; managed_objects?: { user?: string; roles?: string[]; tokens?: string[]; pools?: string[]; acl?: unknown[]; assumed?: string }
}
export interface KindDrift { ok: boolean; missing: { path: string; privileges: string[] }[]; unexpected: { path: string; privileges: string[] }[]; forbidden: { path: string; privileges: string[] }[]; suggestion: string[]; unauthorized_exposure?: { path: string; privileges: string[] }[]
  scope_reach?: { path: string; privileges: string[]; reaches: string; enforced_by: string }[] }
export interface IcsScopeCheck { ok: boolean; enforced_by: 'ics'; nodes: { policy: string[]; endpoint: string[] }; storages: { policy: string[]; endpoint: string[] }; note: string }
export interface DriftReport { ok: boolean; error?: string; error_code?: string; kinds?: Record<string, KindDrift>; checked_at?: string; ics_scope?: IcsScopeCheck }
export interface DriftItem { kind: string; type: 'missing' | 'unexpected' | 'forbidden' | 'exposed'; path: string; privileges: string[]; text: string; suggestion: string }
export function driftItems(r: DriftReport | null | undefined): DriftItem[] {
  if (!r?.kinds) return []
  const out: DriftItem[] = []
  const kindName = (k: string) => (k === 'inventory' ? 'Inventory token' : k === 'provision' ? 'Provisioning token' : k)
  for (const [k, d] of Object.entries(r.kinds)) {
    for (const x of d.missing ?? []) out.push({ kind: kindName(k), type: 'missing', path: x.path, privileges: x.privileges, text: `Expected but not present`, suggestion: `Restore ${x.privileges.join(', ')} on ${x.path}` })
    for (const x of d.unexpected ?? []) out.push({ kind: kindName(k), type: 'unexpected', path: x.path, privileges: x.privileges, text: 'Present but not part of the approved policy', suggestion: `Remove ${x.privileges.join(', ')} on ${x.path}` })
    for (const x of d.forbidden ?? []) out.push({ kind: kindName(k), type: 'forbidden', path: x.path, privileges: x.privileges, text: 'Forbidden privilege present', suggestion: `Remove ${x.privileges.join(', ')} on ${x.path} immediately` })
    for (const x of d.unauthorized_exposure ?? []) out.push({ kind: kindName(k), type: 'exposed', path: x.path, privileges: x.privileges, text: 'Reaches a resource outside the approved scope', suggestion: `Remove access on ${x.path}` })
    for (const x of d.scope_reach ?? []) if (!out.some((o) => o.kind === kindName(k) && o.path === x.path && o.type === 'exposed')) out.push({ kind: kindName(k), type: 'exposed', path: x.path, privileges: x.privileges, text: `Reaches ${x.reaches}, beyond the single-node scope`, suggestion: `Remove ${x.privileges.join(', ')} on ${x.path} in Proxmox` })
  }
  return out
}
export const TYPE_LABEL: Record<DriftItem['type'], string> = { missing: 'Missing', unexpected: 'Unexpected', forbidden: 'Forbidden', exposed: 'Out of scope' }
export function policyStatus(v: PermissionsView | null): { tone: Tone; text: string; detail: string } {
  if (!v) return { tone: 'idle', text: 'Unknown', detail: 'Permissions could not be loaded.' }
  if (!v.managed_by_provisioning) return { tone: 'info', text: 'Manual token', detail: v.note ?? 'Registered with a token you supplied; Office Unbound does not manage its permissions.' }
  const map: Record<string, { tone: Tone; text: string; detail: string }> = {
    ok: { tone: 'ok', text: 'In sync', detail: 'Actual permissions match the approved policy.' },
    drift: { tone: 'warn', text: 'Drift detected', detail: 'Permissions in Proxmox differ from the approved policy.' },
    token_failed: { tone: 'bad', text: 'Token rejected', detail: 'Proxmox no longer accepts the integration token. Rotate or replace it.' },
    unreachable: { tone: 'bad', text: 'Unreachable', detail: 'The cluster could not be reached for the last check.' },
    error: { tone: 'warn', text: 'Check error', detail: 'The last check ended with an error.' },
    revoked: { tone: 'idle', text: 'Revoked', detail: 'The integration was revoked.' },
  }
  return map[v.status ?? ''] ?? { tone: 'idle', text: v.status ?? 'Not checked yet', detail: 'No verification has run yet.' }
}

// ---------------------------------------------------------------------------------------------------- endpoints / cards
export interface ProviderEndpoint {
  id: string; name: string; display_name: string | null; type: string; base_url: string; trust: string; fingerprint_sha256: string | null
  credentials: { inventory: { present: boolean; token_id: string | null }; provision: { present: boolean; token_id: string | null } }
  scope: { allowed_pools: string[]; allowed_storage: string[]; allowed_networks: string[]; allowed_templates: number[]; allow_cicustom: boolean; protected_vmids: number[] }
  enabled: boolean; detached_at: string | null; created_at: string
  health: { status: string; reason: string | null }
  last_probe: { at: string | null; ok: boolean | null; version: string | null; cluster_name: string | null; verbs: Record<string, boolean> } | null
  last_discovery: { at: string | null; ok: boolean | null; error: string | null; warnings: string[]; counts: Record<string, number> }
  last_metrics: { at: string | null; error: string | null }
}
export const providerTitle = (e: ProviderEndpoint) => e.display_name || e.last_probe?.cluster_name || e.name
export function healthTone(h: string): Tone {
  return h === 'ok' ? 'ok' : h === 'warning' ? 'warn' : h === 'critical' ? 'bad' : h === 'unknown' ? 'idle' : 'idle'
}
export const HEALTH_TEXT: Record<string, string> = { ok: 'Healthy', warning: 'Needs attention', critical: 'Problem', unknown: 'Not checked yet', disabled: 'Paused', detached: 'Removed' }

export interface CredentialMeta {
  id: string; provider: string; customer_id: string; label: string; credential_type: string; purpose: string; identity: string | null
  status: string; created_at: string; last_validated_at: string | null; last_used_at: string | null; expires_at: string | null; revoked_at: string | null
  datacenter?: string | null; cluster?: string | null; host?: string | null
}
export function daysUntil(iso: string | null | undefined, now = Date.now()): number | null {
  if (!iso) return null
  const t = Date.parse(iso)
  return isNaN(t) ? null : Math.floor((t - now) / 86400000)
}
export function credentialState(c: CredentialMeta, now = Date.now()): { tone: Tone; text: string; detail: string } {
  if (c.status === 'revoked') return { tone: 'idle', text: 'Revoked', detail: 'Destroyed. It can never be used again.' }
  if (c.status === 'retired') return { tone: 'idle', text: 'Replaced', detail: 'Superseded by a newer credential.' }
  if (c.status === 'expired') return { tone: 'bad', text: 'Expired', detail: 'Expired. Replace it to restore the connection.' }
  if (c.status === 'invalid') return { tone: 'bad', text: 'Rejected', detail: 'Proxmox rejected this credential. Replace or rotate it.' }
  const d = daysUntil(c.expires_at, now)
  if (c.status === 'expiring' || (d !== null && d <= 14)) return { tone: 'warn', text: d !== null && d >= 0 ? `Expires in ${d} day${d === 1 ? '' : 's'}` : 'Expiring', detail: 'Rotate it before it expires.' }
  return { tone: 'ok', text: 'Active', detail: d === null ? 'No expiry date set.' : `Expires in ${d} days.` }
}
/** Worst credential state for a provider, matched by the non-secret token identity. */
export function credentialsFor(e: ProviderEndpoint, all: CredentialMeta[]): CredentialMeta[] {
  const ids = new Set([e.credentials.inventory.token_id, e.credentials.provision.token_id].filter(Boolean))
  return all.filter((c) => c.provider === 'proxmox' && c.identity && ids.has(c.identity) && c.status !== 'retired')
}
export function worstCredential(cs: CredentialMeta[]): { tone: Tone; text: string } {
  if (!cs.length) return { tone: 'idle', text: 'No credential on file' }
  const states = cs.map((c) => credentialState(c))
  const order: Tone[] = ['bad', 'warn', 'idle', 'info', 'ok']
  states.sort((a, b) => order.indexOf(a.tone) - order.indexOf(b.tone))
  return { tone: states[0]!.tone, text: states[0]!.text }
}

/** Authorised-resource summary for a card: what ICS may touch, from the endpoint's own allowlists. */
export function scopeSummary(e: ProviderEndpoint): { label: string; value: string }[] {
  const s = e.scope, c = e.last_discovery.counts ?? {}
  const n = (k: string) => (typeof c[k] === 'number' ? c[k] : null)
  return [
    { label: 'Nodes', value: n('nodes') === null ? '-' : String(n('nodes')) },
    { label: 'Storage', value: s.allowed_storage.length ? `${s.allowed_storage.length} authorised` : (n('storage') === null ? '-' : `${n('storage')} seen, none authorised`) },
    { label: 'Pools', value: s.allowed_pools.length ? s.allowed_pools.join(', ') : 'none' },
    { label: 'Networks', value: s.allowed_networks.length ? s.allowed_networks.join(', ') : 'none' },
  ]
}

// ---------------------------------------------------------------------------------------------------- plan / job progress
export interface PlanRow { id: string; status: string; approvals_required?: number; approval_count?: number; approvers?: string[]; decided_by_username?: string | null; risk?: string }
export interface JobRow { id: string; plan_id: string; status: 'queued' | 'running' | 'succeeded' | 'failed'; result: unknown; error: unknown; created_at: string; started_at?: string | null; finished_at?: string | null }
export type Phase = 'awaiting_approval' | 'queued' | 'running' | 'succeeded' | 'failed' | 'rejected'
export interface RunView { phase: Phase; text: string; detail: string; done: boolean; ok: boolean; progress: number }
export function runView(plan: PlanRow | null, job: JobRow | null): RunView {
  if (job) {
    if (job.status === 'succeeded') return { phase: 'succeeded', text: 'Done', detail: 'The change was applied.', done: true, ok: true, progress: 100 }
    if (job.status === 'failed') return { phase: 'failed', text: 'Failed', detail: errorText(job.error), done: true, ok: false, progress: 100 }
    if (job.status === 'running') return { phase: 'running', text: 'Working', detail: 'Office Unbound is talking to your cluster.', done: false, ok: false, progress: 66 }
    return { phase: 'queued', text: 'Queued', detail: 'Waiting for a worker to pick it up.', done: false, ok: false, progress: 33 }
  }
  if (plan?.status === 'rejected') return { phase: 'rejected', text: 'Rejected', detail: 'An approver rejected this request. Nothing was changed.', done: true, ok: false, progress: 100 }
  if (plan?.status === 'pending_approval') {
    const need = plan.approvals_required ?? 1, have = plan.approval_count ?? 0
    return { phase: 'awaiting_approval', text: 'Waiting for approval', detail: `${have} of ${need} approval${need === 1 ? '' : 's'} recorded. Another operator with the approver role must approve this.`, done: false, ok: false, progress: 15 + Math.round((have / Math.max(1, need)) * 15) }
  }
  return { phase: 'queued', text: 'Queued', detail: 'Approved. Waiting for a worker.', done: false, ok: false, progress: 30 }
}
export function errorText(e: unknown): string {
  if (!e) return 'The job failed without details.'
  if (typeof e === 'string') return e
  if (typeof e === 'object') { const o = e as Record<string, unknown>; return String(o.message ?? o.error ?? o.detail ?? JSON.stringify(e)) }
  return String(e)
}
/** Plain-language help for the most common failures, shown with the raw message under "Troubleshooting". */
export function troubleshoot(msg: string): string[] {
  const m = msg.toLowerCase(), out: string[] = []
  if (/401|authentication|unauthor|invalid (username|password|ticket)|token.*(rejected|invalid)/.test(m)) out.push('The credentials were rejected. Check the user, password or token ID and secret. Tokens belong to a user and look like user@realm!name.')
  if (/403|permission|forbidden|not allowed/.test(m)) out.push('The account is valid but lacks permission. Use an administrator account for setup, or add the missing privileges shown on the previous step.')
  if (/fingerprint|certificate|tls|ssl|pin/.test(m)) out.push('The certificate did not match. Re-run the fingerprint command on the node and compare it character by character. If the node certificate was renewed, enter the new fingerprint.')
  if (/timed? ?out|unreachable|refused|no route|resolve|connect/.test(m)) out.push('The cluster could not be reached. Check that this server can reach the host and port 8006, and that no firewall blocks it.')
  if (/hash|changed since/.test(m)) out.push('The cluster changed between preview and apply, so nothing was applied. Go back and preview again.')
  if (/conflict|already exists|collision/.test(m)) out.push('Something with the same name already exists in Proxmox. Pick different names under Advanced details, or remove the old object.')
  if (/verification|does not match/.test(m)) out.push('The permissions were applied but the result did not match the plan, so the run was rolled back. See the verification details.')
  if (!out.length) out.push('Try the step again. If it keeps failing, copy the message above into your support request; it contains no secrets.')
  return out
}

// ---------------------------------------------------------------------------------------------------- metrics
export interface Pt { t: number; v: number }
export function toPoints(raw: unknown): Pt[] {
  const pts = (raw as { points?: { ts: string; avg: number | null }[] } | null)?.points ?? []
  return pts.filter((p) => p.avg !== null && isFinite(p.avg)).map((p) => ({ t: Date.parse(p.ts), v: p.avg as number })).filter((p) => isFinite(p.t)).sort((a, b) => a.t - b.t)
}
/** Combine per-resource series on shared timestamps: 'mean' of values or 'sum'. Missing timestamps are skipped, never interpolated. */
export function mergeSeries(series: Pt[][], how: 'mean' | 'sum'): Pt[] {
  const by = new Map<number, number[]>()
  for (const s of series) for (const p of s) { const a = by.get(p.t) ?? []; a.push(p.v); by.set(p.t, a) }
  return [...by.entries()].sort((a, b) => a[0] - b[0]).map(([t, v]) => ({ t, v: how === 'sum' ? v.reduce((x, y) => x + y, 0) : v.reduce((x, y) => x + y, 0) / v.length }))
}
export function ratioSeries(num: Pt[], den: Pt[]): Pt[] {
  const d = new Map(den.map((p) => [p.t, p.v]))
  return num.filter((p) => (d.get(p.t) ?? 0) > 0).map((p) => ({ t: p.t, v: (p.v / d.get(p.t)!) * 100 }))
}

// ---------------------------------------------------------------------------------------------------- capacity
export interface InfraNode { id: string; name: string; status: string; managed: boolean; cpu_total: number | null; mem_total: number | null; mem_used: number | null; cpu_pct: number | null; disk_total: number | null; disk_used: number | null; health?: { status: string; reason: string | null } }
export interface InfraStorage { id: string; name: string; node: string; type: string | null; content: string[]; shared: boolean | null; total: number | null; used: number | null; active: boolean | null; health?: { status: string; reason: string | null } }
export interface InfraGuest { id: string; vmid: number; kind: 'vm' | 'lxc'; node: string; name: string | null; status: string; pool: string | null; ou_managed: boolean; cpus: number | null; mem_max: number | null }
export const pctOf = (used: number | null, total: number | null) => (used !== null && total ? Math.min(100, (used / total) * 100) : null)
/** Deployable headroom inside the authorised scope: free CPU/memory on managed online nodes and free space on authorised storage. Only counts what was actually observed. */
export function capacityHeadroom(nodes: InfraNode[], storage: InfraStorage[], scope: ProviderEndpoint['scope'] | null, guests: InfraGuest[]) {
  const on = nodes.filter((n) => n.managed && n.status === 'online')
  const memFree = on.reduce((a, n) => a + Math.max(0, (n.mem_total ?? 0) - (n.mem_used ?? 0)), 0)
  const allowed = scope?.allowed_storage ?? []
  const seen = new Set<string>(), st = storage.filter((s) => (allowed.length ? allowed.includes(s.name) : false) && s.active !== false && s.total && (seen.has(s.name) ? false : (seen.add(s.name), true)))
  const diskFree = st.reduce((a, s) => a + Math.max(0, (s.total ?? 0) - (s.used ?? 0)), 0)
  const cpuTotal = on.reduce((a, n) => a + (n.cpu_total ?? 0), 0)
  const cpuFree = on.reduce((a, n) => a + Math.max(0, (n.cpu_total ?? 0) * (1 - (n.cpu_pct ?? 0) / 100)), 0)
  const running = guests.filter((g) => g.status === 'running')
  return { nodesCounted: on.length, memFree, diskFree, cpuTotal, cpuFree, authorisedStorage: st.length, running: running.length, stopped: guests.filter((g) => g.status === 'stopped').length,
    vmsRunning: running.filter((g) => g.kind === 'vm').length, ctsRunning: running.filter((g) => g.kind === 'lxc').length, vmsStopped: guests.filter((g) => g.kind === 'vm' && g.status === 'stopped').length, ctsStopped: guests.filter((g) => g.kind === 'lxc' && g.status === 'stopped').length }
}
export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !isFinite(n)) return '-'
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  let i = 0, x = n
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++ }
  return `${x.toFixed(x >= 100 || i === 0 ? 0 : 1)} ${u[i]}`
}
export const gbOf = (bytes: number | null) => (bytes === null ? 0 : bytes / 1024 ** 3)


// ---------------------------------------------------------------------------------------------------- scope mode (one node or the whole cluster)
export const SCOPE_MODES: { id: ScopeMode; title: string; badge: string; blurb: string; can: string[]; cannot: string[] }[] = [
  { id: 'single_node', title: 'Connect one node only (recommended for security)', badge: 'Recommended',
    blurb: 'Proxmox itself is set up so this integration can see and use one server of the cluster and nothing else. Other nodes stay out of reach even if Office Unbound were compromised, as far as Proxmox can enforce it.',
    can: ['See and use the one node you choose', 'Use storage that exists only on that node'],
    cannot: ['See or use other nodes', 'Place disks on shared storage', 'Move VMs to other nodes'] },
  { id: 'whole_cluster', title: 'Connect the whole cluster', badge: 'Wider access',
    blurb: 'Office Unbound can see every node, including nodes that join later, and may use shared storage you select. Choose this when you want to spread VMs across nodes.',
    can: ['See every node and its capacity', 'Use shared storage when you select it', 'Move VMs between nodes (optional)'],
    cannot: ['Change Proxmox users, roles or permissions (never granted)'] },
]
export const SINGLE_NODE_NOTES = [
  'Proxmox pools and the classic bridge zone are cluster-wide names. Proxmox cannot say "only on node X" for them, so keeping new VMs on the chosen node also relies on node-local storage (Proxmox) and the Office Unbound node allowlist.',
  'You can change the scope later. Widening needs approval; narrowing is refused if it would leave managed VMs outside the new scope.',
]
export type MergedStorage = DiscStorage & { nodes: string[] }
/** Can a VM disk on this storage end up on a node outside `selected`? Shared storage or storage that exists on other nodes can. */
export function storageLocality(s: { shared: boolean; nodes: string[] }, selected: string[]): { local: boolean; reason: string } {
  if (s.shared) return { local: false, reason: 'Shared between nodes: disks could be placed from other nodes.' }
  const other = s.nodes.filter((n) => !selected.includes(n))
  if (other.length) return { local: false, reason: `Also exists on ${other.join(', ')}: disks could be placed there.` }
  return { local: true, reason: `Only exists on ${selected.join(', ')}.` }
}
const holdsDisks = (s: DiscStorage) => s.content.some((c) => c === 'images' || c === 'rootdir')
export function blockedStorages(m: Pick<WizardModel, 'discovery' | 'scope' | 'riskOverrides'>): { name: string; reason: string }[] {
  if (!m.discovery) return []
  return mergeStorage(m.discovery.storage).filter((s) => m.scope.storages.includes(s.name) && holdsDisks(s) && !m.riskOverrides.includes(`shared_storage:${s.name}`))
    .map((s) => ({ name: s.name, ...storageLocality(s, m.scope.nodes) })).filter((x) => !x.local)
}
/** Storage the picker may offer in single-node mode: only node-local ones (others are listed, disabled, with the reason). */
export function storageChoices(d: Discovery | null, mode: ScopeMode, selected: string[], overrides: string[]) {
  return (d ? mergeStorage(d.storage) : []).map((s) => {
    const loc = mode === 'single_node' && holdsDisks(s) ? storageLocality(s, selected) : { local: true, reason: '' }
    const overridden = overrides.includes(`shared_storage:${s.name}`)
    return { ...s, selectable: loc.local || overridden, reason: loc.reason, overridden }
  })
}

// ---------------------------------------------------------------------------------------------------- scope change (provider.scope.change)
export interface ScopeSummary { mode: string; nodes: string[]; storages: string[]; migrate: boolean; overrides: string[] }
export interface AclRow { path: string; role: string; propagate: boolean; subjects: string[]; enforced_by: 'proxmox' | 'ics' }
export interface ScopeChangeOut {
  direction: 'widen' | 'narrow' | 'same'; risk: 'normal' | 'high'; blocked: string[]; detach: number[]
  old_scope: ScopeSummary; new_scope: ScopeSummary
  diff: { acl_add: AclRow[]; acl_remove: AclRow[]; roles: { capability: string; role: string; change: string; added?: string[]; removed?: string[] }[]
    ics_allowlist: { nodes: { before: string[]; after: string[] }; storages: { before: string[]; after: string[] } } }
  impact: { capacity: { node: string; cpus: number | null; mem_gib: number | null; before: boolean; after: boolean; change: 'added' | 'removed' | 'kept' | 'outside' }[]
    managed_guests_outside: { vmid: number; name: string | null; node: string | null; deployment: string | null; why: string[] }[]
    visibility: { nodes_visible_before: string[]; nodes_visible_after: string[] }; notes: string[] }
  enforcement_before: EnforcementNote[]; enforcement_after: EnforcementNote[]
}
export interface ScopePreviewOut { preview_id: string; plan_hash: string; risk: 'normal' | 'high'; direction: ScopeChangeOut['direction']; blocked: string[]; scope: ScopeChangeOut }
export interface ScopeTarget { mode: ScopeMode; nodes: string[]; storages?: string[]; risk_overrides: string[]; detach_orphans: boolean }
export const DIRECTION_TEXT = {
  widen: { title: 'This widens access', text: 'Proxmox will let this integration reach more than before. It is a high-risk change: it needs the extra approvals set for this customer.' },
  narrow: { title: 'This narrows access', text: 'Proxmox will let this integration reach less than before. Normal risk, unless managed VMs have to be detached.' },
  same: { title: 'No change in reach', text: 'The permissions stay the same.' },
} as const
export function scopeTargetValid(t: ScopeTarget): string | null {
  if (t.mode === 'single_node' && !t.nodes.length) return 'Choose at least one node.'
  return null
}
export function scopeTargetOf(view: PermissionsView, mode: ScopeMode, nodes: string[], storages: string[], overrides: string[], detach: boolean): ScopeTarget {
  void view
  return { mode, nodes: mode === 'single_node' ? [...nodes] : [], storages: [...storages], risk_overrides: mode === 'single_node' ? [...overrides] : [], detach_orphans: detach }
}
export function scopePreviewParams(endpointId: string, t: ScopeTarget, c: Creds) {
  return { purpose: 'scope_change' as const, endpoint_id: endpointId, scope_target: t, ...c }
}
export function scopeChangeParams(endpointId: string, p: ScopePreviewOut, execution: 'mode_a' | 'confirm_package', c: Creds, packageId?: string) {
  return { endpoint_id: endpointId, preview_id: p.preview_id, plan_hash: p.plan_hash, direction: p.direction, detach: p.scope.detach.length > 0, execution, ...(packageId ? { package_id: packageId } : {}), ...(execution === 'mode_a' ? c : {}) }
}
export function scopePackageParams(endpointId: string, p: ScopePreviewOut) {
  return { endpoint_id: endpointId, preview_id: p.preview_id, plan_hash: p.plan_hash, direction: p.direction, detach: p.scope.detach.length > 0 }
}
export const scopePreviewOf = (job: JobRow): ScopePreviewOut | null => {
  const r = job.result as Partial<ScopePreviewOut> | null
  return r && r.preview_id && r.plan_hash && r.scope ? (r as ScopePreviewOut) : null
}
export const SCOPE_MODE_LABEL: Record<string, string> = { single_node: 'One node only', whole_cluster: 'Whole cluster', nodes: 'Selected nodes (older setup)' }
