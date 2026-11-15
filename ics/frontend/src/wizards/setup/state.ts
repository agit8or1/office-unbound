// First-run setup wizard: state, validation, readiness, and the exact plan payload (endpoint.register).
import type { Discovery, ProbeRequest, ProbeResult, TlsProbeRequest, TlsResult, TrustMode } from '../api'
import type { Errors, StepDef } from '../kit'
import { DOMAIN_RE, POOL_RE, SLUG_RE, TOKEN_ID_RE, TOKEN_SECRET_RE, intIn, isHost, isIpv4, isPort, looksLikePem, normalizeFingerprint } from '../kit'

export interface SetupModel {
  name: string
  host: string
  port: number
  tokenId: string
  tokenSecret: string
  /** Optional second, pool-scoped credential that allows ICS to create VMs (ADR-0002 section 2). Without it the endpoint is inventory-only. */
  provTokenId: string
  provTokenSecret: string
  trust: TrustMode
  fingerprint: string
  caPem: string
  /** Stage 1: certificate presented by the server, checked before any token is sent. */
  tlsCheck: TlsResult | null
  tlsKey: string | null
  /** Edit mode: id of the existing endpoint (plan = endpoint.update). */
  endpointId: string | null
  probe: ProbeResult | null
  probedKey: string | null
  defaults: {
    pool: string
    /** Cluster nodes ICS may create/change/migrate guests on (deny by default). */
    nodes: string[]
    storage: string
    bridge: string
    vlan: string
    searchDomain: string
    dnsServers: string
    backupStorage: string
    images: string[]
    resourcePolicy: 'conservative' | 'balanced' | 'dense'
  }
  confirmed: boolean
}

export const OS_IMAGES = [
  { id: 'debian-12', label: 'Debian 12 cloud image (checksum-pinned)' },
  { id: 'ubuntu-24.04', label: 'Ubuntu 24.04 cloud image (checksum-pinned)' },
]
export const POLICIES = [
  { id: 'conservative', label: 'Conservative: keep plenty of headroom' },
  { id: 'balanced', label: 'Balanced (recommended)' },
  { id: 'dense', label: 'Dense: pack as much as fits' },
] as const

export function newSetupModel(): SetupModel {
  return {
    name: 'pve-main', host: '', port: 8006, tokenId: '', tokenSecret: '', provTokenId: '', provTokenSecret: '', trust: 'fingerprint', fingerprint: '', caPem: '',
    tlsCheck: null, tlsKey: null, endpointId: null, probe: null, probedKey: null,
    defaults: {
      pool: '', nodes: [], storage: '', bridge: '', vlan: '', searchDomain: '', dnsServers: '', backupStorage: '', images: ['debian-12'], resourcePolicy: 'balanced',
    },
    confirmed: false,
  }
}

export const baseUrl = (m: SetupModel) => `https://${m.host.trim()}${m.port === 443 ? '' : ':' + m.port}`

export function probeRequest(m: SetupModel): ProbeRequest {
  const r: ProbeRequest = { base_url: baseUrl(m), token_id: m.tokenId.trim(), token_secret: m.tokenSecret.trim() }
  if (m.trust === 'fingerprint') r.fingerprint_sha256 = normalizeFingerprint(m.fingerprint) ?? ''
  else r.ca_pem = m.caPem.trim()
  if (hasProvision(m)) { r.provision_token_id = m.provTokenId.trim(); r.provision_token_secret = m.provTokenSecret.trim() }
  return r
}

export const hasProvision = (m: SetupModel) => !!(m.provTokenId.trim() || m.provTokenSecret.trim())

export function tlsRequest(m: SetupModel): TlsProbeRequest {
  const r: TlsProbeRequest = { stage: 'tls', base_url: baseUrl(m) }
  if (m.trust === 'fingerprint') r.fingerprint_sha256 = normalizeFingerprint(m.fingerprint) ?? ''
  else r.ca_pem = m.caPem.trim()
  return r
}
/** Identifies the server-identity inputs (no credentials) a certificate check belongs to. */
export function identityKey(m: SetupModel): string { return JSON.stringify(tlsRequest(m)) }
/**
 * The server identity is verified when the certificate check ran for exactly these inputs and either the CA verified the chain,
 * or the fingerprint the admin typed (obtained out of band) equals the one the server presented. Tokens are only sent after this.
 */
export function identityVerified(m: SetupModel): boolean {
  const t = m.tlsCheck
  if (!t || m.tlsKey !== identityKey(m) || !t.ok) return false
  if (m.trust === 'ca') return true
  const presented = t.presented_fingerprint_sha256 ? normalizeFingerprint(t.presented_fingerprint_sha256) : null
  return !!presented && presented === normalizeFingerprint(m.fingerprint)
}
export function fingerprintMismatch(m: SetupModel): boolean {
  const t = m.tlsCheck
  if (!t || m.tlsKey !== identityKey(m) || m.trust !== 'fingerprint' || !t.presented_fingerprint_sha256) return false
  return normalizeFingerprint(t.presented_fingerprint_sha256) !== normalizeFingerprint(m.fingerprint)
}

/** Identifies the connection inputs a probe result belongs to; any change invalidates the result. Never rendered. */
export function connectionKey(m: SetupModel): string {
  return JSON.stringify(probeRequest(m))
}

export function validateIdentityFields(m: SetupModel): Errors {
  const e: Errors = {}
  if (!m.host.trim()) e.host = 'Enter the Proxmox host name or IP address.'
  else if (!isHost(m.host.trim())) e.host = 'Not a valid host name or IPv4 address (no scheme, port or path).'
  if (!isPort(m.port)) e.port = 'Port must be a whole number from 1 to 65535.'
  if (m.trust === 'fingerprint') {
    if (!m.fingerprint.trim()) e.fingerprint = 'Enter the SHA-256 fingerprint you obtained out of band. TLS is always verified.'
    else if (!normalizeFingerprint(m.fingerprint)) e.fingerprint = 'Expected 64 hex digits (32 bytes), optionally separated by ":".'
  } else if (!looksLikePem(m.caPem)) e.caPem = 'Paste the CA certificate in PEM form (-----BEGIN CERTIFICATE----- ...).'
  return e
}

export function validateCredentialFields(m: SetupModel): Errors {
  const e: Errors = {}
  if (!SLUG_RE.test(m.name)) e.name = 'Use lower-case letters, digits, "-" or "_" (max 63), starting with a letter or digit.'
  if (!TOKEN_ID_RE.test(m.tokenId.trim())) e.tokenId = 'Format: user@realm!tokenname, for example ics-inventory@pve!inventory.'
  if (!TOKEN_SECRET_RE.test(m.tokenSecret.trim())) e.tokenSecret = 'The secret is 8-200 characters of letters, digits, "_" or "-" (surrounding whitespace is ignored).'
  if (hasProvision(m)) {
    if (!TOKEN_ID_RE.test(m.provTokenId.trim())) e.provTokenId = 'Format: user@realm!tokenname. Leave both provisioning fields empty for a read-only connection.'
    if (!TOKEN_SECRET_RE.test(m.provTokenSecret.trim())) e.provTokenSecret = 'The secret is 8-200 characters of letters, digits, "_" or "-".'
    if (m.provTokenId.trim() === m.tokenId.trim()) e.provTokenId = 'Use a different token than the read-only one: ICS keeps inventory and provisioning credentials separate.'
  }
  return e
}

export function validateConnectionFields(m: SetupModel): Errors { return { ...validateCredentialFields(m), ...validateIdentityFields(m) } }

export function probeIsCurrent(m: SetupModel): boolean {
  return !!m.probe && m.probedKey !== null && m.probedKey === connectionKey(m)
}

export function validateConnection(m: SetupModel): Errors {
  const e = validateConnectionFields(m)
  if (Object.keys(e).length) return e
  if (!identityVerified(m)) e.identity = 'Check the server certificate and compare its fingerprint before sending any credentials.'
  else if (!probeIsCurrent(m)) e.probe = 'Run "Test connection" with these exact details before continuing.'
  else if (!m.probe!.tls.ok) e.probe = 'TLS verification failed. Fix the fingerprint or CA before continuing.'
  else if (!m.probe!.permissions.inventory.ok) e.probe = 'The token cannot read inventory yet. Apply the listed commands on the Proxmox node and test again.'
  return e
}

export const discovery = (m: SetupModel): Discovery | null => m.probe?.discovery ?? null

export function validateDiscovery(m: SetupModel): Errors {
  const d = discovery(m)
  if (!d || d.nodes.length === 0) return { discovery: 'Discovery returned no nodes. Go back and test the connection again.' }
  return {}
}

export function storageFor(m: SetupModel, content: string) { return (discovery(m)?.storage ?? []).filter((s) => s.content.includes(content)) }

/** Express path: pre-fill everything the discovery makes unambiguous. Never overwrites a value the user already chose. */
export function autoDefaults(m: SetupModel): void {
  const d = m.defaults
  const disc = discovery(m)
  if (!disc) return
  const managed = disc.nodes.filter((n) => n.managed !== false && n.status === 'online')
  if (!d.nodes.length && managed.length === 1) d.nodes = [managed[0]!.name]
  const images = storageFor(m, 'images')
  if (!d.storage && images.length === 1) d.storage = images[0]!.id
  const backups = storageFor(m, 'backup')
  if (!d.backupStorage && backups.length === 1) d.backupStorage = backups[0]!.id
  const bridges = disc.networks.filter((n) => n.kind === 'bridge')
  if (!d.bridge && new Set(bridges.map((b) => b.name)).size === 1) d.bridge = bridges[0]!.name
  if (!d.pool && disc.pools?.length === 1) d.pool = disc.pools[0]!
}

export function validateDefaults(m: SetupModel): Errors {
  const e: Errors = {}
  const d = m.defaults
  if (hasProvision(m)) {
    if (!POOL_RE.test(d.pool)) e.pool = 'Choose the resource pool the provisioning token is allowed to use.'
    if (!d.nodes.length) e.nodes = 'Choose at least one node ICS may create machines on.'
    if (!d.storage) e.storage = 'Choose the storage for VM disks.'
    if (!d.bridge) e.bridge = 'Choose the network bridge.'
  }
  if (d.vlan.trim() !== '' && !(/^\d+$/.test(d.vlan.trim()) && intIn(Number(d.vlan), 1, 4094))) e.vlan = 'VLAN tag must be 1-4094, or empty for untagged.'
  if (d.searchDomain.trim() && !DOMAIN_RE.test(d.searchDomain.trim())) e.searchDomain = 'Enter a domain such as your-company.tld.'
  if (d.dnsServers.trim() && !splitList(d.dnsServers).every(isIpv4)) e.dnsServers = 'Comma-separated IPv4 addresses.'
  if (d.images.length === 0) e.images = 'Approve at least one OS image.'
  return e
}

export interface Check { id: string; level: 'ok' | 'warn' | 'bad'; text: string; blocks?: 'provisioning' }
export function readiness(m: SetupModel): Check[] {
  const c: Check[] = []
  const pr = m.probe
  const cur = probeIsCurrent(m)
  c.push(cur && pr?.tls.ok ? { id: 'tls', level: 'ok', text: `TLS verified by ${pr!.tls.verified_by === 'ca' ? 'CA bundle' : 'pinned fingerprint'}.` } : { id: 'tls', level: 'bad', text: 'TLS has not been verified for these connection details.' })
  c.push(cur && pr?.permissions.inventory.ok ? { id: 'inv', level: 'ok', text: 'Inventory (read-only) permissions are sufficient.' } : { id: 'inv', level: 'bad', text: 'Inventory permissions are missing.' })
  c.push(!hasProvision(m)
    ? { id: 'prov', level: 'warn', text: 'No provisioning token: ICS will only read this cluster. Deployments stay blocked until one is added (Settings, Endpoints).' }
    : cur && pr?.permissions.provision.ok
      ? { id: 'prov', level: 'ok', text: 'The provisioning token has the permissions ICS needs in the chosen pool, storage and network.' }
      : { id: 'prov', level: 'bad', blocks: 'provisioning', text: 'The provisioning token is missing permissions (see the list above). Fix them, or remove the token to register read-only. You can still register now; deployments stay blocked until it passes.' })
  const sdn = sdnMissing(m)
  if (cur && sdn.length) c.push({ id: 'sdn', level: 'bad', blocks: 'provisioning', text: `The token lacks SDN.Use on ${sdn.map((x) => x.path).join(', ')}: VMs cannot be attached to those bridges, so provisioning is blocked until it is granted.` })
  if (cur && (pr?.permissions.provision.unnecessary?.length || pr?.permissions.inventory.unnecessary?.length)) c.push({ id: 'extra', level: 'warn', text: `The token holds privileges ICS does not need (${unnecessaryList(m).join(', ')}). Remove them to keep the token least-privilege.` })
  c.push(discovery(m)?.nodes.length ? { id: 'disc', level: 'ok', text: `${discovery(m)!.nodes.length} node(s) discovered.` } : { id: 'disc', level: 'bad', text: 'No nodes discovered.' })
  c.push(Object.keys(validateDefaults(m)).length ? { id: 'def', level: 'bad', text: 'Deployment defaults are incomplete.' } : { id: 'def', level: 'ok', text: 'Deployment defaults are complete.' })
  return c
}
/** Provisioning-only blockers (e.g. missing SDN.Use) do not stop registering an inventory-only endpoint. */
export const isReady = (m: SetupModel) => readiness(m).every((c) => c.level !== 'bad' || c.blocks === 'provisioning')
export const sdnMissing = (m: SetupModel) => (m.probe?.permissions.provision.missing ?? []).filter((x) => x.privilege === 'SDN.Use')
export const unnecessaryList = (m: SetupModel) => [...new Set([...(m.probe?.permissions.inventory.unnecessary ?? []), ...(m.probe?.permissions.provision.unnecessary ?? [])].map((x) => x.privilege))]

export function splitList(s: string): string[] { return s.split(',').map((x) => x.trim()).filter(Boolean) }

/** Exact params for POST /plans {action: 'endpoint.register'}. Scope and defaults travel inside the same plan so one approval covers connection + policy. */
export function buildRegisterParams(m: SetupModel): Record<string, unknown> {
  const d = m.defaults
  const prov = hasProvision(m)
  const net = d.vlan.trim() ? `${d.bridge}/${Number(d.vlan)}` : d.bridge
  const storage = [...new Set([d.storage, d.backupStorage].filter(Boolean))]
  const p: Record<string, unknown> = {
    name: m.name,
    type: 'proxmox',
    base_url: baseUrl(m),
    token_id: m.tokenId.trim(),
    token_secret: m.tokenSecret.trim(),
  }
  if (m.trust === 'fingerprint') p.fingerprint_sha256 = normalizeFingerprint(m.fingerprint)
  else p.ca_pem = m.caPem.trim()
  if (prov) { p.provision_token_id = m.provTokenId.trim(); p.provision_token_secret = m.provTokenSecret.trim() }
  p.allowed_pools = prov ? [d.pool] : []
  p.allowed_nodes = prov ? [...d.nodes].sort() : []
  p.allowed_storage = prov ? storage : []
  p.allowed_networks = prov ? [net] : []
  const defaults: Record<string, unknown> = { resource_policy: d.resourcePolicy, ip_mode: 'dhcp', approved_os_images: [...d.images].sort() }
  if (d.storage) defaults.storage = d.storage
  if (d.bridge) defaults.bridge = d.bridge
  if (d.vlan.trim()) defaults.vlan = Number(d.vlan)
  if (d.searchDomain.trim()) defaults.search_domain = d.searchDomain.trim()
  if (splitList(d.dnsServers).length) defaults.dns_servers = splitList(d.dnsServers)
  if (d.backupStorage) defaults.backup_storage = d.backupStorage
  p.defaults = defaults
  return p
}

/** Submit only from the review step, with a ready model and explicit confirmation. */
export function assertSubmittable(m: SetupModel, onReviewStep: boolean): void {
  if (!onReviewStep) throw new Error('Review step has not been reached.')
  if (!m.confirmed) throw new Error('Confirm the review before submitting.')
  if (!isReady(m)) throw new Error('Readiness checks have blocking failures.')
  if (!probeIsCurrent(m)) throw new Error('Connection details changed after the last test.')
  if (!identityVerified(m)) throw new Error('Server identity has not been verified.')
}

/** pveum commands that grant what a probe reported missing (mirrors docs/status/proxmox-setup.md). */
export function fixCommands(m: SetupModel): { inventory: string[]; provision: string[] } {
  const pr = m.probe
  const tid = m.tokenId.trim() || '<user>@<realm>!<token>'
  const user = tid.split('!')[0]
  const out = { inventory: [] as string[], provision: [] as string[] }
  if (!pr) return out
  if (!pr.permissions.inventory.ok) {
    out.inventory = pr.permissions.inventory.fix_commands?.length ? pr.permissions.inventory.fix_commands : [
      `pveum acl modify / --users ${user} --roles PVEAuditor`,
      `pveum acl modify / --tokens '${tid}' --roles PVEAuditor`,
    ]
  }
  const sdn = sdnMissing(m)
  if (hasProvision(m) && sdn.length && !pr.permissions.provision.fix_commands?.length) {
    out.provision = sdn.map((x) => `pveum acl modify ${x.path} --tokens '${tid}' --roles PVESDNUser`)
  }
  if (hasProvision(m) && !pr.permissions.provision.ok && !out.provision.length) {
    const d = m.defaults
    const pool = d.pool || 'ou-lab'
    const st = d.storage || '<STORAGE>'
    const br = d.bridge || '<BRIDGE>'
    out.provision = pr.permissions.provision.fix_commands?.length ? pr.permissions.provision.fix_commands : [
      `pveum pool add ${pool} --comment "Office Unbound lab - isolated"`,
      'pveum role add OULabProvisioner --privs "VM.Allocate VM.Clone VM.Audit VM.PowerMgmt VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options"',
      ...[`--users ${user}`, `--tokens '${tid}'`].flatMap((who) => [
        `pveum acl modify /pool/${pool} ${who} --roles OULabProvisioner`,
        `pveum acl modify /storage/${st} ${who} --roles PVEDatastoreUser`,
        `pveum acl modify /sdn/zones/localnetwork/${br} ${who} --roles PVESDNUser`,
      ]),
    ]
  }
  return out
}

export const setupSteps: StepDef<SetupModel>[] = [
  { id: 'connection', title: 'Connection', validate: validateConnection },
  { id: 'discovery', title: 'Discovery', validate: validateDiscovery },
  { id: 'defaults', title: 'Defaults', validate: validateDefaults },
  { id: 'review', title: 'Verify and submit' },
]

// ---- editing an existing endpoint's connection (route /setup/connection?endpoint=<id>) ----
export const connectionSteps: StepDef<SetupModel>[] = [
  { id: 'connection', title: 'Connection', validate: validateConnection },
  { id: 'review', title: 'Review and submit' },
]

/** Exact params for POST /plans {action: 'endpoint.update'}: connection details only; defaults and policy are untouched. */
export function buildUpdateParams(m: SetupModel): Record<string, unknown> {
  const p: Record<string, unknown> = {
    endpoint_id: m.endpointId,
    base_url: baseUrl(m),
    token_id: m.tokenId.trim(),
    token_secret: m.tokenSecret.trim(),
  }
  if (m.trust === 'fingerprint') p.fingerprint_sha256 = normalizeFingerprint(m.fingerprint)
  else p.ca_pem = m.caPem.trim()
  if (hasProvision(m)) { p.provision_token_id = m.provTokenId.trim(); p.provision_token_secret = m.provTokenSecret.trim() }
  return p
}

export function assertConnectionSubmittable(m: SetupModel, onReviewStep: boolean): void {
  if (!onReviewStep) throw new Error('Review step has not been reached.')
  if (!m.endpointId) throw new Error('No endpoint selected for editing.')
  if (!m.confirmed) throw new Error('Confirm the review before submitting.')
  if (!identityVerified(m)) throw new Error('Server identity has not been verified for these details.')
  if (!probeIsCurrent(m) || !m.probe!.tls.ok || !m.probe!.permissions.inventory.ok) throw new Error('The connection test must pass for the current details.')
}

/** "Add endpoint" without the full setup: connection only, nothing allowed for provisioning until scopes are set. */
export function buildAddParams(m: SetupModel): Record<string, unknown> {
  const p = buildRegisterParams(m)
  delete p.defaults
  p.allowed_pools = []; p.allowed_nodes = []; p.allowed_storage = []; p.allowed_networks = []
  delete p.provision_token_id; delete p.provision_token_secret // provisioning needs scopes: set them in first-run setup
  return p
}

/** Fill the connection fields from an existing endpoint record (edit mode). The secret is never prefilled. */
export function prefillFromEndpoint(m: SetupModel, e: { id: string; name: string; base_url: string; credentials: { inventory: { token_id: string } }; trust: string; fingerprint_sha256: string | null }) {
  m.endpointId = e.id
  m.name = e.name
  try {
    const u = new URL(e.base_url)
    m.host = u.hostname
    m.port = u.port ? Number(u.port) : 443
  } catch { /* leave empty; validation will ask */ }
  m.tokenId = e.credentials.inventory.token_id
  m.trust = e.trust === 'ca_bundle' ? 'ca' : 'fingerprint'
  m.fingerprint = e.fingerprint_sha256 ?? ''
}
