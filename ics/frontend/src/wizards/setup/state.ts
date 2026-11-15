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
    storage: string
    bridge: string
    vlan: string
    ipMode: 'dhcp' | 'static'
    ipStart: string; ipEnd: string; gateway: string; prefix: number
    domain: string
    dnsServers: string
    backupStorage: string
    images: string[]
    maxCores: number; maxMemoryGb: number; maxDiskGb: number; cpuOvercommit: number
  }
  security: { approvalsLow: 1 | 2; approvalsHigh: 1 | 2; requireMfaForApprovers: boolean; alertKind: 'none' | 'email' | 'webhook'; alertTarget: string }
  confirmed: boolean
}

export const OS_IMAGES = [
  { id: 'debian-12', label: 'Debian 12 cloud image (checksum-pinned)' },
  { id: 'ubuntu-24.04', label: 'Ubuntu 24.04 cloud image (checksum-pinned)' },
]

export function newSetupModel(): SetupModel {
  return {
    name: 'pve-main', host: '', port: 8006, tokenId: '', tokenSecret: '', trust: 'fingerprint', fingerprint: '', caPem: '',
    tlsCheck: null, tlsKey: null, endpointId: null, probe: null, probedKey: null,
    defaults: {
      pool: 'ou-lab', storage: '', bridge: '', vlan: '', ipMode: 'dhcp', ipStart: '', ipEnd: '', gateway: '', prefix: 24,
      domain: '', dnsServers: '', backupStorage: '', images: ['debian-12'],
      maxCores: 16, maxMemoryGb: 64, maxDiskGb: 500, cpuOvercommit: 2,
    },
    security: { approvalsLow: 1, approvalsHigh: 2, requireMfaForApprovers: true, alertKind: 'none', alertTarget: '' },
    confirmed: false,
  }
}

export const baseUrl = (m: SetupModel) => `https://${m.host.trim()}${m.port === 443 ? '' : ':' + m.port}`

export function probeRequest(m: SetupModel): ProbeRequest {
  const r: ProbeRequest = { base_url: baseUrl(m), token_id: m.tokenId.trim(), token_secret: m.tokenSecret.trim() }
  if (m.trust === 'fingerprint') r.fingerprint_sha256 = normalizeFingerprint(m.fingerprint) ?? ''
  else r.ca_pem = m.caPem.trim()
  return r
}

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

export function validateDefaults(m: SetupModel): Errors {
  const e: Errors = {}
  const d = m.defaults
  if (!POOL_RE.test(d.pool)) e.pool = 'Pool names start with a letter; letters, digits, "-" and "_" only.'
  if (!d.storage) e.storage = 'Choose the default storage for VM disks.'
  if (!d.bridge) e.bridge = 'Choose the default bridge.'
  if (d.vlan.trim() !== '' && !(/^\d+$/.test(d.vlan.trim()) && intIn(Number(d.vlan), 1, 4094))) e.vlan = 'VLAN tag must be 1-4094, or empty for untagged.'
  if (d.ipMode === 'static') {
    for (const k of ['ipStart', 'ipEnd', 'gateway'] as const) if (!isIpv4(d[k])) e[k] = 'Enter an IPv4 address.'
    if (!intIn(d.prefix, 8, 30)) e.prefix = 'Prefix length must be 8-30.'
  }
  if (d.domain.trim() && !DOMAIN_RE.test(d.domain.trim())) e.domain = 'Enter a domain such as corp.example.com.'
  if (d.dnsServers.trim() && !splitList(d.dnsServers).every(isIpv4)) e.dnsServers = 'Comma-separated IPv4 addresses.'
  if (d.images.length === 0) e.images = 'Approve at least one OS image.'
  if (!intIn(d.maxCores, 1, 4096)) e.maxCores = 'Whole number 1-4096.'
  if (!intIn(d.maxMemoryGb, 1, 65536)) e.maxMemoryGb = 'Whole number 1-65536.'
  if (!intIn(d.maxDiskGb, 10, 1048576)) e.maxDiskGb = 'Whole number of at least 10.'
  if (!(d.cpuOvercommit >= 1 && d.cpuOvercommit <= 8)) e.cpuOvercommit = 'Between 1 and 8.'
  return e
}

export function validateSecurity(m: SetupModel): Errors {
  const e: Errors = {}
  const s = m.security
  if (s.alertKind === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.alertTarget)) e.alertTarget = 'Enter a valid e-mail address.'
  if (s.alertKind === 'webhook' && !/^https:\/\/[^\s/]+\S*$/.test(s.alertTarget)) e.alertTarget = 'Webhooks must be https:// URLs.'
  if (s.approvalsHigh < s.approvalsLow) e.approvalsHigh = 'High-risk actions need at least as many approvals as low-risk ones.'
  return e
}

export interface Check { id: string; level: 'ok' | 'warn' | 'bad'; text: string; blocks?: 'provisioning' }
export function readiness(m: SetupModel): Check[] {
  const c: Check[] = []
  const pr = m.probe
  const cur = probeIsCurrent(m)
  c.push(cur && pr?.tls.ok ? { id: 'tls', level: 'ok', text: `TLS verified by ${pr!.tls.verified_by === 'ca' ? 'CA bundle' : 'pinned fingerprint'}.` } : { id: 'tls', level: 'bad', text: 'TLS has not been verified for these connection details.' })
  c.push(cur && pr?.permissions.inventory.ok ? { id: 'inv', level: 'ok', text: 'Inventory (read-only) permissions are sufficient.' } : { id: 'inv', level: 'bad', text: 'Inventory permissions are missing.' })
  c.push(cur && pr?.permissions.provision.ok
    ? { id: 'prov', level: 'ok', text: 'Provision permissions are sufficient for the allowed pool, storage and network.' }
    : { id: 'prov', level: 'warn', text: 'Provision permissions are missing: the endpoint registers as inventory-only and deployments stay blocked until provision access is added.' })
  const sdn = sdnMissing(m)
  if (cur && sdn.length) c.push({ id: 'sdn', level: 'bad', blocks: 'provisioning', text: `The token lacks SDN.Use on ${sdn.map((x) => x.path).join(', ')}: VMs cannot be attached to those bridges, so provisioning is blocked until it is granted.` })
  if (cur && (pr?.permissions.provision.unnecessary?.length || pr?.permissions.inventory.unnecessary?.length)) c.push({ id: 'extra', level: 'warn', text: `The token holds privileges ICS does not need (${unnecessaryList(m).join(', ')}). Remove them to keep the token least-privilege.` })
  c.push(discovery(m)?.nodes.length ? { id: 'disc', level: 'ok', text: `${discovery(m)!.nodes.length} node(s) discovered.` } : { id: 'disc', level: 'bad', text: 'No nodes discovered.' })
  c.push(Object.keys(validateDefaults(m)).length ? { id: 'def', level: 'bad', text: 'Deployment defaults are incomplete.' } : { id: 'def', level: 'ok', text: 'Deployment defaults are complete.' })
  c.push(Object.keys(validateSecurity(m)).length ? { id: 'sec', level: 'bad', text: 'Security settings are invalid.' } : { id: 'sec', level: m.security.alertKind === 'none' ? 'warn' : 'ok', text: m.security.alertKind === 'none' ? 'No alert channel configured: incidents will only appear in the console.' : 'Alert channel configured.' })
  return c
}
/** Provisioning-only blockers (e.g. missing SDN.Use) do not stop registering an inventory-only endpoint. */
export const isReady = (m: SetupModel) => readiness(m).every((c) => c.level !== 'bad' || c.blocks === 'provisioning')
export const sdnMissing = (m: SetupModel) => (m.probe?.permissions.provision.missing ?? []).filter((x) => x.privilege === 'SDN.Use')
export const unnecessaryList = (m: SetupModel) => [...new Set([...(m.probe?.permissions.inventory.unnecessary ?? []), ...(m.probe?.permissions.provision.unnecessary ?? [])].map((x) => x.privilege))]

export function splitList(s: string): string[] { return s.split(',').map((x) => x.trim()).filter(Boolean) }

/** Exact params for POST /plans {action: 'endpoint.register'}. Defaults travel inside the same plan so one approval covers connection + policy. */
export function buildRegisterParams(m: SetupModel): Record<string, unknown> {
  const d = m.defaults
  const provision = !!m.probe?.permissions.provision.ok
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
  p.credential_roles = provision ? ['inventory', 'provision'] : ['inventory']
  p.allowed_pools = provision ? [d.pool] : []
  p.allowed_storage = provision ? storage : []
  p.allowed_networks = provision ? [net] : []
  p.defaults = {
    storage: d.storage,
    network: { bridge: d.bridge, vlan: d.vlan.trim() ? Number(d.vlan) : null },
    ip: d.ipMode === 'dhcp' ? { mode: 'dhcp' } : { mode: 'static', start: d.ipStart, end: d.ipEnd, gateway: d.gateway, prefix: d.prefix },
    dns: { domain: d.domain.trim() || null, servers: splitList(d.dnsServers) },
    backup_storage: d.backupStorage || null,
    approved_images: [...d.images].sort(),
    resource_policy: { max_cores: d.maxCores, max_memory_gb: d.maxMemoryGb, max_disk_gb: d.maxDiskGb, cpu_overcommit: d.cpuOvercommit },
    security: {
      approvals_required: { low: m.security.approvalsLow, high: m.security.approvalsHigh },
      require_mfa_for_approvers: m.security.requireMfaForApprovers,
      alert_channel: m.security.alertKind === 'none' ? null : { kind: m.security.alertKind, target: m.security.alertTarget.trim() },
    },
  }
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
  if (sdn.length && !pr.permissions.provision.fix_commands?.length) {
    out.provision = sdn.map((x) => `pveum acl modify ${x.path} --tokens '${tid}' --roles PVESDNUser`)
  }
  if (!pr.permissions.provision.ok && !out.provision.length) {
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
  { id: 'security', title: 'Security', validate: validateSecurity },
  { id: 'review', title: 'Verify and submit' },
]

// ---- editing an existing endpoint's connection (route /setup/connection?endpoint=<id>) ----
export const connectionSteps: StepDef<SetupModel>[] = [
  { id: 'connection', title: 'Connection', validate: validateConnection },
  { id: 'review', title: 'Review and submit' },
]

/** Exact params for POST /plans {action: 'endpoint.update'}: connection details only; defaults and policy are untouched. */
export function buildUpdateParams(m: SetupModel): Record<string, unknown> {
  const provision = !!m.probe?.permissions.provision.ok
  const p: Record<string, unknown> = {
    endpoint_id: m.endpointId,
    base_url: baseUrl(m),
    token_id: m.tokenId.trim(),
    token_secret: m.tokenSecret.trim(),
  }
  if (m.trust === 'fingerprint') p.fingerprint_sha256 = normalizeFingerprint(m.fingerprint)
  else p.ca_pem = m.caPem.trim()
  p.credential_roles = provision ? ['inventory', 'provision'] : ['inventory']
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
  p.allowed_pools = []; p.allowed_storage = []; p.allowed_networks = []
  return p
}

/** Fill the connection fields from an existing endpoint record (edit mode). The secret is never prefilled. */
export function prefillFromEndpoint(m: SetupModel, e: { id: string; name: string; base_url: string; token_id: string; fingerprint_sha256: string | null }) {
  m.endpointId = e.id
  m.name = e.name
  try {
    const u = new URL(e.base_url)
    m.host = u.hostname
    m.port = u.port ? Number(u.port) : 443
  } catch { /* leave empty; validation will ask */ }
  m.tokenId = e.token_id
  m.trust = e.fingerprint_sha256 ? 'fingerprint' : 'ca'
  m.fingerprint = e.fingerprint_sha256 ?? ''
}
