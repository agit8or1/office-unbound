import { describe, expect, it } from 'vitest'
import type { ProbeResult } from '../api'
import {
  assertConnectionSubmittable, assertSubmittable, buildAddParams, buildRegisterParams, buildUpdateParams, connectionKey, fixCommands, identityKey, identityVerified,
  isReady, newSetupModel, prefillFromEndpoint, probeRequest, readiness, tlsRequest, validateConnection, validateConnectionFields, validateDefaults, validateSecurity,
} from './state'
import type { SetupModel } from './state'

const FP = Array.from({ length: 32 }, (_, i) => (i * 7 + 3).toString(16).padStart(2, '0')).join(':').toUpperCase()
const SECRET = 'abcdEFGH_12345678'

function probe(over: Partial<ProbeResult['permissions']> = {}): ProbeResult {
  return {
    ok: true, version: '9.0.3', tls: { ok: true, verified_by: 'fingerprint', presented_fingerprint_sha256: FP },
    permissions: { inventory: { ok: true, missing: [] }, provision: { ok: true, missing: [] }, ...over },
    discovery: { nodes: [{ name: 'n1', status: 'online', cpu_total: 8, cpu_used: 1, mem_total_gb: 64, mem_used_gb: 8 }], storage: [{ id: 'zfs', node: null, type: 'zfspool', content: ['images'], total_gb: 100, used_gb: 10 }], networks: [{ name: 'vmbr0', node: null, kind: 'bridge' }], guests: [] },
  }
}
function filled(p: ProbeResult = probe()): SetupModel {
  const m = newSetupModel()
  Object.assign(m, { host: 'pve.example.internal', tokenId: 'ics-inv@pve!inventory', tokenSecret: SECRET, fingerprint: FP })
  m.tlsCheck = p.tls; m.tlsKey = identityKey(m)
  m.probe = p; m.probedKey = connectionKey(m)
  Object.assign(m.defaults, { storage: 'zfs', bridge: 'vmbr0', backupStorage: 'pbs', vlan: '120' })
  return m
}

describe('setup: connection step', () => {
  it('validates every connection field with a message', () => {
    const m = newSetupModel()
    m.port = 70000; m.tokenId = 'bad'; m.tokenSecret = 'x'; m.host = 'https://x'
    const e = validateConnectionFields(m)
    expect(Object.keys(e).sort()).toEqual(['fingerprint', 'host', 'port', 'tokenId', 'tokenSecret'])
  })
  it('requires TLS trust: pin or CA, and builds the matching probe request', () => {
    const m = filled()
    expect(probeRequest(m)).toEqual({ base_url: 'https://pve.example.internal:8006', token_id: 'ics-inv@pve!inventory', token_secret: SECRET, fingerprint_sha256: FP })
    m.trust = 'ca'; m.caPem = 'nope'
    expect(validateConnectionFields(m).caPem).toBeTruthy()
  })
  it('stage 1 request carries no credentials', () => {
    const r = tlsRequest(filled())
    expect(r).toEqual({ stage: 'tls', base_url: 'https://pve.example.internal:8006', fingerprint_sha256: FP })
    expect(JSON.stringify(r)).not.toContain(SECRET)
  })
  it('identity is verified only when presented and entered fingerprints match', () => {
    const m = filled()
    expect(identityVerified(m)).toBe(true)
    m.fingerprint = FP.replace(/^../, 'FF')
    expect(identityVerified(m)).toBe(false) // changed input or mismatch
    const other = filled()
    other.tlsCheck = { ...other.tlsCheck!, presented_fingerprint_sha256: 'AA:' + FP.slice(3) }
    expect(identityVerified(other)).toBe(false)
  })
  it('cannot continue without a current successful probe and verified identity', () => {
    const m = filled()
    expect(validateConnection(m)).toEqual({})
    m.host = 'other.example.internal' // changes the key
    expect(validateConnection(m).identity).toBeTruthy()
    const noInv = filled(probe({ inventory: { ok: false, missing: [{ path: '/', privilege: 'Sys.Audit' }] } }))
    expect(validateConnection(noInv).probe).toMatch(/inventory/)
  })
})

describe('setup: permission matrix fixes', () => {
  it('missing SDN.Use is a provisioning blocker with the exact pveum command; inventory-only registration still allowed', () => {
    const m = filled(probe({ provision: { ok: false, missing: [{ path: '/sdn/zones/localnetwork/vmbr0', privilege: 'SDN.Use' }] }, inventory: { ok: true, missing: [], unnecessary: [{ path: '/', privilege: 'VM.Console' }] } }))
    m.tokenId = 'officeunbound@pam!ics'; m.tlsKey = identityKey(m); m.probedKey = connectionKey(m)
    expect(fixCommands(m).provision).toEqual(["pveum acl modify /sdn/zones/localnetwork/vmbr0 --tokens 'officeunbound@pam!ics' --roles PVESDNUser"])
    const checks = readiness(m)
    expect(checks.find((c) => c.id === 'sdn')).toMatchObject({ level: 'bad', blocks: 'provisioning' })
    expect(checks.find((c) => c.id === 'extra')?.text).toContain('VM.Console')
    expect(isReady(m)).toBe(true)
    expect(buildRegisterParams(m).credential_roles).toEqual(['inventory'])
    expect(buildRegisterParams(m).allowed_pools).toEqual([])
  })
  it('fix commands mirror docs/status/proxmox-setup.md when provision is wholly missing', () => {
    const m = filled(probe({ provision: { ok: false, missing: [{ path: '/pool/ou-lab', privilege: 'VM.Allocate' }] } }))
    const c = fixCommands(m).provision
    expect(c[0]).toBe('pveum pool add ou-lab --comment "Office Unbound lab - isolated"')
    expect(c.some((l) => l.startsWith('pveum role add OULabProvisioner --privs "VM.Allocate VM.Clone'))).toBe(true)
    expect(c).toContain("pveum acl modify /storage/zfs --tokens 'ics-inv@pve!inventory' --roles PVEDatastoreUser")
  })
  it('prefers server-supplied fix commands', () => {
    const m = filled(probe({ inventory: { ok: false, missing: [], fix_commands: ['custom cmd'] } }))
    expect(fixCommands(m).inventory).toEqual(['custom cmd'])
  })
})

describe('setup: defaults and security validation', () => {
  it('flags missing and invalid defaults', () => {
    const m = filled()
    m.defaults.storage = ''; m.defaults.vlan = '5000'; m.defaults.ipMode = 'static'; m.defaults.images = []
    expect(Object.keys(validateDefaults(m)).sort()).toEqual(['images', 'ipEnd', 'ipStart', 'gateway', 'storage', 'vlan'].sort())
  })
  it('security: webhook must be https, high needs >= low', () => {
    const m = filled()
    m.security.alertKind = 'webhook'; m.security.alertTarget = 'http://x'
    m.security.approvalsLow = 2; m.security.approvalsHigh = 1
    expect(Object.keys(validateSecurity(m)).sort()).toEqual(['alertTarget', 'approvalsHigh'])
  })
})

describe('setup: exact endpoint.register payload', () => {
  it('matches the contract JSON', () => {
    const m = filled()
    m.defaults.domain = 'corp.example.com'; m.defaults.dnsServers = '192.168.1.1, 1.1.1.1'
    m.security.alertKind = 'email'; m.security.alertTarget = 'ops@example.com'
    expect(JSON.parse(JSON.stringify(buildRegisterParams(m)))).toEqual({
      name: 'pve-main', type: 'proxmox', base_url: 'https://pve.example.internal:8006', token_id: 'ics-inv@pve!inventory', token_secret: SECRET, fingerprint_sha256: FP,
      credential_roles: ['inventory', 'provision'], allowed_pools: ['ou-lab'], allowed_storage: ['zfs', 'pbs'], allowed_networks: ['vmbr0/120'],
      defaults: {
        storage: 'zfs', network: { bridge: 'vmbr0', vlan: 120 }, ip: { mode: 'dhcp' }, dns: { domain: 'corp.example.com', servers: ['192.168.1.1', '1.1.1.1'] },
        backup_storage: 'pbs', approved_images: ['debian-12'],
        resource_policy: { max_cores: 16, max_memory_gb: 64, max_disk_gb: 500, cpu_overcommit: 2 },
        security: { approvals_required: { low: 1, high: 2 }, require_mfa_for_approvers: true, alert_channel: { kind: 'email', target: 'ops@example.com' } },
      },
    })
  })
  it('endpoint.update carries connection fields only; add omits defaults and scopes', () => {
    const m = filled()
    prefillFromEndpoint(m, { id: 'ep1', name: 'pve-main', base_url: 'https://pve.example.internal:8006', token_id: 'ics-inv@pve!inventory', fingerprint_sha256: FP })
    expect(buildUpdateParams(m)).toEqual({ endpoint_id: 'ep1', base_url: 'https://pve.example.internal:8006', token_id: 'ics-inv@pve!inventory', token_secret: SECRET, fingerprint_sha256: FP, credential_roles: ['inventory', 'provision'] })
    const add = buildAddParams(m)
    expect(add.defaults).toBeUndefined()
    expect(add.allowed_pools).toEqual([])
  })
})

describe('setup: nothing is submitted without the review step', () => {
  it('assertSubmittable demands review step, confirmation, readiness and a current probe', () => {
    const m = filled()
    expect(() => assertSubmittable(m, false)).toThrow(/Review step/)
    expect(() => assertSubmittable(m, true)).toThrow(/Confirm/)
    m.confirmed = true
    expect(() => assertSubmittable(m, true)).not.toThrow()
    m.host = 'changed.example'
    expect(() => assertSubmittable(m, true)).toThrow()
  })
  it('connection-only flow requires review, confirmation and a verified identity', () => {
    const m = filled(); m.endpointId = 'ep1'
    expect(() => assertConnectionSubmittable(m, false)).toThrow()
    expect(() => assertConnectionSubmittable(m, true)).toThrow(/Confirm/)
    m.confirmed = true
    expect(() => assertConnectionSubmittable(m, true)).not.toThrow()
    m.tlsCheck = null
    expect(() => assertConnectionSubmittable(m, true)).toThrow(/identity/)
  })
})
