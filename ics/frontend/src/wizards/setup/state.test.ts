import { describe, expect, it } from 'vitest'
import type { ProbeResult } from '../api'
import {
  assertConnectionSubmittable, assertSubmittable, buildAddParams, buildRegisterParams, buildUpdateParams, connectionKey, fixCommands, identityKey, identityVerified,
  autoDefaults, isReady, newSetupModel, prefillFromEndpoint, probeRequest, readiness, tlsRequest, validateConnection, validateConnectionFields, validateDefaults,
} from './state'
import type { SetupModel } from './state'

const FP = Array.from({ length: 32 }, (_, i) => (i * 7 + 3).toString(16).padStart(2, '0')).join(':').toUpperCase()
const SECRET = 'abcdEFGH_12345678'

function probe(over: Partial<ProbeResult['permissions']> = {}): ProbeResult {
  return {
    ok: true, version: '9.0.3', tls: { ok: true, verified_by: 'fingerprint', presented_fingerprint_sha256: FP },
    permissions: { inventory: { ok: true, missing: [] }, provision: { ok: true, missing: [] }, ...over },
    discovery: { nodes: [{ name: 'n1', status: 'online', managed: true, cpu_total: 8, cpu_used: 1, mem_total_gb: 64, mem_used_gb: 8 }], storage: [{ id: 'zfs', node: null, type: 'zfspool', content: ['images'], total_gb: 100, used_gb: 10 }], networks: [{ name: 'vmbr0', node: null, kind: 'bridge' }], guests: [], pools: ['ou-lab'] },
  }
}
function filled(p: ProbeResult = probe()): SetupModel {
  const m = newSetupModel()
  Object.assign(m, { host: 'pve.example.internal', tokenId: 'ics-inv@pve!inventory', tokenSecret: SECRET, fingerprint: FP })
  m.tlsCheck = p.tls; m.tlsKey = identityKey(m)
  m.probe = p; m.probedKey = connectionKey(m)
  Object.assign(m.defaults, { pool: 'ou-lab', nodes: ['n1'], storage: 'zfs', bridge: 'vmbr0', backupStorage: 'pbs', vlan: '120' })
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
    m.tokenId = 'officeunbound@pam!ics'; m.provTokenId = 'officeunbound@pam!prov'; m.provTokenSecret = SECRET; m.tlsKey = identityKey(m); m.probedKey = connectionKey(m)
    expect(fixCommands(m).provision).toEqual(["pveum acl modify /sdn/zones/localnetwork/vmbr0 --tokens 'officeunbound@pam!ics' --roles PVESDNUser"])
    const checks = readiness(m)
    expect(checks.find((c) => c.id === 'sdn')).toMatchObject({ level: 'bad', blocks: 'provisioning' })
    expect(checks.find((c) => c.id === 'extra')?.text).toContain('VM.Console')
    expect(isReady(m)).toBe(true)
    expect(buildRegisterParams(m).provision_token_id).toBe('officeunbound@pam!prov')
    expect(buildRegisterParams(m).allowed_nodes).toEqual(['n1'])
  })
  it('fix commands mirror docs/status/proxmox-setup.md when provision is wholly missing', () => {
    const m = filled(probe({ provision: { ok: false, missing: [{ path: '/pool/ou-lab', privilege: 'VM.Allocate' }] } }))
    m.provTokenId = 'ics-lab@pve!lab'; m.provTokenSecret = SECRET
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

describe('setup: defaults validation and the express path', () => {
  it('a read-only connection needs no scope; a provisioning one needs pool, nodes, storage and bridge', () => {
    const m = filled()
    expect(validateDefaults(m)).toEqual({})                // no provisioning token: nothing else to choose
    m.provTokenId = 'ics-lab@pve!lab'; m.provTokenSecret = SECRET
    Object.assign(m.defaults, { pool: '', nodes: [], storage: '', bridge: '', vlan: '5000', images: [] })
    expect(Object.keys(validateDefaults(m)).sort()).toEqual(['bridge', 'images', 'nodes', 'pool', 'storage', 'vlan'])
  })
  it('the provisioning token must differ from the read-only one and both fields go together', () => {
    const m = filled(); m.provTokenId = 'ics-inv@pve!inventory'
    expect(Object.keys(validateConnectionFields(m))).toEqual(expect.arrayContaining(['provTokenId', 'provTokenSecret']))
  })
  it('autoDefaults fills what discovery makes unambiguous and never overwrites a choice', () => {
    const m = filled(); Object.assign(m.defaults, { pool: '', nodes: [], storage: '', bridge: '', backupStorage: '' })
    autoDefaults(m)
    expect(m.defaults).toMatchObject({ pool: 'ou-lab', nodes: ['n1'], storage: 'zfs', bridge: 'vmbr0' })
    m.defaults.storage = 'mine'; autoDefaults(m)
    expect(m.defaults.storage).toBe('mine')
  })
  it('two online nodes are never guessed', () => {
    const p = probe(); p.discovery!.nodes.push({ name: 'n2', status: 'online', managed: true, cpu_total: 8, cpu_used: 1, mem_total_gb: 64, mem_used_gb: 8 })
    const m = filled(p); m.defaults.nodes = []
    autoDefaults(m)
    expect(m.defaults.nodes).toEqual([])
  })
})

describe('setup: exact endpoint.register payload (backend EndpointRegister)', () => {
  it('matches the contract JSON: two credentials, scope lists, saved defaults', () => {
    const m = filled()
    m.provTokenId = 'ics-lab@pve!lab'; m.provTokenSecret = SECRET + 'x'
    Object.assign(m.defaults, { searchDomain: 'corp.example.com', dnsServers: '192.168.1.1, 1.1.1.1' })
    expect(JSON.parse(JSON.stringify(buildRegisterParams(m)))).toEqual({
      name: 'pve-main', type: 'proxmox', base_url: 'https://pve.example.internal:8006', token_id: 'ics-inv@pve!inventory', token_secret: SECRET, fingerprint_sha256: FP,
      provision_token_id: 'ics-lab@pve!lab', provision_token_secret: SECRET + 'x',
      allowed_pools: ['ou-lab'], allowed_nodes: ['n1'], allowed_storage: ['zfs', 'pbs'], allowed_networks: ['vmbr0/120'],
      defaults: { storage: 'zfs', bridge: 'vmbr0', vlan: 120, ip_mode: 'dhcp', dns_servers: ['192.168.1.1', '1.1.1.1'], search_domain: 'corp.example.com',
                  backup_storage: 'pbs', approved_os_images: ['debian-12'], resource_policy: 'balanced' },
    })
  })
  it('without a provisioning token the scope lists are empty (read-only), and no credential_roles field exists', () => {
    const p = JSON.parse(JSON.stringify(buildRegisterParams(filled())))
    expect(p).not.toHaveProperty('credential_roles'); expect(p).not.toHaveProperty('provision_token_id')
    expect(p.allowed_pools).toEqual([]); expect(p.allowed_nodes).toEqual([])
  })
  it('endpoint.update carries connection fields only; add omits defaults and scopes', () => {
    const m = filled()
    prefillFromEndpoint(m, { id: 'ep1', name: 'pve-main', base_url: 'https://pve.example.internal:8006', credentials: { inventory: { token_id: 'ics-inv@pve!inventory' } }, trust: 'fingerprint', fingerprint_sha256: FP })
    expect(buildUpdateParams(m)).toEqual({ endpoint_id: 'ep1', base_url: 'https://pve.example.internal:8006', token_id: 'ics-inv@pve!inventory', token_secret: SECRET, fingerprint_sha256: FP })
    const add = buildAddParams(m)
    expect(add.defaults).toBeUndefined()
    expect(add.allowed_pools).toEqual([]); expect(add.allowed_nodes).toEqual([])
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
