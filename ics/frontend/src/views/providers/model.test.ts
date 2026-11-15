import { describe, expect, it } from 'vitest'
import {
  adminCreds, applyParams, buildPolicy, capacityHeadroom, changedOnly, connectionKey, credentialState, credentialsFor, daysUntil, describeStep, diffPolicies, discoverySummary, driftItems,
  fingerprintMismatch, identityKey, identityVerified, importParams, mergeSeries, mergeStorage, newModel, newSecrets, normDiscovery, packageParams, parseRanges, parseVmids, policyFromView,
  policyStatus, previewKeyOf, previewParams, probeRequest, ratioSeries, registerParams, reviewVerdict, riskOf, runView, splitEnforcement, stepRows, suggestName, suggestScope,
  blockedStorages, scopeChangeParams, scopePackageParams, scopePreviewParams, scopeTargetOf, scopeTargetValid, storageChoices, storageLocality,
  tlsRequest, tokenPathEnforcement, troubleshoot, validateConnect, validateCreds, validateScope, wipe, worstCredential,
  type CredentialMeta, type PlanPreviewOut, type PlanStep, type ProviderEndpoint, type WizardModel,
} from './model'
import { useWizard, type StepDef } from '../../wizards/kit'
import { reactive } from 'vue'

const FP = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99'
function model(over: Partial<WizardModel> = {}): WizardModel {
  const m = newModel()
  Object.assign(m, { host: 'pve1.example.com', name: 'main', fingerprint: FP, ...over })
  return m
}
const verified = (m: WizardModel) => { m.tls = { ok: true, presented_fingerprint_sha256: FP }; m.tlsKey = identityKey(m); return m }

describe('connection identity', () => {
  it('builds the TLS request without any credential and normalises the fingerprint', () => {
    const r = tlsRequest(model({ fingerprint: FP.toLowerCase().replace(/:/g, '') }))
    expect(r).toEqual({ stage: 'tls', base_url: 'https://pve1.example.com:8006', fingerprint_sha256: FP })
    expect(Object.keys(r)).not.toContain('token_secret')
  })
  it('is only verified for the exact connection that was checked', () => {
    const m = verified(model())
    expect(identityVerified(m)).toBe(true)
    m.host = 'pve2.example.com'
    expect(identityVerified(m)).toBe(false)
  })
  it('detects a fingerprint mismatch', () => {
    const m = model(); m.tls = { ok: false, presented_fingerprint_sha256: FP.replace('AA', 'AB') }
    expect(fingerprintMismatch(m)).toBe(true)
  })
  it('suggests a short id from the host', () => { expect(suggestName('PVE-01.Lab.example.com')).toBe('pve-01') })
})

describe('secrets never enter the wizard model', () => {
  it('copies the token secret into the probe body only and wipes the bag', () => {
    const m = verified(model({ tokenId: 'ics@pve!inv' })); const s = newSecrets(); s.tokenSecret = 'supersecretvalue1'
    const body = probeRequest(m, s)
    expect(body.token_secret).toBe('supersecretvalue1')
    expect(JSON.stringify(m)).not.toContain('supersecretvalue1')
    wipe(s)
    expect(s.tokenSecret).toBe('')
  })
  it('keeps temporary admin credentials out of the model and out of the policy', () => {
    const m = model({ method: 'admin', adminUser: 'root@pam' }); const s = newSecrets(); s.adminPassword = 'hunter2-hunter2'
    const p = previewParams(m, s)
    expect(JSON.stringify(m)).not.toContain('hunter2')
    expect(JSON.stringify(p.policy)).not.toContain('hunter2')
    expect(adminCreds(m, s)).toEqual({ admin_username: 'root@pam', admin_password: 'hunter2-hunter2' })
  })
})

describe('policy and scope validation', () => {
  it('nothing is allowed by default', () => {
    const m = model(); expect(validateScope(m).scope).toMatch(/at least one/)
  })
  it('deployment needs pool, storage and network', () => {
    const m = model(); m.scope.nodes = ['pve1']
    const e = validateScope(m)
    expect(Object.keys(e)).toEqual(expect.arrayContaining(['pools', 'storages', 'networks']))
    m.scope.pools = ['ou']; m.scope.storages = ['local']; m.scope.networks = ['vmbr0']
    expect(validateScope(m)).toEqual({})
  })
  it('monitoring needs only a visible scope', () => {
    const m = model({ preset: 'monitoring' }); m.scope.nodes = ['pve1']
    expect(validateScope(m)).toEqual({})
  })
  it('full administration needs an explicit acknowledgement and is high risk', () => {
    const m = model({ preset: 'full_admin' })
    expect(validateScope(m).ack).toBeTruthy()
    expect(buildPolicy(m).acknowledge_full_admin).toBe(false)
    m.acknowledgeFullAdmin = true
    expect(validateScope(m)).toEqual({})
    expect(buildPolicy(m).acknowledge_full_admin).toBe(true)
    expect(riskOf(m)).toBe('high')
  })
  it('capabilities only travel with the custom preset', () => {
    const m = model({ preset: 'deploy', capabilities: ['monitor'] }); expect(buildPolicy(m).capabilities).toEqual([])
    m.preset = 'custom'; expect(buildPolicy(m).capabilities).toEqual(['monitor'])
  })
  it('rejects invalid names, ranges and caps', () => {
    const m = model({ preset: 'monitoring' }); m.scope.nodes = ['n']; m.scope.pools = ['bad name!']; m.scope.vmid_ranges = [[50, 10]]; m.scope.max_cores = 0
    expect(Object.keys(validateScope(m))).toEqual(expect.arrayContaining(['names', 'vmid', 'max_cores']))
  })
  it('parses ids and ranges', () => {
    expect(parseVmids('9000, 100 99 abc 9000')).toEqual([100, 9000])
    expect(parseRanges('9000-9099, x, 200-300')).toEqual([[9000, 9099], [200, 300]])
  })
  it('requires the connection details and a passing probe on the token path', () => {
    const m = verified(model({ method: 'token', tokenId: 'ics@pve!inv' })); const s = newSecrets()
    expect(validateConnect(m, s).tokenSecret).toBeTruthy()
    s.tokenSecret = 'abcdefgh12345'
    expect(validateConnect(m, s).probe).toBeTruthy()
    m.probe = { ok: true, tls: { ok: true }, permissions: { inventory: { ok: true, missing: [] }, provision: { ok: false, missing: [] } } }; m.probedKey = connectionKey(m)
    expect(validateConnect(m, s)).toEqual({})
    m.probe.permissions!.inventory.ok = false
    expect(validateConnect(m, s).probe).toBeTruthy()
  })
  it('validates temporary credentials', () => {
    const m = model({ adminKind: 'password', adminUser: 'root' }); const s = newSecrets()
    expect(Object.keys(validateCreds(m, s))).toEqual(['adminUser', 'adminPassword'])
    m.adminKind = 'token'; expect(Object.keys(validateCreds(m, s))).toEqual(['adminTokenId', 'adminTokenSecret'])
  })
})

describe('action payload builders', () => {
  const policyModel = () => { const m = model({ method: 'admin', name: 'main' }); m.scope.pools = ['ou']; m.scope.storages = ['local']; m.scope.networks = ['vmbr0']; m.scope.nodes = ['pve1']; return m }
  it('online preview names the cluster and carries the admin login; offline preview carries the version instead', () => {
    const m = policyModel(); const s = newSecrets(); s.adminPassword = 'x'.repeat(10)
    const on = previewParams(m, s) as Record<string, unknown>
    expect(on).toMatchObject({ purpose: 'provision', name: 'main', base_url: 'https://pve1.example.com:8006', fingerprint_sha256: FP, admin_username: 'root@pam' })
    m.method = 'package'
    const off = previewParams(m, s) as Record<string, unknown>
    expect(off.pve_major).toBe(9); expect(off).not.toHaveProperty('admin_password'); expect(off).not.toHaveProperty('base_url')
  })
  it('an existing endpoint is addressed by id, never with connection details', () => {
    const m = policyModel(); m.endpointId = '11111111-1111-1111-1111-111111111111'
    expect(applyParams({ ...m, preview: { preview_id: 'p', plan_hash: 'h'.repeat(64) } as PlanPreviewOut }, newSecrets())).toMatchObject({ endpoint_id: m.endpointId, preview_id: 'p' })
    expect(Object.keys(packageParams(m))).toEqual(expect.arrayContaining(['policy', 'endpoint_id']))
  })
  it('apply is bound to the previewed plan hash', () => {
    const m = policyModel(); m.preview = { preview_id: 'pid', plan_hash: 'a'.repeat(64) } as PlanPreviewOut
    const p = applyParams(m, newSecrets())
    expect(p.plan_hash).toBe('a'.repeat(64)); expect(p.preview_id).toBe('pid')
    m.preview = null; expect(() => applyParams(m, newSecrets())).toThrow()
  })
  it('a stale preview is detected when the policy changes', () => {
    const m = policyModel(); const k = previewKeyOf(m); m.scope.storages.push('other')
    expect(previewKeyOf(m)).not.toBe(k)
  })
  it('omits unset caps from the API policy', () => {
    const m = policyModel(); const p = previewParams(m, newSecrets()) as { policy: { scope: Record<string, unknown> } }
    expect(p.policy.scope).not.toHaveProperty('max_cores')
  })
  it('register params use the allowlists and never include notes about secrets in the model', () => {
    const m = verified(model({ method: 'token', tokenId: 'ics@pve!inv', displayName: ' Main ' })); m.scope.pools = ['ou']; m.scope.storages = ['local']; m.scope.backup_storages = ['pbs']
    const s = newSecrets(); s.tokenSecret = ' abcdefgh12 '
    const r = registerParams(m, s)
    expect(r).toMatchObject({ name: 'main', type: 'proxmox', display_name: 'Main', token_secret: 'abcdefgh12', allowed_pools: ['ou'], allowed_storage: ['local', 'pbs'] })
    expect(r).not.toHaveProperty('provision_token_id')
  })
  it('import params use the package-defined token ids', () => {
    const m = model({ method: 'package', packageId: 'pkg' }); m.packageUser = 'ics-svc@pve'; m.packageTokens = { inventory: 'ics-inv', provision: 'ics-prov' }
    const s = newSecrets(); s.importInventory = 'aaaaaaaa1'; s.importProvision = 'bbbbbbbb2'
    expect(importParams(m, s)).toMatchObject({ package_id: 'pkg', inventory_token_id: 'ics-svc@pve!ics-inv', provision_token_id: 'ics-svc@pve!ics-prov', inventory_token_secret: 'aaaaaaaa1' })
  })
})

describe('wizard state machine with the real validators', () => {
  it('cannot leave Access with an empty scope and keeps state when going back', () => {
    const m = reactive(verified(model({ method: 'package' })))
    const steps: StepDef<WizardModel>[] = [{ id: 'c', title: 'C' }, { id: 'a', title: 'A', validate: (x) => validateScope(x) }, { id: 'r', title: 'R' }]
    const w = useWizard(steps, m)
    expect(w.next()).toBe(true)
    expect(w.next()).toBe(false); expect(w.m.errors.scope).toBeTruthy()
    m.scope.nodes.push('pve1'); m.scope.pools.push('ou'); m.scope.storages.push('local'); m.scope.networks.push('vmbr0')
    expect(w.next()).toBe(true); w.back(); expect(m.scope.pools).toEqual(['ou'])
  })
})

describe('discovery', () => {
  const d = normDiscovery({
    nodes: [{ name: 'a', status: 'online', managed: true, cpu_total: 8, mem_total: 8e9, mem_used: 2e9, cpu_pct: 10 }, { name: 'b', status: 'online', managed: false }],
    storage: [{ name: 'zfs', node: 'a', type: 'zfspool', content: ['images'], shared: false, total: 100, used: 40, active: true }, { name: 'zfs', node: 'b', type: 'zfspool', content: ['images'], shared: false, total: 100, used: 10, active: true },
      { name: 'nfs', node: 'a', content: ['backup'], shared: true, total: 500, used: 5 }, { name: 'nfs', node: 'b', content: ['backup'], shared: true, total: 500, used: 5 }],
    networks: [{ name: 'vmbr0', node: 'a', kind: 'bridge', vlan_aware: true }, { name: 'vmbr0', node: 'b', kind: 'bridge' }, { name: 'z', node: '', kind: 'sdn_zone' }],
    guests: [{ vmid: 100, kind: 'vm', node: 'a', status: 'running', pool: 'p1' }], templates: [{ vmid: 9000, kind: 'vm', node: 'a', pool: null }], warnings: ['x'],
  })!
  it('merges per-node storage: local adds up, shared counts once', () => {
    const s = mergeStorage(d.storage)
    expect(s.find((x) => x.name === 'zfs')).toMatchObject({ total: 200, used: 50, nodes: ['a', 'b'] })
    expect(s.find((x) => x.name === 'nfs')).toMatchObject({ total: 500, used: 5 })
  })
  it('summarises without inventing values and does not hide unmanaged nodes', () => {
    expect(discoverySummary(d)).toEqual(expect.arrayContaining([{ label: 'Nodes', value: 2 }, { label: 'Storage', value: 2 }, { label: 'Networks', value: 1 }, { label: 'Templates', value: 1 }, { label: 'Pools', value: 1 }]))
    expect(d.nodes[1]!.managed).toBe(false)
  })
  it('suggests a conservative scope and never selects unmanaged nodes', () => {
    const s = suggestScope(d, 'deploy')
    expect(s).toMatchObject({ nodes: ['a'], storages: ['zfs'], networks: ['vmbr0'], pools: ['office-unbound'] })
    expect(suggestScope(null, 'deploy').pools).toEqual([])
  })
})

describe('plan rendering', () => {
  const steps: PlanStep[] = [
    { kind: 'role', op: 'create', target: 'OfficeUnboundDeploy', detail: { privileges: ['VM.Allocate', 'VM.Clone'] }, reason: '', risk: 'normal' },
    { kind: 'acl', op: 'create', target: '/pool/ou|ics-svc@pve|OfficeUnboundDeploy', detail: {}, reason: 'clone into the pool', risk: 'normal' },
    { kind: 'user', op: 'noop', target: 'ics-svc@pve', detail: {}, reason: '', risk: 'normal' },
    { kind: 'role', op: 'conflict', target: 'OfficeUnboundMonitor', detail: {}, reason: 'exists with other privileges', risk: 'high' },
  ]
  it('lists exactly what changes and hides what is already in place', () => {
    const rows = stepRows(steps)
    expect(rows.map((r) => r.opLabel)).toEqual(['Create', 'Create', 'Conflict'])
    expect(rows[1]!.target).toBe('/pool/ou'); expect(rows[1]!.what).toBe('On /pool/ou: ics-svc@pve gets role OfficeUnboundDeploy')
    expect(stepRows(steps, true)).toHaveLength(4)
    expect(describeStep(steps[0]!)).toContain('VM.Clone')
  })
  it('separates what Proxmox enforces from what only Office Unbound enforces', () => {
    const e = splitEnforcement([{ control: 'a', enforced_by: 'proxmox', detail: '' }, { control: 'b', enforced_by: 'ics', detail: '' }, { control: 'c', enforced_by: 'not_enforced', detail: '' }, { control: 'd', enforced_by: 'both', detail: '' }])
    expect([e.proxmox.length, e.ics.length, e.notEnforced.length]).toEqual([2, 1, 1])
    const m = model({ method: 'token' }); m.scope.nodes = ['a']; m.scope.max_cores = 4
    const t = tokenPathEnforcement(m)
    expect(t.find((x) => x.control.startsWith('Node allowlist'))!.enforced_by).toBe('ics')
    expect(t.find((x) => x.control.startsWith('VMID'))!.enforced_by).toBe('not_enforced')
  })
  it('blocks an unapproved elevated privilege', () => {
    const p = { plan: { blocked: [], conflicts: ['c'], warnings: [], elevated: [{ privilege: 'Sys.Modify', path: '/', why: 'cicustom', approved: false }] } } as unknown as PlanPreviewOut
    const v = reviewVerdict(p)
    expect(v.ok).toBe(false); expect(v.blockers[0]).toContain('Sys.Modify'); expect(v.warnings).toEqual(['c'])
    expect(reviewVerdict(null).ok).toBe(false)
  })
})

describe('before and after diff', () => {
  it('shows only what changed', () => {
    const a = buildPolicy(Object.assign(model(), { preset: 'deploy' as const })); a.scope.storages = ['local']
    const b = JSON.parse(JSON.stringify(a)); b.scope.storages = ['local', 'zfs']; b.scope.max_cores = 8
    const rows = changedOnly(diffPolicies(a, b))
    expect(rows.map((r) => r.field)).toEqual(['Storage', 'CPU cap'])
    expect(rows[0]).toMatchObject({ before: 'local', after: 'local, zfs' })
  })
  it('rebuilds an editable policy from the permissions view, or nothing for manual tokens', () => {
    expect(policyFromView({ endpoint_id: 'x', managed_by_provisioning: false })).toBeNull()
    const p = policyFromView({ endpoint_id: 'x', managed_by_provisioning: true, preset: 'custom', service_user: 'ics-svc@pve', scope: { pools: ['ou'] }, roles: { monitor: { name: 'M', privileges: [] }, storage: { name: 'S', privileges: [] } } })!
    expect(p.capabilities).toEqual(['monitor', 'storage']); expect(p.service_user).toBe('ics-svc'); expect(p.scope.pools).toEqual(['ou']); expect(p.scope.guest_types).toEqual(['qemu'])
  })
})

describe('drift and status', () => {
  it('turns a drift report into corrections', () => {
    const items = driftItems({ ok: false, kinds: { provision: { ok: false, missing: [{ path: '/pool/ou', privileges: ['VM.Clone'] }], unexpected: [{ path: '/', privileges: ['Sys.Audit'] }], forbidden: [], suggestion: [] } } })
    expect(items.map((i) => i.type)).toEqual(['missing', 'unexpected'])
    expect(items[0]!.suggestion).toBe('Restore VM.Clone on /pool/ou')
    expect(driftItems(null)).toEqual([])
  })
  it('explains policy status in plain words', () => {
    expect(policyStatus({ endpoint_id: 'x', managed_by_provisioning: true, status: 'token_failed' }).tone).toBe('bad')
    expect(policyStatus({ endpoint_id: 'x', managed_by_provisioning: false }).text).toBe('Manual token')
  })
})

describe('plan progress', () => {
  it('maps plan and job state to a phase and progress', () => {
    expect(runView({ id: 'p', status: 'pending_approval', approvals_required: 2, approval_count: 1 }, null)).toMatchObject({ phase: 'awaiting_approval', done: false })
    expect(runView({ id: 'p', status: 'rejected' }, null).phase).toBe('rejected')
    expect(runView(null, { id: 'j', plan_id: 'p', status: 'running', result: null, error: null, created_at: '' }).progress).toBeGreaterThan(50)
    const f = runView(null, { id: 'j', plan_id: 'p', status: 'failed', result: null, error: { message: 'HTTP 401 authentication failure' }, created_at: '' })
    expect(f).toMatchObject({ phase: 'failed', ok: false }); expect(f.detail).toContain('401')
  })
  it('gives troubleshooting for common failures', () => {
    expect(troubleshoot('HTTP 401 authentication failure')[0]).toMatch(/rejected/)
    expect(troubleshoot('plan hash differs: the cluster changed since')[0]).toMatch(/preview again/)
    expect(troubleshoot('???')).toHaveLength(1)
  })
})

describe('credentials', () => {
  const now = Date.parse('2026-11-15T00:00:00Z')
  const c = (o: Partial<CredentialMeta>): CredentialMeta => ({ id: '1', provider: 'proxmox', customer_id: 'c', label: 'l', credential_type: 'api_token', purpose: 'inventory', identity: 'ics@pve!inv', status: 'active', created_at: '', last_validated_at: null, last_used_at: null, expires_at: null, revoked_at: null, ...o })
  it('computes expiry and state', () => {
    expect(daysUntil('2026-11-25T00:00:00Z', now)).toBe(10)
    expect(credentialState(c({ expires_at: '2026-11-25T00:00:00Z' }), now)).toMatchObject({ tone: 'warn', text: 'Expires in 10 days' })
    expect(credentialState(c({ status: 'expired' }), now).tone).toBe('bad')
    expect(credentialState(c({ expires_at: '2027-06-01T00:00:00Z' }), now).tone).toBe('ok')
    expect(credentialState(c({ status: 'revoked' }), now).text).toBe('Revoked')
  })
  it('matches credentials to a cluster by token identity and reports the worst state', () => {
    const ep = { credentials: { inventory: { present: true, token_id: 'ics@pve!inv' }, provision: { present: false, token_id: null } } } as ProviderEndpoint
    const list = credentialsFor(ep, [c({ id: 'a' }), c({ id: 'b', identity: 'other@pve!x' }), c({ id: 'r', status: 'retired' })])
    expect(list.map((x) => x.id)).toEqual(['a'])
    expect(worstCredential([c({}), c({ status: 'invalid' })]).tone).toBe('bad')
    expect(worstCredential([]).text).toMatch(/No credential/)
  })
})

describe('metrics and capacity', () => {
  it('merges series on shared timestamps without interpolating', () => {
    const a = [{ t: 1, v: 10 }, { t: 2, v: 20 }], b = [{ t: 2, v: 40 }, { t: 3, v: 50 }]
    expect(mergeSeries([a, b], 'mean')).toEqual([{ t: 1, v: 10 }, { t: 2, v: 30 }, { t: 3, v: 50 }])
    expect(mergeSeries([a, b], 'sum')[1]!.v).toBe(60)
    expect(ratioSeries([{ t: 1, v: 50 }, { t: 2, v: 10 }], [{ t: 1, v: 100 }])).toEqual([{ t: 1, v: 50 }])
  })
  it('counts headroom only on authorised storage and online managed nodes', () => {
    const nodes = [{ id: 'n1', name: 'a', status: 'online', managed: true, cpu_total: 8, mem_total: 100, mem_used: 40, cpu_pct: 50, disk_total: null, disk_used: null }, { id: 'n2', name: 'b', status: 'online', managed: false, cpu_total: null, mem_total: null, mem_used: null, cpu_pct: null, disk_total: null, disk_used: null }]
    const storage = [{ id: 's1', name: 'zfs', node: 'a', type: null, content: [], shared: false, total: 1000, used: 400, active: true }, { id: 's2', name: 'other', node: 'a', type: null, content: [], shared: false, total: 9999, used: 0, active: true }]
    const cap = capacityHeadroom(nodes, storage, { allowed_storage: ['zfs'], allowed_pools: [], allowed_networks: [], allowed_templates: [], allow_cicustom: false, protected_vmids: [] }, [
      { id: 'g', vmid: 100, kind: 'vm', node: 'a', name: null, status: 'running', pool: null, ou_managed: true, cpus: 1, mem_max: 1 }])
    expect(cap).toMatchObject({ memFree: 60, diskFree: 600, nodesCounted: 1, running: 1, authorisedStorage: 1 })
    expect(cap.cpuFree).toBeCloseTo(4)
  })
})


describe('scope modes (one node only / whole cluster)', () => {
  const disc = () => normDiscovery({
    nodes: [{ name: 'pve05', status: 'online', managed: true }, { name: 'pve06', status: 'online', managed: true }],
    storage: [
      { name: 'PVE06-Storage', node: 'pve06', type: 'lvmthin', content: ['images', 'rootdir'], shared: false, total: 100, used: 10, active: true },
      { name: 'ha-zfs', node: 'pve05', type: 'zfspool', content: ['images', 'rootdir'], shared: true, total: 500, used: 10, active: true },
      { name: 'ha-zfs', node: 'pve06', type: 'zfspool', content: ['images', 'rootdir'], shared: true, total: 500, used: 10, active: true },
      { name: 'PBS1', node: 'pve06', type: 'pbs', content: ['backup'], shared: true, total: 900, used: 1, active: true },
    ],
  })!
  it('defaults to one node and sends the mode, never a node list for the whole cluster', () => {
    const m = model(); m.scope.nodes = ['pve06']
    expect(buildPolicy(m).scope_mode).toBe('single_node')
    m.scopeMode = 'whole_cluster'
    const p = buildPolicy(m)
    expect(p.scope_mode).toBe('whole_cluster'); expect(p.scope.nodes).toEqual([]); expect(p.scope_risk_overrides).toEqual([])
  })
  it('full administration is always a whole-cluster scope', () => {
    const m = model({ preset: 'full_admin', acknowledgeFullAdmin: true }); m.scope.nodes = ['pve06']
    expect(buildPolicy(m).scope_mode).toBe('whole_cluster')
  })
  it('one node: migration and cloud-init snippets are not sent without the explicit exception', () => {
    const m = model({ allowMigrate: true, allowCicustom: true }); m.scope.nodes = ['pve06']
    let p = buildPolicy(m); expect(p.allow_migrate).toBe(false); expect(p.allow_cicustom).toBe(false)
    m.riskOverrides = ['migrate']; p = buildPolicy(m); expect(p.allow_migrate).toBe(true); expect(p.scope_risk_overrides).toEqual(['migrate'])
  })
  it('only node-local storage is selectable in one-node mode; shared and multi-node storage is refused with a reason', () => {
    const d = disc()
    const rows = storageChoices(d, 'single_node', ['pve06'], [])
    const by = Object.fromEntries(rows.map((r) => [r.name, r]))
    expect(by['PVE06-Storage']!.selectable).toBe(true)
    expect(by['ha-zfs']!.selectable).toBe(false); expect(by['ha-zfs']!.reason).toMatch(/Shared/)
    expect(by['PBS1']!.selectable).toBe(true)          // backup-only storage cannot hold VM disks
    expect(storageChoices(d, 'whole_cluster', ['pve06'], []).every((r) => r.selectable)).toBe(true)
    expect(storageLocality({ shared: false, nodes: ['pve05', 'pve06'] }, ['pve06']).reason).toMatch(/pve05/)
  })
  it('a shared storage only becomes selectable with the explicit high-risk exception', () => {
    const d = disc()
    expect(storageChoices(d, 'single_node', ['pve06'], ['shared_storage:ha-zfs']).find((r) => r.name === 'ha-zfs')!.selectable).toBe(true)
    const m = model(); m.discovery = d; m.scope.nodes = ['pve06']; m.scope.storages = ['ha-zfs']
    expect(blockedStorages(m).map((b) => b.name)).toEqual(['ha-zfs']); expect(validateScope(m).storages).toMatch(/other nodes/)
    m.riskOverrides = ['shared_storage:ha-zfs']; expect(blockedStorages(m)).toEqual([])
  })
  it('suggests exactly one node and only storage local to it', () => {
    const s = suggestScope(disc(), 'deploy', 'single_node')
    expect(s.nodes).toEqual(['pve05']); expect(s.storages).toEqual([])        // pve05 has no node-local storage: nothing unsafe is pre-selected
    expect(suggestScope(disc(), 'deploy', 'whole_cluster').nodes).toEqual(['pve05', 'pve06'])
  })
  it('one node needs a node', () => { const m = model(); expect(validateScope(m).nodes).toMatch(/Choose the node/) })
  it('builds scope-change requests: preview, apply (Mode A), package and confirm (Mode B)', () => {
    const t = scopeTargetOf({ endpoint_id: 'e', managed_by_provisioning: true }, 'single_node', ['pve06'], ['PVE06-Storage'], [], false)
    expect(t).toEqual({ mode: 'single_node', nodes: ['pve06'], storages: ['PVE06-Storage'], risk_overrides: [], detach_orphans: false })
    expect(scopeTargetValid({ ...t, nodes: [] })).toMatch(/at least one/)
    expect(scopeTargetOf({ endpoint_id: 'e', managed_by_provisioning: true }, 'whole_cluster', ['pve06'], [], ['migrate'], false).nodes).toEqual([])
    expect(scopePreviewParams('e', t, { admin_username: 'root@pam', admin_password: 'x' })).toMatchObject({ purpose: 'scope_change', endpoint_id: 'e', scope_target: t })
    const pv = { preview_id: 'p', plan_hash: 'h', risk: 'high', direction: 'widen', blocked: [], scope: { detach: [7] } } as never
    expect(scopeChangeParams('e', pv, 'mode_a', { admin_token_id: 'a@pam!t', admin_token_secret: 's' })).toMatchObject({ direction: 'widen', detach: true, execution: 'mode_a', admin_token_id: 'a@pam!t' })
    const b = scopeChangeParams('e', pv, 'confirm_package', { admin_token_id: 'a@pam!t', admin_token_secret: 's' }, 'pkg')
    expect(b).toMatchObject({ execution: 'confirm_package', package_id: 'pkg' }); expect(JSON.stringify(b)).not.toContain('admin_token')
    expect(scopePackageParams('e', pv)).toEqual({ endpoint_id: 'e', preview_id: 'p', plan_hash: 'h', direction: 'widen', detach: true })
  })
  it('shows an injected cluster-wide grant as out of scope in the drift list', () => {
    const items = driftItems({ ok: false, kinds: { inventory: { ok: false, missing: [], unexpected: [], forbidden: [], suggestion: [], scope_reach: [{ path: '/nodes', privileges: ['Sys.Audit'], reaches: 'every node in the cluster', enforced_by: 'proxmox' }] } } })
    expect(items).toHaveLength(1); expect(items[0]).toMatchObject({ type: 'exposed', path: '/nodes' }); expect(items[0]!.text).toMatch(/single-node/)
  })
})
