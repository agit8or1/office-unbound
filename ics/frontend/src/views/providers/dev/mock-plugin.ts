// DEV-ONLY design-review mock for the provider screens ("design-review-mock"). Runs inside the Vite dev server (Node) and is never imported by
// the app, so it is absent from `vite build` output (verified by grepping dist). Every value below is invented to exercise the UI. It is NOT infrastructure data.
import type { Plugin } from 'vite'
import type { IncomingMessage, ServerResponse } from 'node:http'

const FP = '3A:91:C4:0E:7B:55:D2:18:6F:A0:9C:41:E7:2D:B3:68:F5:0A:17:CC:84:3E:9B:D1:62:4F:A8:05:7D:E9:30:BB'
const EP = '7c1d3b52-0f64-4e0a-9a1d-3b52a1c0e001'
const now = Date.now()
const iso = (msAgo: number) => new Date(now - msAgo).toISOString()
const GB = 1024 ** 3

type Scenario = 'empty' | 'full' | 'manual'
let scenario: Scenario = 'full'
const polls: Record<string, number> = {}
const plans: Record<string, { action: string; params: Record<string, any>; risk: string; created: number }> = {} // eslint-disable-line @typescript-eslint/no-explicit-any

const node = (i: number, name: string, status: string, managed: boolean) => ({
  id: `00000000-0000-4000-8000-00000000010${i}`, endpoint_id: EP, name, status, managed, cpu_total: managed ? 32 : null, mem_total: managed ? 256 * GB : null, mem_used: managed ? [88, 131, 0][i]! * GB : null,
  cpu_pct: managed ? [18, 37, 0][i]! : null, disk_total: managed ? 900 * GB : null, disk_used: managed ? 300 * GB : null, ip: `10.20.0.1${i}`, uptime: 1e6, health: { status: managed ? (status === 'online' ? 'ok' : 'critical') : 'unmanaged', reason: managed ? null : 'token has no Sys.Audit on this node' }, observed_at: iso(60e3),
})
const nodes = [node(0, 'pve-a', 'online', true), node(1, 'pve-b', 'online', true), node(2, 'pve-c', 'online', false)]
const stor = (i: number, name: string, nodeName: string, type: string, content: string[], total: number, used: number, shared = false) => ({
  id: `00000000-0000-4000-8000-00000000020${i}`, endpoint_id: EP, name, node: nodeName, type, content, shared, enabled: true, active: true, total: total * GB, used: used * GB, thin: false, provisioned_bytes: null, observed_at: iso(60e3), health: { status: 'ok', reason: null },
})
const storage = [stor(1, 'tank-zfs', 'pve-a', 'zfspool', ['images', 'rootdir'], 3800, 1450), stor(2, 'tank-zfs', 'pve-b', 'zfspool', ['images', 'rootdir'], 3800, 3500), stor(3, 'backup-nfs', 'pve-a', 'nfs', ['backup'], 12000, 4100, true), stor(4, 'backup-nfs', 'pve-b', 'nfs', ['backup'], 12000, 4100, true), stor(5, 'local', 'pve-a', 'dir', ['iso', 'vztmpl'], 200, 60)]
const networks = [
  { id: 'n1', endpoint_id: EP, name: 'vmbr0', node: 'pve-a', kind: 'bridge', vlan_aware: true, tag: null, zone: null }, { id: 'n2', endpoint_id: EP, name: 'vmbr0', node: 'pve-b', kind: 'bridge', vlan_aware: true, tag: null, zone: null },
  { id: 'n3', endpoint_id: EP, name: 'vmbr1', node: 'pve-a', kind: 'bridge', vlan_aware: false, tag: null, zone: null },
]
const mkGuest = (vmid: number, name: string, kind: 'vm' | 'lxc', n: string, status: string, pool: string | null, managed = false) => ({ id: `00000000-0000-4000-8000-0000000003${vmid}`, endpoint_id: EP, vmid, kind, node: n, name, status, pool, tags: [], ou_managed: managed, cpus: 4, mem_max: 8 * GB })
const guests = [mkGuest(100, 'dns-01', 'lxc', 'pve-a', 'running', null), mkGuest(101, 'unifi', 'vm', 'pve-a', 'running', null), mkGuest(105, 'files-gw', 'vm', 'pve-b', 'running', 'ou-demo', true), mkGuest(106, 'mail-core', 'vm', 'pve-b', 'running', 'ou-demo', true), mkGuest(118, 'build-old', 'vm', 'pve-b', 'stopped', null), mkGuest(120, 'monitor', 'lxc', 'pve-a', 'running', null)]
const templates = [{ id: 't1', endpoint_id: EP, vmid: 9000, kind: 'vm', node: 'pve-a', name: 'debian-12-template', pool: 'ou-demo' }, { id: 't2', endpoint_id: EP, vmid: 9001, kind: 'vm', node: 'pve-a', name: 'ubuntu-2404-template', pool: null }]

const endpoint = (manual: boolean) => ({
  id: EP, name: 'demo-lab', display_name: 'Demo lab cluster', type: 'proxmox', base_url: 'https://pve-a.demo.example:8006', trust: 'fingerprint', fingerprint_sha256: FP,
  credentials: { inventory: { present: true, token_id: 'ics-svc@pve!ics-inv' }, provision: { present: !manual, token_id: manual ? null : 'ics-svc@pve!ics-prov' } },
  scope: { allowed_pools: ['ou-demo'], allowed_storage: ['tank-zfs'], allowed_networks: ['vmbr0'], allowed_templates: [9000], allow_cicustom: false, protected_vmids: [126] },
  defaults: {}, enabled: true, detached_at: null, created_at: iso(9 * 864e5), health: { status: 'warning', reason: 'partial data (see warnings)' },
  last_probe: { at: iso(120e3), ok: true, version: '9.0.3', cluster_name: 'demo-lab', verbs: { discover: true, metrics: true, clone_vm: true, configure_vm: true, power: true, destroy_vm: true, migrate: false } },
  last_discovery: { at: iso(70e3), ok: true, error: null, warnings: ['pve-c: token has no Sys.Audit, capacity unknown'], counts: { nodes: 3, storage: 5, guests: 6, templates: 2, networks: 3 } }, last_metrics: { at: iso(60e3), error: null },
})
const roleFor = (n: string, privileges: string[]) => ({ name: n, privileges })
const permissions = {
  endpoint_id: EP, managed_by_provisioning: true, mode: 'A', status: 'drift', preset: 'deploy', service_user: 'ics-svc@pve', plan_hash: 'f'.repeat(64),
  tokens: { inventory: { id: 'ics-svc@pve!ics-inv', gen: 1 }, provision: { id: 'ics-svc@pve!ics-prov', gen: 2 } },
  roles: { monitor: roleFor('OfficeUnboundMonitor', ['Datastore.Audit', 'Pool.Audit', 'Sys.Audit', 'VM.Audit']), deploy: roleFor('OfficeUnboundDeploy', ['Datastore.AllocateSpace', 'VM.Allocate', 'VM.Clone', 'VM.Config.CPU', 'VM.Config.Disk', 'VM.Config.Memory', 'VM.Config.Network', 'VM.PowerMgmt', 'VM.Snapshot']) },
  expected: { inventory: { '/nodes/pve-a': ['Sys.Audit'], '/nodes/pve-b': ['Sys.Audit'], '/pool/ou-demo': ['VM.Audit', 'Pool.Audit'], '/storage/tank-zfs': ['Datastore.Audit'] },
    provision: { '/pool/ou-demo': ['VM.Allocate', 'VM.Clone', 'VM.Config.CPU', 'VM.Config.Disk', 'VM.Config.Memory', 'VM.Config.Network', 'VM.PowerMgmt', 'VM.Snapshot'], '/storage/tank-zfs': ['Datastore.AllocateSpace'], '/sdn/zones/localnetwork/vmbr0': ['SDN.Use'], '/vms/9000': ['VM.Clone', 'VM.Audit'] } },
  last_verification: { ok: true }, last_verified_at: iso(26 * 36e5),
  last_drift: { ok: false, checked_at: iso(2 * 36e5), kinds: { inventory: { ok: true, missing: [], unexpected: [], forbidden: [], suggestion: [] },
    provision: { ok: false, missing: [{ path: '/sdn/zones/localnetwork/vmbr0', privileges: ['SDN.Use'] }], unexpected: [{ path: '/storage/backup-nfs', privileges: ['Datastore.AllocateSpace'] }], forbidden: [], suggestion: [] } } },
  last_drift_at: iso(2 * 36e5),
  enforcement: [
    { control: 'Pool membership (which guests may be created/changed)', enforced_by: 'proxmox', detail: 'ACL on /pool/<pool>; Proxmox refuses VM.* operations on guests outside the pools.' },
    { control: 'Storage allowlist', enforced_by: 'proxmox', detail: 'Datastore.AllocateSpace only on authorised storage.' },
    { control: 'Bridge / SDN vnet allowlist', enforced_by: 'proxmox', detail: 'SDN.Use only on the authorised bridges.' },
    { control: 'Ownership tags and protected guests', enforced_by: 'ics', detail: 'Every mutation re-checks the ou-managed tag; the ICS VM is never touched.' },
    { control: 'Node allowlist (pve-a, pve-b)', enforced_by: 'ics', detail: 'Application-enforced. Proxmox pool ACLs do not restrict which node a pooled guest lands on.' },
    { control: 'VMID ranges, CPU/RAM/disk caps', enforced_by: 'not_enforced', detail: 'Cannot be expressed in Proxmox. Policy guard implemented; broker wiring pending.' },
  ],
  scope: { nodes: ['pve-a', 'pve-b'], pools: ['ou-demo'], storages: ['tank-zfs'], networks: ['vmbr0'], template_vmids: [9000], vmid_ranges: [[9000, 9199]], guest_types: ['qemu'], backup_storages: [], protected_vmids: [126], max_cores: 8, max_memory_mb: 16384, max_disk_gb: 200 },
  never_granted: ['Permissions.Modify', 'User.Modify', 'Group.Allocate', 'Realm.AllocateUser', 'Sys.Modify'], managed_objects: { user: 'ics-svc@pve', roles: ['OfficeUnboundMonitor', 'OfficeUnboundDeploy'], tokens: [], pools: ['ou-demo'] },
}
const credentials = [
  { id: 'c1', provider: 'proxmox', customer_id: 'cu1', label: 'demo-lab inventory', credential_type: 'api_token', purpose: 'inventory', identity: 'ics-svc@pve!ics-inv', status: 'active', created_at: iso(9 * 864e5), last_validated_at: iso(36e5), last_used_at: iso(60e3), expires_at: new Date(now + 200 * 864e5).toISOString(), revoked_at: null },
  { id: 'c2', provider: 'proxmox', customer_id: 'cu1', label: 'demo-lab provisioning', credential_type: 'api_token', purpose: 'provision', identity: 'ics-svc@pve!ics-prov', status: 'expiring', created_at: iso(120 * 864e5), last_validated_at: iso(5 * 36e5), last_used_at: iso(3 * 864e5), expires_at: new Date(now + 9 * 864e5).toISOString(), revoked_at: null },
]
const customers = [
  { id: 'cu1', name: 'Demo Office GmbH', msp_owned: false, provisioning_mode: 'customer_approval', extra_approvals: { delete_guest: 1, expand_permissions: 1 }, contact_name: 'A. Example', contact_email: 'it@demo-office.example', created_at: iso(30 * 864e5), disabled_at: null },
  { id: 'cu0', name: 'MSP (internal)', msp_owned: true, provisioning_mode: 'auto', extra_approvals: {}, contact_name: null, contact_email: null, created_at: iso(90 * 864e5), disabled_at: null },
  { id: 'cu2', name: 'Sample Clinic', msp_owned: false, provisioning_mode: 'monitoring_only', extra_approvals: {}, contact_name: null, contact_email: null, created_at: iso(10 * 864e5), disabled_at: null },
]
const approvals = [
  { id: 'ap1', customer_id: 'cu1', plan_id: null, title: 'Proxmox access for Demo lab cluster', status: 'pending', proposal_hash: 'a3f9c2d41b7e', created_at: iso(36e5), submitted_at: iso(36e5), token_expires_at: new Date(now + 2 * 864e5).toISOString(), decided_at: null, approver_name: null, approver_email: null, approver_statement: null, decision_note: null, completed_at: null },
  { id: 'ap2', customer_id: 'cu2', plan_id: null, title: 'Read-only access', status: 'approved', proposal_hash: '77be01c9d2aa', created_at: iso(5 * 864e5), submitted_at: iso(5 * 864e5), token_expires_at: iso(2 * 864e5), decided_at: iso(4 * 864e5), approver_name: 'Sam Example', approver_email: 'sam@sample-clinic.example', approver_statement: 'I am authorised to approve these permissions.', decision_note: null, completed_at: null },
]

const planOut = (policy: any) => { // eslint-disable-line @typescript-eslint/no-explicit-any
  const s = policy?.scope ?? {}, pools: string[] = s.pools ?? [], stores: string[] = s.storages ?? [], nets: string[] = s.networks ?? []
  const steps: any[] = [ // eslint-disable-line @typescript-eslint/no-explicit-any
    ...pools.map((p) => ({ kind: 'pool', op: 'create', target: p, detail: {}, reason: 'Pool the account is confined to', risk: 'normal' })),
    { kind: 'role', op: 'create', target: 'OfficeUnboundMonitor', detail: { privileges: ['Datastore.Audit', 'Pool.Audit', 'Sys.Audit', 'VM.Audit'] }, reason: '', risk: 'normal' },
    ...(policy?.preset === 'monitoring' ? [] : [{ kind: 'role', op: 'create', target: 'OfficeUnboundDeploy', detail: { privileges: ['Datastore.AllocateSpace', 'VM.Allocate', 'VM.Clone', 'VM.Config.CPU', 'VM.PowerMgmt'] }, reason: '', risk: 'normal' }]),
    { kind: 'user', op: 'create', target: 'ics-svc@pve', detail: {}, reason: '', risk: 'normal' },
    { kind: 'token', op: 'create', target: 'ics-svc@pve!ics-inv', detail: { privsep: true }, reason: 'Reads inventory', risk: 'normal' },
    ...(policy?.preset === 'monitoring' ? [] : [{ kind: 'token', op: 'create', target: 'ics-svc@pve!ics-prov', detail: { privsep: true }, reason: 'Creates and changes VMs', risk: 'normal' }]),
    ...(s.nodes ?? []).map((n: string) => ({ kind: 'acl', op: 'create', target: `/nodes/${n}|ics-svc@pve!ics-inv|OfficeUnboundMonitor`, detail: {}, reason: 'See node health', risk: 'normal' })),
    ...pools.map((p) => ({ kind: 'acl', op: 'create', target: `/pool/${p}|ics-svc@pve!ics-prov|OfficeUnboundDeploy`, detail: {}, reason: 'Create and manage VMs in the pool', risk: 'normal' })),
    ...stores.map((x) => ({ kind: 'acl', op: 'create', target: `/storage/${x}|ics-svc@pve!ics-prov|OfficeUnboundDeploy`, detail: {}, reason: 'Allocate disks', risk: 'normal' })),
    ...nets.map((x) => ({ kind: 'acl', op: 'create', target: `/sdn/zones/localnetwork/${x}|ics-svc@pve!ics-prov|OfficeUnboundDeploy`, detail: {}, reason: 'Attach NICs', risk: 'normal' })),
    { kind: 'role', op: 'noop', target: 'PVEAuditor', detail: {}, reason: 'built-in, untouched', risk: 'normal' },
  ]
  const summary = { create: steps.filter((x) => x.op === 'create').length, modify: 0, remove: 0, noop: 1, conflict: 0 }
  return { preview_id: 'pv-' + Math.random().toString(36).slice(2, 8), plan_hash: Math.random().toString(16).slice(2).padEnd(64, 'a').slice(0, 64), risk: policy?.preset === 'full_admin' ? 'high' : 'normal', summary,
    plan: { steps, conflicts: [], warnings: policy?.preset === 'deploy' ? ['pve-c is not visible to the integration; it cannot be authorised.'] : [], elevated: [], consequences: policy?.preset === 'full_admin' ? ['Every VM, container and storage in the cluster becomes reachable by the integration.'] : [],
      enforcement: permissions.enforcement, blocked: [], facts: { pve_major: 9 } } }
}
const files: Record<string, string> = {
  'commands.txt': ['pveum pool add ou-demo --comment "Office Unbound (design-review mock)"', 'pveum role add OfficeUnboundDeploy --privs "VM.Allocate VM.Clone VM.PowerMgmt"', 'pveum user add ics-svc@pve --comment "Office Unbound service account"', 'pveum user token add ics-svc@pve ics-inv --privsep 1', 'pveum acl modify /pool/ou-demo --tokens ics-svc@pve!ics-prov --roles OfficeUnboundDeploy'].join('\n'),
  'provision.sh': '#!/usr/bin/env bash\n# design-review mock\n', 'rollback.sh': '#!/usr/bin/env bash\n', 'validate.txt': 'pveum user token list ics-svc@pve', 'report.html': '<p>mock</p>',
  'package.json': JSON.stringify({ plan: { facts: { tokens: { inventory: 'ics-inv', provision: 'ics-prov' }, service_user: 'ics-svc@pve' } } }),
}

function read(req: IncomingMessage): Promise<any> { // eslint-disable-line @typescript-eslint/no-explicit-any
  return new Promise((res) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => { try { res(b ? JSON.parse(b) : {}) } catch { res({}) } }) })
}
const send = (res: ServerResponse, code: number, body: unknown) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(body)) }
function series(seed: number, base: number, amp: number) {
  const pts = []
  for (let i = 288; i >= 0; i--) pts.push({ ts: new Date(now - i * 300e3).toISOString(), avg: Math.max(1, Math.min(99, base + amp * Math.sin((i + seed * 30) / 22) + ((i * 7919 + seed) % 7) - 3)), max: null })
  return { points: pts }
}

function jobFor(id: string) {
  const p = plans[id]; if (!p) return null
  const n = (polls[id] = (polls[id] ?? 0) + 1)
  const high = p.risk === 'high'
  const pending = high && n < 4
  if (pending) return { plan: { id, status: 'pending_approval', approvals_required: 2, approval_count: n > 1 ? 1 : 0 }, job: null }
  const status = n < (high ? 6 : 3) ? 'running' : 'succeeded'
  let result: unknown = {}
  const a = p.action
  if (a === 'provider.provision.plan_preview') result = planOut(p.params.policy)
  else if (a === 'provider.provision.apply' || a === 'provider.credential.import' || a === 'endpoint.register') result = { endpoint_id: EP, pve_version: '9.0.3', verification: { inventory: { ok: true, verbs: [], missing: [], unexpected: [] }, provision: { ok: true, verbs: [], missing: [], unexpected: [] }, ok: true } }
  else if (a === 'provider.provision.package') result = { package_id: 'pkg-1', plan_hash: 'b'.repeat(64), files: Object.keys(files), summary: {} }
  return { plan: { id, status: 'approved' }, job: { id: 'job-' + id, plan_id: id, status, result: status === 'succeeded' ? result : null, error: null, created_at: iso(5e3) } }
}

export function mockApi(): Plugin {
  return {
    name: 'providers-design-review-mock',
    configureServer(server) {
      server.middlewares.use('/api/v1', async (req, res, next) => {
        const url = (req.url ?? '').split('?')[0]!, qs = new URLSearchParams((req.url ?? '').split('?')[1] ?? ''), method = req.method ?? 'GET'
        const b = method === 'POST' ? await read(req) : {}
        if (url === '/__scenario') { scenario = (qs.get('name') as Scenario) ?? 'full'; for (const k of Object.keys(polls)) delete polls[k]; return send(res, 200, { scenario }) }
        const have = scenario !== 'empty'
        if (url === '/auth/me') return send(res, 200, { id: 'u1', username: 'admin', role: 'admin', csrf_token: 'mock' })
        if (url === '/incidents') return send(res, 200, [])
        if (url === '/endpoints') return send(res, 200, have ? [endpoint(scenario === 'manual')] : [])
        if (url === `/endpoints/${EP}`) return send(res, 200, endpoint(scenario === 'manual'))
        if (url === '/infra/nodes') return send(res, 200, have ? nodes : [])
        if (url === '/infra/storage') return send(res, 200, have ? storage : [])
        if (url === '/infra/networks') return send(res, 200, have ? networks : [])
        if (url === '/infra/guests') return send(res, 200, have ? guests : [])
        if (url === '/infra/templates') return send(res, 200, have ? templates : [])
        if (url === '/infra/metrics') { const m = qs.get('metric') ?? ''; const id = qs.get('id') ?? ''; const seed = id.length + (id.charCodeAt(id.length - 1) || 0)
          if (m === 'cpu_pct') return send(res, 200, series(seed, 26, 12)); if (m === 'mem_used_bytes') return send(res, 200, { points: series(seed, 40, 8).points.map((p) => ({ ...p, avg: (p.avg ?? 0) * GB })) })
          if (m === 'mem_total_bytes') return send(res, 200, { points: series(seed, 40, 0).points.map((p) => ({ ...p, avg: 100 * GB })) })
          if (m === 'used_bytes') return send(res, 200, { points: series(seed, 55, 4).points.map((p) => ({ ...p, avg: (p.avg ?? 0) * GB })) }); return send(res, 200, { points: series(seed, 100, 0).points.map((p) => ({ ...p, avg: 100 * GB })) }) }
        if (url === `/providers/${EP}/permissions`) return send(res, 200, scenario === 'manual' ? { endpoint_id: EP, managed_by_provisioning: false, note: 'this endpoint was registered with manually supplied tokens; no provisioning policy is stored' } : permissions)
        if (url === `/providers/${EP}/permissions/check`) return send(res, 200, permissions.last_drift)
        if (/^\/providers\/[^/]+\/provisioning\/packages\//.test(url)) return send(res, 200, { package_id: 'pkg-1', plan_hash: 'b'.repeat(64), files })
        if (url === '/credentials') return send(res, 200, have ? credentials : [])
        if (/^\/credentials\/access-review/.test(url)) return send(res, 200, [{ seq: 1, at: iso(60e3), event: 'credential.use', who: 'inventory-collector', credential_id: 'c1', label: 'x', provider: 'proxmox', purpose: 'inventory', use: 'discovery' }])
        if (/^\/credentials\/c\d$/.test(url)) return send(res, 200, { ...credentials[0], history: [{ at: iso(9 * 864e5), event: 'credential.created', actor: 'admin' }, { at: iso(36e5), event: 'credential.tested', actor: 'admin' }], used_by_endpoints: [EP] })
        if (url === '/customers') return send(res, 200, customers)
        if (url === '/customer-approvals' && method === 'GET') return send(res, 200, approvals)
        if (url === '/customer-approvals' && method === 'POST') return send(res, 201, { id: 'ap9', status: 'draft', proposal_hash: 'c0ffee' })
        if (/\/customer-approvals\/[^/]+\/submit/.test(url)) return send(res, 200, { id: 'ap9', link_path: '/approve#t=mock-single-use-token-not-real', expires_at: new Date(now + 3 * 864e5).toISOString() })
        if (url === '/audit') return send(res, 200, [{ seq: 12, at: iso(2 * 36e5), action: 'provider.permissions.check', actor_name: 'worker', resource: 'endpoint', resource_id: EP }, { seq: 9, at: iso(9 * 864e5), action: 'provider.provision.applied', actor_name: 'admin', resource: 'endpoint', resource_id: EP }])
        if (url === '/setup/probe') {
          const ok = !b.fingerprint_sha256 || b.fingerprint_sha256 === FP
          const tls = { ok: b.ca_pem ? true : ok, verified_by: b.ca_pem ? 'ca' : 'fingerprint', presented_fingerprint_sha256: FP, subject: 'CN=pve-a.demo.example', not_after: '2027-09-30', ...(ok ? {} : { error: 'The certificate does not match the pinned fingerprint.' }) }
          if (b.stage === 'tls') return send(res, 200, { tls })
          return send(res, 200, { ok: true, version: '9.0.3', cluster_name: 'demo-lab', tls, permissions: { inventory: { ok: true, missing: [], unnecessary: [{ path: '/vms', privilege: 'VM.Console' }] }, provision: { ok: false, missing: [{ path: '/sdn/zones/localnetwork/vmbr0', privilege: 'SDN.Use' }], fix_commands: ["pveum acl modify /sdn/zones/localnetwork/vmbr0 --tokens 'ics-svc@pve!ics-prov' --roles OfficeUnboundDeploy"] } },
            discovery: { nodes: nodes.map(({ name, status, managed, cpu_total, mem_total, mem_used, cpu_pct }) => ({ name, status, managed, cpu_total, mem_total, mem_used, cpu_pct })), storage: storage.map(({ name, node: n, type, content, shared, total, used, active }) => ({ name, node: n, type, content, shared, total, used, active })), networks, guests, templates, warnings: ['pve-c: token has no Sys.Audit, capacity unknown'] } })
        }
        if (url === '/plans' && method === 'POST') {
          const id = 'plan-' + Math.random().toString(36).slice(2, 8), high = ['provider.provision.apply', 'endpoint.register', 'provider.token.revoke', 'provider.token.rotate', 'provider.permissions.reconcile', 'customer.update', 'customer.create'].includes(b.action)
          plans[id] = { action: b.action, params: b.params ?? {}, risk: high ? 'high' : 'low', created: Date.now() }
          return send(res, 201, { plan_id: id, status: high ? 'pending_approval' : 'approved', risk: high ? 'high' : 'low', job_id: null, params_hash: 'x', approvals_required: high ? 2 : 1 })
        }
        if (url === '/plans' && method === 'GET') return send(res, 200, Object.keys(plans).map((id) => jobFor(id)!.plan))
        if (/^\/jobs\/job-/.test(url)) { const j = jobFor(url.slice(10))?.job; return j ? send(res, 200, j) : send(res, 404, { detail: 'job not found' }) }
        if (url === '/jobs' && method === 'GET') return send(res, 200, Object.keys(plans).map((id) => jobFor(id)!.job).filter(Boolean))
        return next()
      })
    },
  }
}
