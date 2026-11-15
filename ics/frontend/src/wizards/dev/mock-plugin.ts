// DEV-ONLY mock API for design review. Runs inside the Vite dev server (Node), is never imported by the app, and is therefore absent from `vite build` output.
// Every payload below is invented to exercise the UI. It is NOT infrastructure data.
import type { Plugin } from 'vite'
import type { IncomingMessage, ServerResponse } from 'node:http'

const PRESENTED_FP = '3A:91:C4:0E:7B:55:D2:18:6F:A0:9C:41:E7:2D:B3:68:F5:0A:17:CC:84:3E:9B:D1:62:4F:A8:05:7D:E9:30:BB'

const nodes = [
  { name: 'pve-a', status: 'online', cpu_total: 32, cpu_used: 9, mem_total_gb: 256, mem_used_gb: 88 },
  { name: 'pve-b', status: 'online', cpu_total: 32, cpu_used: 14, mem_total_gb: 256, mem_used_gb: 131 },
]
const storage = [
  { id: 'local-zfs', node: null, type: 'zfspool', content: ['images', 'rootdir'], total_gb: 3800, used_gb: 1450, shared: true },
  { id: 'ssd-fast', node: 'pve-a', type: 'lvmthin', content: ['images'], total_gb: 960, used_gb: 410 },
  { id: 'pbs-backup', node: null, type: 'pbs', content: ['backup'], total_gb: 12000, used_gb: 4100, shared: true },
]
const networks = [
  { name: 'vmbr0', node: null, kind: 'bridge', vlan: null },
  { name: 'vmbr1', node: null, kind: 'bridge', vlan: null },
  { name: 'vlan120', node: null, kind: 'vlan', vlan: 120 },
]
const guests = [
  { vmid: 100, name: 'dns-01', kind: 'lxc', node: 'pve-a', status: 'running' },
  { vmid: 101, name: 'unifi', kind: 'vm', node: 'pve-a', status: 'running' },
  { vmid: 105, name: 'nas-gw', kind: 'vm', node: 'pve-b', status: 'running' },
  { vmid: 9000, name: 'ubuntu-2404-ci', kind: 'vm', node: 'pve-a', status: 'stopped', template: true },
]
const profiles = [
  { id: 'lab', label: 'Lab', description: 'Single VM for evaluation. No redundancy.', users_min: 1, users_max: 10, vm_count: 1, components: ['identity', 'groupware', 'files', 'edge'] },
  { id: 'small', label: 'Small', description: 'Two VMs: core services and files/office.', users_min: 10, users_max: 50, vm_count: 2, components: ['identity', 'groupware', 'files', 'office', 'edge', 'monitoring'] },
  { id: 'medium', label: 'Medium', description: 'Services split across three VMs for headroom.', users_min: 50, users_max: 250, vm_count: 3, components: ['identity', 'groupware', 'files', 'office', 'edge', 'monitoring'] },
  { id: 'large', label: 'Large', description: 'Dedicated VMs per heavy component.', users_min: 250, users_max: 1000, vm_count: 5, components: ['identity', 'groupware', 'files', 'office', 'edge', 'monitoring'] },
  { id: 'ha', label: 'High availability', description: 'Replicated components across nodes.', users_min: 100, users_max: null, vm_count: 6, ha: true, components: ['identity', 'groupware', 'files', 'office', 'edge', 'monitoring'] },
  { id: 'msp-multi', label: 'MSP multi-tenant', description: 'Shared platform, isolated tenants.', users_min: 50, users_max: null, vm_count: 5, multi_tenant: true, components: ['identity', 'groupware', 'files', 'office', 'edge', 'monitoring'] },
  { id: 'dedicated', label: 'Dedicated', description: 'One isolated environment per customer.', users_min: 25, users_max: 500, vm_count: 4, components: ['identity', 'groupware', 'files', 'office', 'edge', 'monitoring'] },
  { id: 'custom', label: 'Custom', description: 'Choose the components and layout yourself.', vm_count: 3, components: ['identity', 'edge'] },
]
const components = [
  { id: 'identity', label: 'Identity' }, { id: 'groupware', label: 'Groupware' }, { id: 'files', label: 'Files' }, { id: 'edge', label: 'Edge proxy' },
  { id: 'office', label: 'Online office', optional: true, default_on: true, description: 'Collabora document editing' },
  { id: 'monitoring', label: 'Monitoring', optional: true, default_on: true, description: 'Health checks and metrics' },
  { id: 'antispam', label: 'Anti-spam gateway', optional: true, description: 'Inbound mail filtering' },
]
const envs = [
  { id: 'env-acme', name: 'acme-prod', profile: 'medium', status: 'running' },
  { id: 'env-lab', name: 'lab-eval', profile: 'lab', status: 'running' },
]
const resources = [
  { logical_name: 'acme-core', kind: 'vm' }, { logical_name: 'acme-files', kind: 'vm' }, { logical_name: 'acme-edge', kind: 'vm' },
  { logical_name: 'keycloak', kind: 'service' }, { logical_name: 'opencloud', kind: 'service' }, { logical_name: 'postgres', kind: 'service' },
]

type Body = Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any

function buildPlan(r: Body) {
  const p = profiles.find((x) => x.id === r.profile) ?? profiles[1]
  const ha = r.availability === 'ha'
  const roles = ['core', 'files', 'edge', 'office', 'db', 'mail'].slice(0, Math.max(1, p.vm_count ?? 2) + (ha ? 1 : 0))
  const per = Math.max(1, Math.ceil(r.users / 25))
  const vms = roles.map((role, i) => ({
    name: `${r.name}-${role}${ha && i === 0 ? '-1' : ''}`, role, os_image: i % 3 === 2 ? 'Debian 12' : 'Ubuntu 24.04',
    cores: Math.min(16, 2 + Math.round(per / (i + 1))), memory_mb: Math.min(65536, 4096 + 1024 * per * (i === 0 ? 2 : 1)),
    disks: [{ name: 'scsi0', size_gb: 40, storage: r.storage }, ...(role === 'files' ? [{ name: 'scsi1', size_gb: Math.min(2000, 100 + r.users * 5), storage: r.storage }] : [])],
    nics: [{ bridge: r.network.bridge, vlan: r.network.vlan, ip: 'DHCP' }], node: i % 2 ? 'pve-b' : 'pve-a',
  }))
  const cores = vms.reduce((a, v) => a + v.cores, 0)
  const memGb = vms.reduce((a, v) => a + v.memory_mb / 1024, 0)
  const diskGb = vms.reduce((a, v) => a + v.disks.reduce((b, d) => b + d.size_gb, 0), 0)
  const errors: { message: string }[] = []
  const warnings: { message: string }[] = []
  if (memGb > 300) errors.push({ message: `Requested memory (${Math.round(memGb)} GiB) exceeds what the endpoint can provide. Reduce users or choose a larger profile split.` })
  if (ha) warnings.push({ message: 'High availability needs shared storage for live failover; local-zfs is shared, ssd-fast is not.' })
  if (!r.backup.enabled) warnings.push({ message: 'Backups are disabled. Recovery from data loss will not be possible.' })
  const comps = p.components.filter((c) => !['office', 'monitoring'].includes(c) || r.optional_components.includes(c))
  return {
    plan_hash: 'sha256:' + btoa(JSON.stringify(r)).replace(/[^A-Za-z0-9]/g, '').slice(0, 24).toLowerCase(),
    vms,
    containers: comps.map((c, i) => ({ name: `ou-${c}`, vm: vms[i % vms.length].name, image: `registry.example/ou/${c}:1.4.${i}`, digest: 'sha256:9f2c' + '0'.repeat(30) + i })),
    services: comps.map((c, i) => ({ name: c, component: c, vm: vms[i % vms.length].name, ports: c === 'edge' ? [80, 443] : [8000 + i * 10] })),
    steps: [
      { id: 'clone', label: 'Clone approved template for each VM' }, { id: 'cfg', label: 'Configure CPU, memory, disks, NICs', depends_on: ['clone'] },
      { id: 'boot', label: 'Start VMs and wait for agent enrollment', depends_on: ['cfg'] }, { id: 'pods', label: 'Deploy pinned containers (rootless Podman)', depends_on: ['boot'] },
      { id: 'dns', label: 'Create DNS records and TLS', depends_on: ['pods'] }, { id: 'checks', label: 'Register health checks and verify', depends_on: ['dns'] },
    ],
    ports: [{ service: 'edge', port: 443, proto: 'tcp', exposure: 'external' }, { service: 'edge', port: 80, proto: 'tcp', exposure: 'external' }, ...comps.filter((c) => c !== 'edge').map((c, i) => ({ service: c, port: 8000 + i * 10, proto: 'tcp', exposure: 'internal' }))],
    backups: r.backup.enabled ? [{ target: r.backup.storage, schedule: 'daily 02:00', retention_days: r.backup.retention_days }] : [],
    monitoring: [{ check: 'HTTPS edge reachable', target: `${r.name}.example` }, { check: 'Identity login flow' }, { check: 'Disk free above 15%' }],
    consumption: { cores, memory_gb: Math.round(memGb), disk_gb: diskGb },
    capacity: [
      { scope: 'node', id: 'pve-a', unit: 'cores', total: 32, used: 9, added: Math.ceil(cores / 2) }, { scope: 'node', id: 'pve-b', unit: 'cores', total: 32, used: 14, added: Math.floor(cores / 2) },
      { scope: 'node', id: 'pve-a', unit: 'GiB', total: 256, used: 88, added: Math.ceil(memGb / 2) }, { scope: 'node', id: 'pve-b', unit: 'GiB', total: 256, used: 131, added: Math.floor(memGb / 2) },
      { scope: 'storage', id: r.storage, unit: 'GiB', total: 3800, used: 1450, added: diskGb },
    ],
    warnings, errors,
  }
}

function buildPreview(change: Body) {
  const v = change.params
  const resource = v.vm ?? v.service ?? v.component ?? 'environment'
  const disruptive = ['resize_cpu', 'resize_ram', 'move_workload', 'change_network', 'change_version'].includes(change.type)
  const diffs: Record<string, [string, unknown, unknown]> = {
    resize_cpu: ['vCPU', 4, v.cores], resize_ram: ['Memory (GiB)', 8, v.memory_gb], expand_storage: ['Disk size (GiB)', 100, v.new_size_gb],
    move_workload: ['Node', 'pve-a', v.target_node], change_network: ['Bridge / VLAN', 'vmbr0 / untagged', `${v.bridge} / ${v.vlan ?? 'untagged'}`], scale: ['Replicas', 1, v.replicas],
    change_version: ['Version', '2.0.3', v.version], add_service: ['Service', '(absent)', v.component], remove_service: ['Service', 'present', '(removed)'], add_vm: ['VM', '(absent)', `${v.role}: ${v.cores} vCPU / ${v.memory_gb} GiB / ${v.disk_gb} GiB`],
    backup_policy: ['Retention (days)', 14, v.retention_days], monitoring_policy: ['Check interval (s)', 60, v.interval_seconds],
  }
  const d = diffs[change.type] ?? ['Setting', 'old', 'new']
  return {
    plan_hash: 'sha256:' + btoa(JSON.stringify(change)).replace(/[^A-Za-z0-9]/g, '').slice(0, 24).toLowerCase(),
    summary: `${change.type.replace(/_/g, ' ')} on ${resource}`,
    diff: [{ resource, field: d[0], current: d[1] as string | number, proposed: d[2] as string | number }],
    capacity: [{ scope: 'node', id: 'pve-a', unit: 'GiB', total: 256, used: 88, added: change.type === 'resize_ram' ? v.memory_gb - 8 : 4 }, { scope: 'storage', id: 'local-zfs', unit: 'GiB', total: 3800, used: 1450, added: change.type === 'expand_storage' ? v.new_size_gb - 100 : 0 }],
    downtime: { seconds: disruptive ? 180 : 0, steps: disruptive ? ['Shut down guest (graceful)', 'Apply configuration', 'Start guest and verify health'] : [] },
    dependencies: resource === 'postgres' ? ['keycloak', 'opencloud'] : ['edge'],
    risk: change.type === 'remove_service' ? 'high' : disruptive ? 'medium' : 'low',
    requires_snapshot: disruptive || change.type === 'expand_storage', requires_backup: change.type === 'remove_service' || change.type === 'change_version',
    requires_maintenance_window: disruptive,
    warnings: disruptive ? [{ message: 'The guest restarts. Users see a short interruption.' }] : [], errors: [],
  }
}

function read(req: IncomingMessage): Promise<Body> {
  return new Promise((res) => { let s = ''; req.on('data', (c) => (s += c)); req.on('end', () => { try { res(JSON.parse(s || '{}')) } catch { res({}) } }) })
}
function send(res: ServerResponse, status: number, body: unknown) { res.statusCode = status; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(body)) }

export function mockApi(): Plugin {
  return {
    name: 'ou-wizard-mock-api',
    apply: 'serve',
    configureServer(server) {
      server.middlewares.use('/api/v1', async (req, res, next) => {
        const url = (req.url ?? '').split('?')[0]
        const method = req.method ?? 'GET'
        const b = method === 'POST' ? await read(req) : {}
        if (url === '/setup/state') return send(res, 200, { has_endpoint: false, mfa: { enrolled_users: 1, total_users: 3, required: false }, alert_channels: [] })
        if (url === '/setup/probe') {
          const fpOk = !b.fingerprint_sha256 || b.fingerprint_sha256.replace(/:/g, '') === PRESENTED_FP.replace(/:/g, '')
          const tls = { ok: b.ca_pem ? true : fpOk, verified_by: b.ca_pem ? 'ca' : 'fingerprint', presented_fingerprint_sha256: PRESENTED_FP, subject: 'CN=pve-a.lab.example', not_after: '2027-09-30',
            ...(fpOk ? {} : { error: 'Presented certificate does not match the pinned fingerprint.' }) }
          if (b.stage === 'tls') return send(res, 200, { tls })
          return send(res, 200, {
            ok: true, version: '9.0.3', cluster_name: 'lab-cluster', tls,
            permissions: {
              inventory: { ok: true, missing: [], unnecessary: [{ path: '/vms', privilege: 'VM.Console' }] },
              provision: { ok: false, missing: [{ path: '/sdn/zones/localnetwork/vmbr0', privilege: 'SDN.Use' }] },
            },
            discovery: { nodes, storage, networks, guests, pools: ['ou-lab'] },
          })
        }
        if (url === '/catalog/profiles') return send(res, 200, profiles)
        if (url === '/catalog/components') return send(res, 200, components)
        if (url === '/endpoints') return send(res, 200, [{ id: 'ep1', name: 'pve-main', type: 'proxmox', base_url: 'https://pve-a.lab.example:8006', token_id: 'ics-inventory@pve!inventory', fingerprint_sha256: null, has_ca_bundle: false, created_at: '2026-11-15T10:00:00Z' }])
        if (url === '/infra/nodes') return send(res, 200, nodes)
        if (url === '/infra/storage') return send(res, 200, storage)
        if (url === '/infra/networks') return send(res, 200, networks)
        if (url === '/deployments' && method === 'GET') return send(res, 200, envs)
        if (/^\/deployments\/[^/]+\/resources$/.test(url)) return send(res, 200, resources)
        if (url === '/deployments/plan') return send(res, 200, buildPlan(b))
        if (/^\/deployments\/[^/]+\/changes\/preview$/.test(url)) return send(res, 200, buildPreview(b.change))
        if (url === '/plans' && method === 'POST') return send(res, 201, { plan_id: '5b1e0a7c-3f64-4c11-9a2e-0d2f6c1a9b77', status: 'pending_approval', risk: 'high', job_id: b.action === 'deployment.create' ? 'job-demo-1' : null, params_hash: 'abc', approvals_required: 2 })
        if (/^\/jobs\/[^/]+\/steps$/.test(url)) return send(res, 200, [
          { index: 0, name: 'Clone approved template', status: 'succeeded', progress: 100, attempts: 1 },
          { index: 1, name: 'Configure CPU, memory, disks, NICs', status: 'succeeded', progress: 100, attempts: 1 },
          { index: 2, name: 'Start VMs and wait for agent enrollment', status: 'running', progress: 45, attempts: 1, log_excerpt: 'waiting for enrollment of mock-core (2/3)' },
          { index: 3, name: 'Deploy pinned containers', status: 'pending', progress: 0, attempts: 0 },
        ])
        return next()
      })
    },
  }
}
