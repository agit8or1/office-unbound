import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick } from 'vue'
import { api, load } from './api'
import { setCsrf } from '../api'
import DeployWizard from './deploy/DeployWizard.vue'

function stubFetch(routes: Record<string, { status?: number; body: unknown }>) {
  const calls: { method: string; url: string; body: string | undefined }[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ method: init.method ?? 'GET', url, body: init.body as string | undefined })
    const r = routes[`${init.method} ${url}`] ?? { status: 404, body: { detail: 'Not Found' } }
    return new Response(JSON.stringify(r.body), { status: r.status ?? 200 })
  }))
  return calls
}
afterEach(() => vi.unstubAllGlobals())

describe('wizard api client', () => {
  it('submitPlan posts the exact {action, params} JSON to /plans with CSRF', async () => {
    setCsrf('csrf1')
    const calls = stubFetch({ 'POST /api/v1/plans': { status: 201, body: { plan_id: 'p', status: 'pending_approval', risk: 'high', job_id: null, params_hash: 'h', approvals_required: 2 } } })
    await api.submitPlan('deployment.change', { deployment_id: 'e', changes: { users: 80 } })
    expect(calls).toHaveLength(1)
    expect(JSON.parse(calls[0].body!)).toEqual({ action: 'deployment.change', params: { deployment_id: 'e', changes: { users: 80 } } })
    setCsrf(null)
  })
  it('maps 404 to an "unavailable" state, other errors to error, never to data', async () => {
    stubFetch({ 'GET /api/v1/catalog/profiles': { status: 404, body: { detail: 'Not Found' } }, 'GET /api/v1/catalog/components': { status: 500, body: { detail: 'boom' } } })
    expect(await load(() => api.profiles())).toEqual({ state: 'unavailable', status: 404 })
    expect(await load(() => api.components())).toMatchObject({ state: 'error', message: 'boom' })
  })
})

describe('backend response mapping', () => {
  it('maps the real catalog, plan and change-preview shapes', async () => {
    stubFetch({
      'GET /api/v1/catalog/profiles': { body: { profiles: [{ name: 'small', title: 'Small', description: 'd', max_users: 50, min_nodes: 1, ha: false, tenancy: 'single', maturity: 'lab-validated',
        vms: [{ name: 'id', components: ['identity', 'edge'] }, { name: 'files', components: ['files', 'office'] }], optional_components: ['office'], default_optional: ['office'] }] } },
      'POST /api/v1/deployments/plan': { body: { plan_hash: 'h', executable: true, vms: [{ name: 'a-id', logical: 'id', os_image: { id: 'debian-12' }, cores: 2, memory_mb: 2048, disks: [{ name: 'root', size_gb: 20, storage: 's' }], nics: [{ bridge: 'vmbr0', vlan: null }], node: 'pve1' }],
        containers: [], services: [], firewall: [{ vm: 'a-id', port: 443, proto: 'tcp', from: 'any', purpose: 'edge' }], dns: [], backups: [], checks: [],
        steps: [{ key: 'vm.clone:a-id', op: 'clone_vm', target: 'a-id', depends_on: [] }], consumption: { vms: 1, cores: 2, memory_mb: 2048, disk_gb: 20, est_seconds: 120 },
        capacity: { nodes: [{ name: 'pve1', memory_free_mb: 4096, vcpu_free: 30, vms_placed: 1 }], storage: [{ name: 's@pve1', avail_after_gb: 100 }] }, warnings: [{ code: 'w', message: 'careful' }], errors: [] } },
      'POST /api/v1/deployments/prod/changes/preview': { body: { executable: true, plan: { plan_hash: 'p2', capacity: { nodes: [], storage: [] }, warnings: [], errors: [], vms: [], containers: [], services: [], steps: [], firewall: [], dns: [], backups: [], checks: [], consumption: {} },
        diff: { added: [], removed: [{ kind: 'vm', name: 'x' }], changed: [{ kind: 'vm', name: 'a-id', fields: { cores: { from: 2, to: 4 } } }], capacity_impact: { vms: -1, cores: 2, memory_mb: 0, disk_gb: 0 },
          downtime_seconds: 120, disruptive_steps: ['vm.stop:a-id'], snapshot_required: true, risk: 'high', risk_reasons: ['resources are removed'], requires_maintenance: true } } },
    })
    const [p] = await api.profiles()
    expect(p).toMatchObject({ id: 'small', label: 'Small', users_max: 50, vm_count: 2, multi_tenant: false, components: ['identity', 'edge', 'files', 'office'], default_optional: ['office'] })
    const plan = await api.planDeployment({ customer_id: 'c', deployment_id: 'prod', profile: 'small', users: 5, tenants: 1, domain: 'c.example', endpoint: 'lab', pool: 'p', bridge: 'vmbr0', optional: {} })
    expect(plan.vms[0]).toMatchObject({ os_image: 'debian-12', role: 'id' })
    expect(plan.steps[0]).toMatchObject({ id: 'vm.clone:a-id', label: 'clone vm a-id' })
    expect(plan.ports[0]).toMatchObject({ port: 443, from: 'any' }); expect(plan.warnings[0]!.message).toBe('careful')
    expect(plan.capacity.map((c) => c.id)).toEqual(['pve1', 's@pve1'])
    const cp = await api.previewChange('prod', { users: 80 })
    expect(cp).toMatchObject({ plan_hash: 'p2', risk: 'high', requires_snapshot: true, requires_maintenance: true, downtime: { seconds: 120, steps: ['vm.stop:a-id'] } })
    expect(cp.diff).toEqual(expect.arrayContaining([{ resource: 'vm a-id', field: 'cores', current: 2, proposed: 4 }, { resource: 'vm x', field: 'resource', current: 'present', proposed: 'removed' }]))
  })
})

describe('DeployWizard component', () => {
  it('on a backend without the catalog shows the unavailable state, offers no submit, and sends no plan', async () => {
    const calls = stubFetch({})
    const el = document.createElement('div'); document.body.appendChild(el)
    const app = createApp(DeployWizard); app.mount(el)
    await new Promise((r) => setTimeout(r, 20)); await nextTick()
    expect(el.textContent).toMatch(/not available|catalog/i)
    const submit = [...el.querySelectorAll('button')].find((b) => /Submit deployment plan/.test(b.textContent ?? '')) as HTMLButtonElement | undefined
    expect(submit === undefined || submit.disabled).toBe(true)
    expect(calls.some((c) => c.method === 'POST')).toBe(false)
    app.unmount()
  })
})
