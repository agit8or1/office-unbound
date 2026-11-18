import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  applyType, architectureCards, backupMessages, buildSizeRequest, createParams, createSizer, newModel, recommendationText, requestKey, sizable, sizingApi,
  summarize, validatePlacement, validateType, validateWorkload, vmEvidence, wizardSteps, type SizeResponse, type SizeVm,
} from './sizing'
import { canSubmitChange, changeParams, needsMaintenance, recommendationRows, resizeApi, type ResizeResponse } from './resize'

const vm = (name: string, cores: number, memory_mb: number, disk_gb: number, components: string[], node = 'pve1'): SizeVm =>
  ({ name, logical: name, services: [], components, cores, memory_mb, disk_gb, disks: [], node, depends_on: [], sizing: null })

function response(over: Partial<SizeResponse> = {}): SizeResponse {
  const vms = [vm('acme-prod-id', 2, 2048, 20, ['identity']), vm('acme-prod-gw', 4, 8192, 120, ['groupware']), vm('acme-prod-edge', 1, 1024, 10, ['edge'], 'pve2')]
  return {
    deployment_type: 'production', services: ['mail'], components: ['identity', 'groupware', 'edge'],
    service_catalog: [{ id: 'mail', components: ['groupware'] }, { id: 'files', components: ['files'] }, { id: 'office', components: ['office'] }],
    architectures: [
      { id: 'consolidated', available: true, why_not: null, vms: 1, fits: true },
      { id: 'balanced', available: true, why_not: null, vms: 3, fits: true },
      { id: 'isolated', available: true, why_not: null, vms: 4, fits: false, capacity_errors: [{ code: 'insufficient_capacity', message: 'pve1 short of memory' }] },
      { id: 'ha', available: false, why_not: 'groupware has no application replication', vms: 6, fits: true },
      { id: 'dedicated', available: false, why_not: 'no approved node without foreign guests' },
    ],
    recommended: { architecture: 'balanced', vms: 3, text: 'Recommended: 3 VMs (balanced)' },
    selected: 'balanced', errors: [], writes: 'none',
    plan_input: { profile: 'custom', customer_id: 'acme' }, plan_hash: 'a'.repeat(64), plan_blocking: [],
    vms, totals: { vms: 3, cores: 7, memory_mb: 11264, disk_gb: 150 }, fits: true,
    capacity: { available: { vcpu: 16, memory_mb: 65536, storage_gb: 1000 }, headroom: { vcpu: 9, memory_mb: 54272, storage_gb: 850, memory_pct: 83 }, nodes: [], storage: [] },
    estimates_flags: ['groupware.memory_mb'], risks: [], backup: { issues: [] },
    ...over,
  }
}

function filled() {
  const m = newModel()
  applyType(m, 'production')
  Object.assign(m, { customerId: 'acme', name: 'prod', domain: 'acme.example', endpoint: 'lab' })
  return m
}

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers() })

describe('size request', () => {
  it('sends only checked services, drops ids the catalog does not offer, sorted', () => {
    const m = filled()
    m.services = ['office', 'mail', 'chat', 'mail']
    expect(buildSizeRequest(m, null).services).toEqual(['chat', 'mail', 'office'])
    expect(buildSizeRequest(m, ['mail', 'office', 'files']).services).toEqual(['mail', 'office'])
    m.services = m.services.filter((s) => s !== 'office')
    expect(buildSizeRequest(m, ['mail', 'office']).services).toEqual(['mail'])
  })
  it('maps the model to the API shape; tenants only for MSP; empty optional fields become null', () => {
    const m = filled()
    m.tenants = 4
    const r = buildSizeRequest(m, null)
    expect(r).toMatchObject({ deployment_type: 'production', customer_id: 'acme', deployment_id: 'prod', domain: 'acme.example', endpoint: 'lab', architecture: null })
    expect(r.workload).toMatchObject({ users: 100, tenants: 1, concurrent_users: null, concurrent_pct: 30, growth_pct: 20 })
    expect(r.placement).toEqual({ allowed_nodes: null, storage: null, bridge: null, vlan: null, pool: null })
    expect(r.updates).toEqual({ mode: 'manual', window: null })
    expect(r.overrides).toEqual({ estimate_margin_pct: null, tier: null, vm: {} })
    applyType(m, 'msp'); m.tenants = 4
    expect(buildSizeRequest(m, null).workload.tenants).toBe(4)
  })
  it('keeps only real VM overrides', () => {
    const m = filled()
    m.vmOverrides = { b: { cores: 4 }, a: {}, c: { memory_mb: 4096, cores: undefined } }
    expect(buildSizeRequest(m, null).overrides.vm).toEqual({ b: { cores: 4 }, c: { memory_mb: 4096 } })
  })
  it('draft identity only for the live summary, and only while names are invalid', () => {
    const m = newModel(); m.endpoint = 'lab'
    expect(buildSizeRequest(m, null, true)).toMatchObject({ customer_id: 'draft', deployment_id: 'draft', domain: 'draft.example' })
    expect(buildSizeRequest(m, null, false).customer_id).toBe('')
    const f = filled()
    expect(buildSizeRequest(f, null, true).customer_id).toBe('acme')
    expect(requestKey(buildSizeRequest(f, null, true))).toBe(requestKey(buildSizeRequest(f, null)))
  })
  it('is sizable only with a cluster, a service and valid numbers', () => {
    const m = filled(); expect(sizable(m)).toBe(true)
    m.services = []; expect(sizable(m)).toBe(false)
    m.services = ['mail']; m.users = 0; expect(sizable(m)).toBe(false)
    m.users = 5; m.endpoint = ''; expect(sizable(m)).toBe(false)
  })
})

describe('response shaping', () => {
  it('summary counts and sums come from the response VMs (= the generated plan)', () => {
    const r = response()
    const s = summarize(r)
    expect(s.vms).toBe(r.vms!.length)
    expect(s.vms).toBe(r.totals!.vms)
    expect([s.vcpu, s.memoryMb, s.storageGb]).toEqual([7, 11264, 150])
    expect([s.vcpu, s.memoryMb, s.storageGb]).toEqual([r.totals!.cores, r.totals!.memory_mb, r.totals!.disk_gb])
    expect(s.headroom).toEqual({ vcpu: 9, memoryMb: 54272, storageGb: 850, memoryPct: 83 })
    expect(s.ready && s.fits).toBe(true)
    const none = summarize(response({ selected: null, vms: undefined, recommended: null }))
    expect(none).toMatchObject({ ready: false, vms: 0, vcpu: 0, fits: null })
    expect(summarize(null).ready).toBe(false)
  })
  it('recommendation N is the API figure', () => {
    expect(recommendationText(response())).toBe('Recommended: 3 VMs based on your selected services and available infrastructure')
    expect(recommendationText(response({ recommended: { architecture: 'consolidated', vms: 1, text: '' } }))).toMatch(/^Recommended: 1 VM based/)
    expect(recommendationText(response({ recommended: null }))).toBeNull()
  })
  it('architecture availability mirrors the API; HA never looks available when the API says no', () => {
    const cards = architectureCards(response())
    const by = Object.fromEntries(cards.map((c) => [c.id, c]))
    expect(cards.map((c) => c.id)).toEqual(['consolidated', 'balanced', 'isolated', 'ha', 'dedicated'])
    expect(by.ha).toMatchObject({ available: false, whyNot: 'groupware has no application replication', vms: null, recommended: false })
    expect(by.dedicated.available).toBe(false)
    expect(by.balanced).toMatchObject({ available: true, recommended: true, selected: true, vms: 3, fitNote: null })
    expect(by.isolated.fitNote).toBe('pve1 short of memory')
    // missing / truthy-but-not-true values never count as available
    const odd = architectureCards(response({ architectures: [{ id: 'ha', available: 'yes' as unknown as boolean, why_not: null }] }))
    expect(odd.every((c) => !c.available)).toBe(true)
    expect(architectureCards(null).every((c) => !c.available)).toBe(true)
  })
  it('placement validation refuses an architecture the API marks unavailable', () => {
    const m = filled(); m.architecture = 'ha'
    expect(validatePlacement(m, response()).architecture).toBeTruthy()
    m.architecture = 'isolated'
    expect(validatePlacement(m, response()).architecture).toBeUndefined()
  })
  it('estimate vs measured badges', () => {
    const r = response()
    expect(vmEvidence(r.vms![1], r.estimates_flags!)).toBe('estimate')
    expect(vmEvidence(r.vms![0], r.estimates_flags!)).toBe('measured')
    expect(vmEvidence({ ...r.vms![0], sizing: { components: { identity: { estimated: ['cores'] } } } }, [])).toBe('estimate')
  })
  it('backup messages from issues and backup risks, without duplicates', () => {
    const r = response({ backup: { issues: [{ code: 'no_backup_destination', severity: 'error', message: 'no destination' }] },
      risks: [{ code: 'no_backup_destination', severity: 'error', message: 'no destination' }, { code: 'rpo_not_achievable', severity: 'warning', message: 'rpo' }, { code: 'thin_storage', message: 'thin' }] })
    expect(backupMessages(r)).toEqual([{ kind: 'bad', text: 'no destination' }, { kind: 'warn', text: 'rpo' }])
  })
  it('create params are the response plan_input plus the generated plan hash', () => {
    const r = response()
    expect(createParams(r.plan_input!, 'h'.repeat(64))).toEqual({ spec: r.plan_input, plan_hash: 'h'.repeat(64) })
  })
})

describe('validation', () => {
  it('type step needs a type and names', () => {
    expect(Object.keys(validateType(newModel())).sort()).toEqual(['customerId', 'domain', 'name', 'type'])
    expect(validateType(filled())).toEqual({})
  })
  it('workload ranges', () => {
    const m = filled(); m.concurrentUsers = '500'
    expect(validateWorkload(m).concurrentUsers).toBeTruthy()
    m.concurrentUsers = '50'; m.growthPct = 600
    expect(Object.keys(validateWorkload(m))).toEqual(['growthPct'])
  })
  it('five steps in order', () => {
    expect(wizardSteps(() => null).map((s) => s.id)).toEqual(['type', 'workload', 'placement', 'backup', 'review'])
  })
})

describe('no provisioning from sizing', () => {
  function stub() {
    const calls: { method: string; url: string }[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ method: init.method ?? 'GET', url })
      return new Response(JSON.stringify(url.endsWith('/deployments/size') ? response() : { plan_hash: 'x', vms: [] }), { status: 200 })
    }))
    return calls
  }
  it('regenerate only calls the dry-run size endpoint', async () => {
    const calls = stub()
    const got: (SizeResponse | null)[] = []
    const s = createSizer((r) => got.push(r))
    await s.regenerate(buildSizeRequest(filled(), null))
    await s.regenerate(buildSizeRequest(filled(), null))
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual(['POST /api/v1/deployments/size', 'POST /api/v1/deployments/size'])
    expect(calls.some((c) => c.url.includes('/plans'))).toBe(false)
    expect(got[1]?.vms?.length).toBe(3)
  })
  it('debounces: rapid edits produce one call with the latest request; stale responses are dropped', async () => {
    vi.useFakeTimers()
    const seen: string[] = []
    const size = vi.fn(async (r: { workload: { users: number } }) => response({ deployment_type: 'production', services: [String(r.workload.users)] }))
    const s = createSizer((r) => seen.push(r!.services[0]), { delay: 300, size: size as never })
    const m = filled()
    for (const u of [10, 20, 30]) { m.users = u; s.schedule(buildSizeRequest(m, null)) }
    await vi.advanceTimersByTimeAsync(350)
    expect(size).toHaveBeenCalledTimes(1)
    expect(seen).toEqual(['30'])
  })
  it('plan dry run posts plan_input to /deployments/plan, not /plans', async () => {
    const calls = stub()
    await sizingApi.plan({ profile: 'custom' })
    expect(calls).toEqual([{ method: 'POST', url: '/api/v1/deployments/plan' }])
  })
})

describe('resize plan', () => {
  const rr = (over: Partial<NonNullable<ResizeResponse['proposed_change']>> = {}): ResizeResponse => ({
    deployment_id: 'acme-prod', window: '7d', writes: 'none',
    recommendations: [
      { kind: 'increase_resources', vm: 'acme-prod-gw', from: { memory_mb: 4096 }, to: { memory_mb: 6144 }, requires_downtime: true, requires_data_migration: false, automatic: false, message: 'memory peak 92%' },
      { kind: 'upgrade_ha', available: false, why_not: 'no replication', requires_downtime: false, requires_data_migration: true, message: 'HA' },
    ],
    proposed_change: { changes: { sizing: {} }, plan_hash: 'p'.repeat(64), executable: true, errors: [], diff: { disruptive_steps: ['vm.stop:x'] }, requires_downtime: true, requires_data_migration: false,
      submit_as: { action: 'deployment.change', params: { deployment_id: 'acme-prod', changes: { sizing: {} }, plan_hash: 'p'.repeat(64) } }, ...over },
  })
  it('rows carry downtime / migration flags', () => {
    const rows = recommendationRows(rr())
    expect(rows[0]).toMatchObject({ title: 'Increase resources', vm: 'acme-prod-gw', from: 'memory_mb 4096', to: 'memory_mb 6144', downtime: true, migration: false })
    expect(rows[1]).toMatchObject({ title: 'High availability', migration: true, message: 'HA (no replication)' })
  })
  it('disruptive proposals need an explicit override before submit; params are the API submit_as', () => {
    const r = rr()
    expect(needsMaintenance(r)).toBe(true)
    expect(canSubmitChange(r, false)).toBe(false)
    expect(canSubmitChange(r, true)).toBe(true)
    expect(changeParams(r, true)).toEqual({ ...r.proposed_change!.submit_as.params, maintenance: 'override' })
    const calm = rr({ requires_downtime: false, diff: {} })
    expect(needsMaintenance(calm)).toBe(false)
    expect(changeParams(calm, false)).toEqual(calm.proposed_change!.submit_as.params)
    expect(canSubmitChange(rr({ executable: false }), true)).toBe(false)
    expect(canSubmitChange({ ...r, proposed_change: null }, true)).toBe(false)
  })
  it('re-run sizing posts only to resize-plan', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => { calls.push(`${init.method} ${url} ${init.body}`); return new Response(JSON.stringify(rr()), { status: 200 }) }))
    await resizeApi.resizePlan('acme-prod', '24h')
    expect(calls).toEqual(['POST /api/v1/deployments/acme-prod/resize-plan {"window":"24h"}'])
  })
})
