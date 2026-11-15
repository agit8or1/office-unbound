import { describe, expect, it } from 'vitest'
import type { DeploymentPlan } from '../api'
import { assertSubmittable, buildCreateParams, buildRequest, newDeployModel, requestKey, validateOptions, validatePlacement, validatePlan, validateSizing } from './state'
import type { DeployModel } from './state'

const plan = (over: Partial<DeploymentPlan> = {}): DeploymentPlan => ({
  plan_hash: 'sha256:abc', vms: [], containers: [], services: [], steps: [], ports: [], backups: [], monitoring: [],
  consumption: { cores: 4, memory_gb: 8, disk_gb: 80 }, capacity: [], warnings: [], errors: [], ...over,
})
function model(): DeployModel {
  const m = newDeployModel()
  Object.assign(m, { profile: 'medium', name: 'acme-prod', users: 120, tenants: 2, availability: 'ha', endpointId: 'ep1', storage: 'zfs', bridge: 'vmbr0', vlan: '120', backupStorage: 'pbs', optional: ['office', 'monitoring'] })
  return m
}

describe('deployment wizard validation', () => {
  it('validates sizing, placement and options', () => {
    const m = newDeployModel()
    expect(Object.keys(validateSizing({ ...m, name: 'Bad Name', users: 0, tenants: 1 })).sort()).toEqual(['name', 'tenants', 'users'])
    expect(validateSizing({ ...m, name: 'x', users: 3, tenants: 5 }).tenants).toMatch(/outnumber/)
    expect(Object.keys(validatePlacement(m)).sort()).toEqual(['bridge', 'endpointId', 'storage'])
    expect(validateOptions({ ...m, backupEnabled: true, backupStorage: '' }).backupStorage).toBeTruthy()
    expect(validateOptions({ ...m, backupEnabled: false, backupStorage: '' })).toEqual({})
  })
})

describe('deployment payloads', () => {
  it('POST /deployments/plan body is exact and deterministic (sorted optional components)', () => {
    const m = model(); m.optional = ['monitoring', 'office']
    expect(buildRequest(m)).toEqual({
      name: 'acme-prod', profile: 'medium', users: 120, tenants: 2, availability: 'ha', endpoint_id: 'ep1', storage: 'zfs',
      network: { bridge: 'vmbr0', vlan: 120 }, backup: { enabled: true, storage: 'pbs', retention_days: 14 }, optional_components: ['monitoring', 'office'],
    })
    const m2 = model(); m2.optional = ['office', 'monitoring']
    expect(requestKey(m)).toBe(requestKey(m2))
  })
  it('backups off produces a null storage and zero retention', () => {
    const m = model(); m.backupEnabled = false
    expect(buildRequest(m).backup).toEqual({ enabled: false, storage: null, retention_days: 0 })
  })
  it('deployment.create params are the reviewed spec plus the reviewed plan hash', () => {
    const m = model(); m.plan = plan(); m.planKey = requestKey(m)
    expect(JSON.parse(JSON.stringify(buildCreateParams(m)))).toEqual({ spec: buildRequest(m), plan_hash: 'sha256:abc' })
  })
})

describe('nothing is submitted without the review step', () => {
  it('refuses when the review step was not reached, no plan, stale plan, blocking errors, or unconfirmed', () => {
    const m = model()
    expect(() => assertSubmittable(m, false)).toThrow(/review step/i)
    expect(() => assertSubmittable(m, true)).toThrow(/No plan/)
    m.plan = plan(); m.planKey = requestKey(m)
    expect(() => assertSubmittable(m, true)).toThrow(/Confirm/)
    m.confirmed = true
    expect(() => assertSubmittable(m, true)).not.toThrow()
    m.users = 500 // edit after review => stale
    expect(validatePlan(m).plan).toMatch(/out of date/)
    expect(() => assertSubmittable(m, true)).toThrow(/out of date/)
    const blocked = model(); blocked.plan = plan({ errors: [{ message: 'too big' }] }); blocked.planKey = requestKey(blocked); blocked.confirmed = true
    expect(() => assertSubmittable(blocked, true)).toThrow(/blocking/)
  })
})
