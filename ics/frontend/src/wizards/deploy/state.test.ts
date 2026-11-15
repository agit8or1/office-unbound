import { describe, expect, it } from 'vitest'
import type { DeploymentPlan } from '../api'
import { assertSubmittable, buildCreateParams, buildRequest, newDeployModel, requestKey, validateOptions, validatePlacement, validatePlan, validateSizing } from './state'
import type { DeployModel } from './state'

const plan = (over: Partial<DeploymentPlan> = {}): DeploymentPlan => ({
  plan_hash: 'a'.repeat(64), executable: true, vms: [], containers: [], services: [], steps: [], ports: [], dns: [], backups: [], checks: [],
  consumption: { vms: 3, cores: 4, memory_mb: 8192, disk_gb: 80, est_seconds: 600 }, capacity: [], warnings: [], errors: [], ...over,
})
function model(): DeployModel {
  const m = newDeployModel()
  Object.assign(m, {
    profile: 'medium', optionalAvailable: ['office', 'monitoring-agent'], optional: ['office'], customerId: 'acme', name: 'prod', users: 120, tenants: 2,
    domain: 'Acme.Example', endpoint: 'lab', pool: 'acme', storage: 'local-lvm', bridge: 'vmbr0', vlan: '120', retentionDays: '30',
  })
  return m
}

describe('deployment wizard validation', () => {
  it('validates identity, sizing, placement and options against the backend rules', () => {
    const m = newDeployModel()
    expect(Object.keys(validateSizing({ ...m, customerId: 'Bad Name', name: 'x', domain: 'nodot', users: 0, tenants: 99 })).sort()).toEqual(['customerId', 'domain', 'name', 'tenants', 'users'])
    expect(validateSizing({ ...model() })).toEqual({})
    expect(Object.keys(validatePlacement(m)).sort()).toEqual(['bridge', 'endpoint', 'pool', 'storage'])
    expect(validateOptions({ ...m, retentionDays: 'abc' }).retentionDays).toBeTruthy()
    expect(validateOptions({ ...m, retentionDays: '' })).toEqual({})
  })
})

describe('deployment payloads', () => {
  it('POST /deployments/plan body is the backend PlanInput, exact and deterministic', () => {
    const m = model()
    expect(buildRequest(m)).toEqual({
      customer_id: 'acme', deployment_id: 'prod', profile: 'medium', users: 120, tenants: 2, domain: 'acme.example', endpoint: 'lab', pool: 'acme', storage: 'local-lvm',
      bridge: 'vmbr0', vlan: 120, optional: { 'monitoring-agent': false, office: true }, backup_retention_days: 30,
    })
    const m2 = model(); m2.optionalAvailable = ['monitoring-agent', 'office']
    expect(requestKey(m)).toBe(requestKey(m2))
  })
  it('optional fields are omitted when empty (profile defaults apply)', () => {
    const m = model(); m.storage = ''; m.retentionDays = ''; m.vlan = ''
    const r = buildRequest(m)
    expect(r).not.toHaveProperty('storage'); expect(r).not.toHaveProperty('backup_retention_days'); expect(r.vlan).toBeNull()
  })
  it('deployment.create params are the reviewed spec plus the reviewed plan hash', () => {
    const m = model(); m.plan = plan(); m.planKey = requestKey(m)
    expect(JSON.parse(JSON.stringify(buildCreateParams(m)))).toEqual({ spec: buildRequest(m), plan_hash: 'a'.repeat(64) })
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
