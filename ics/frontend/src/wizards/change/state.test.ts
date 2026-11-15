import { describe, expect, it } from 'vitest'
import type { ChangePreview } from '../api'
import { CHANGE_TYPES, PLANNED_CHANGES, applyDefaults, assertSubmittable, buildChange, buildChangeParams, changeKey, newChangeModel, validateDetails, validateReview } from './state'
import type { ChangeModel } from './state'

const preview = (over: Partial<ChangePreview> = {}): ChangePreview => ({
  plan_hash: 'b'.repeat(64), executable: true, diff: [], added: [], removed: [], capacity: [], capacityImpact: { vms: 0, cores: 0, memory_mb: 0, disk_gb: 0 },
  downtime: { seconds: 0, steps: [] }, risk: 'normal', riskReasons: [], requires_snapshot: false, requires_maintenance: false, warnings: [], errors: [], ...over,
})
function model(type = 'users', values: ChangeModel['values'] = { users: 80 }): ChangeModel {
  const m = newChangeModel(); m.envId = 'prod'; m.type = type; applyDefaults(m); Object.assign(m.values, values); return m
}

describe('change catalog', () => {
  it('offers only what the backend ChangeSet can express; the rest is listed as Planned', () => {
    expect(CHANGE_TYPES.map((t) => t.id).sort()).toEqual(['backup_retention', 'nodes', 'optional', 'profile', 'tenants', 'users'])
    expect(PLANNED_CHANGES.length).toBeGreaterThan(0)
  })
  it('validates details per type', () => {
    expect(validateDetails(model('users', { users: 0 })).users).toBeTruthy()
    expect(validateDetails(model())).toEqual({})
    expect(validateDetails(model('nodes', { allowed_nodes: 'pve1, pve2' }))).toEqual({})
    expect(validateDetails(model('nodes', { allowed_nodes: 'bad node!' })).allowed_nodes).toBeTruthy()
    expect(validateDetails(model('optional', { component: '' })).component).toBeTruthy()
  })
})

describe('change payloads', () => {
  it('the preview body is the backend ChangeSet (typed, one field per change)', () => {
    expect(buildChange(model())).toEqual({ users: 80 })
    expect(buildChange(model('tenants', { tenants: 3 }))).toEqual({ tenants: 3 })
    expect(buildChange(model('profile', { profile: 'medium' }))).toEqual({ profile: 'medium' })
    expect(buildChange(model('optional', { component: 'office', enabled: false }))).toEqual({ optional: { office: false } })
    expect(buildChange(model('backup_retention', { backup_retention_days: 30 }))).toEqual({ backup_retention_days: 30 })
    expect(buildChange(model('nodes', { allowed_nodes: 'pve1, pve2' }))).toEqual({ allowed_nodes: ['pve1', 'pve2'] })
  })
  it('deployment.change params: slug, changes, hash; maintenance window by id or an explicit override only when disruptive', () => {
    const m = model(); m.preview = preview({ requires_maintenance: true }); m.previewKey = changeKey(m)
    m.maintenanceWindowId = '3f1d6a52-0000-4000-8000-000000000001'
    expect(buildChangeParams(m)).toEqual({ deployment_id: 'prod', changes: { users: 80 }, plan_hash: 'b'.repeat(64), maintenance: 'window', maintenance_window_id: '3f1d6a52-0000-4000-8000-000000000001' })
    m.maintenanceWindowId = ''; m.override = true
    expect(buildChangeParams(m)).toEqual({ deployment_id: 'prod', changes: { users: 80 }, plan_hash: 'b'.repeat(64), maintenance: 'override' })
    const calm = model(); calm.preview = preview(); calm.override = true; calm.maintenanceWindowId = 'x'
    expect(buildChangeParams(calm)).toEqual({ deployment_id: 'prod', changes: { users: 80 }, plan_hash: 'b'.repeat(64) })
  })
})

describe('nothing is submitted without the review step', () => {
  it('requires review step, a fresh error-free preview, a window or override when disruptive, and confirmation', () => {
    const m = model()
    expect(() => assertSubmittable(m, false)).toThrow(/review step/i)
    expect(() => assertSubmittable(m, true)).toThrow(/No impact preview/)
    m.preview = preview({ requires_maintenance: true }); m.previewKey = changeKey(m)
    expect(validateReview(m).window).toBeTruthy()
    m.maintenanceWindowId = '3f1d6a52-0000-4000-8000-000000000001'
    expect(() => assertSubmittable(m, true)).toThrow(/Confirm/)
    m.confirmed = true
    expect(() => assertSubmittable(m, true)).not.toThrow()
    m.values.users = 200 // edit => stale preview
    expect(() => assertSubmittable(m, true)).toThrow(/out of date/)
    const err = model(); err.preview = preview({ errors: [{ message: 'no capacity' }] }); err.previewKey = changeKey(err); err.confirmed = true
    expect(() => assertSubmittable(err, true)).toThrow(/blocking/)
    const nope = model(); nope.preview = preview({ executable: false }); nope.previewKey = changeKey(nope); nope.confirmed = true
    expect(() => assertSubmittable(nope, true)).toThrow(/cannot be executed/)
  })
})
