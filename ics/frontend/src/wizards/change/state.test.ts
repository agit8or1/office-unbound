import { describe, expect, it } from 'vitest'
import type { ChangePreview } from '../api'
import { CHANGE_TYPES, applyDefaults, assertSubmittable, buildChange, buildChangeParams, changeKey, newChangeModel, validateDetails, validateReview } from './state'
import type { ChangeModel } from './state'

const preview = (over: Partial<ChangePreview> = {}): ChangePreview => ({
  plan_hash: 'sha256:p1', diff: [], capacity: [], downtime: { seconds: 0 }, dependencies: [], risk: 'low',
  requires_snapshot: false, requires_backup: false, requires_maintenance_window: false, warnings: [], errors: [], ...over,
})
function model(type = 'resize_ram', values: ChangeModel['values'] = { vm: 'acme-core', memory_gb: 16 }): ChangeModel {
  const m = newChangeModel(); m.envId = 'env-1'; m.type = type; applyDefaults(m); Object.assign(m.values, values); return m
}

describe('change catalog', () => {
  it('covers every change type required by the spec', () => {
    expect(CHANGE_TYPES.map((t) => t.id).sort()).toEqual(['add_service', 'add_vm', 'backup_policy', 'change_network', 'change_version', 'expand_storage', 'monitoring_policy', 'move_workload', 'remove_service', 'resize_cpu', 'resize_ram', 'scale'].sort())
  })
  it('validates details per type', () => {
    expect(validateDetails(model('resize_ram', { vm: '', memory_gb: 0 }))).toMatchObject({ vm: expect.any(String), memory_gb: expect.any(String) })
    expect(validateDetails(model())).toEqual({})
    expect(validateDetails(model('change_network', { vm: 'v', bridge: 'vmbr1' }))).toEqual({}) // vlan optional
    expect(validateDetails(model('expand_storage', { vm: 'v', disk: 'Bad Disk', new_size_gb: 10 })).disk).toBeTruthy()
  })
})

describe('change payloads', () => {
  it('POST changes/preview change spec is typed (numbers as numbers, optional blank = null)', () => {
    expect(buildChange(model())).toEqual({ type: 'resize_ram', params: { vm: 'acme-core', memory_gb: 16 } })
    expect(buildChange(model('change_network', { vm: 'v', bridge: 'vmbr1', vlan: '' }))).toEqual({ type: 'change_network', params: { vm: 'v', bridge: 'vmbr1', vlan: null } })
    expect(buildChange(model('move_workload', { vm: 'v', target_node: 'pve-b' })).params).toEqual({ vm: 'v', target_node: 'pve-b', online: true })
  })
  it('deployment.change params carry the previewed hash and the window or override', () => {
    const m = model(); m.preview = preview({ requires_maintenance_window: true }); m.previewKey = changeKey(m); m.maintenanceWindow = '2026-11-21T22:00'
    expect(buildChangeParams(m)).toEqual({ deployment_id: 'env-1', change: { type: 'resize_ram', params: { vm: 'acme-core', memory_gb: 16 } }, plan_hash: 'sha256:p1', maintenance_window: '2026-11-21T22:00', override: false })
    m.maintenanceWindow = ''; m.override = true
    expect(buildChangeParams(m)).toMatchObject({ maintenance_window: null, override: true })
    const low = model(); low.preview = preview(); low.override = true
    expect(buildChangeParams(low)).toMatchObject({ maintenance_window: null, override: false })
  })
})

describe('nothing is submitted without the review step', () => {
  it('requires review step, a fresh error-free preview, a window or override when disruptive, and confirmation', () => {
    const m = model()
    expect(() => assertSubmittable(m, false)).toThrow(/review step/i)
    expect(() => assertSubmittable(m, true)).toThrow(/No impact preview/)
    m.preview = preview({ requires_maintenance_window: true }); m.previewKey = changeKey(m)
    expect(validateReview(m).window).toBeTruthy()
    m.maintenanceWindow = '2026-11-21T22:00'
    expect(() => assertSubmittable(m, true)).toThrow(/Confirm/)
    m.confirmed = true
    expect(() => assertSubmittable(m, true)).not.toThrow()
    m.values.memory_gb = 32 // edit => stale preview
    expect(() => assertSubmittable(m, true)).toThrow(/out of date/)
    const err = model(); err.preview = preview({ errors: [{ message: 'no capacity' }] }); err.previewKey = changeKey(err); err.confirmed = true
    expect(() => assertSubmittable(err, true)).toThrow(/blocking/)
  })
})
