// Change wizard: change-type catalog, validation, preview request and deployment.change payload.
import type { ChangePreview, ChangeSpec } from '../api'
import type { Errors, StepDef } from '../kit'
import { intIn } from '../kit'

export type FieldValue = string | number | boolean
export interface FieldDef {
  key: string
  label: string
  kind: 'number' | 'text' | 'bool' | 'resource' | 'node' | 'network' | 'component' | 'choice'
  resourceKind?: 'vm' | 'service'
  min?: number; max?: number; unit?: string
  optional?: boolean
  pattern?: RegExp; patternHint?: string
  choices?: { value: string; label: string }[]
  default?: FieldValue
  hint?: string
}
export interface ChangeType { id: string; label: string; description: string; fields: FieldDef[] }

const VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/
export const CHANGE_TYPES: ChangeType[] = [
  { id: 'resize_cpu', label: 'Resize CPU', description: 'Change the vCPU count of a VM.', fields: [
    { key: 'vm', label: 'Virtual machine', kind: 'resource', resourceKind: 'vm' },
    { key: 'cores', label: 'New vCPU count', kind: 'number', min: 1, max: 256 }] },
  { id: 'resize_ram', label: 'Resize RAM', description: 'Change the memory of a VM.', fields: [
    { key: 'vm', label: 'Virtual machine', kind: 'resource', resourceKind: 'vm' },
    { key: 'memory_gb', label: 'New memory', kind: 'number', min: 1, max: 4096, unit: 'GiB' }] },
  { id: 'expand_storage', label: 'Expand storage', description: 'Grow a VM disk. Disks can only grow.', fields: [
    { key: 'vm', label: 'Virtual machine', kind: 'resource', resourceKind: 'vm' },
    { key: 'disk', label: 'Disk', kind: 'text', pattern: /^[a-z][a-z0-9_-]{0,31}$/, patternHint: 'Disk name such as scsi1 or data.' },
    { key: 'new_size_gb', label: 'New size', kind: 'number', min: 1, max: 1048576, unit: 'GiB' }] },
  { id: 'add_service', label: 'Add service', description: 'Add a catalog component to an existing VM.', fields: [
    { key: 'component', label: 'Component', kind: 'component' },
    { key: 'vm', label: 'Target VM', kind: 'resource', resourceKind: 'vm' }] },
  { id: 'remove_service', label: 'Remove service', description: 'Remove a service. Its data is backed up first.', fields: [
    { key: 'service', label: 'Service', kind: 'resource', resourceKind: 'service' }] },
  { id: 'add_vm', label: 'Add VM', description: 'Add another VM to the environment.', fields: [
    { key: 'role', label: 'Role', kind: 'text', pattern: /^[a-z][a-z0-9-]{0,30}$/, patternHint: 'Lower-case role name, for example app or worker.' },
    { key: 'cores', label: 'vCPU', kind: 'number', min: 1, max: 256, default: 2 },
    { key: 'memory_gb', label: 'Memory', kind: 'number', min: 1, max: 4096, unit: 'GiB', default: 4 },
    { key: 'disk_gb', label: 'Disk', kind: 'number', min: 10, max: 1048576, unit: 'GiB', default: 40 }] },
  { id: 'move_workload', label: 'Move workload', description: 'Migrate a VM to another node.', fields: [
    { key: 'vm', label: 'Virtual machine', kind: 'resource', resourceKind: 'vm' },
    { key: 'target_node', label: 'Target node', kind: 'node' },
    { key: 'online', label: 'Live migration (no shutdown)', kind: 'bool', default: true }] },
  { id: 'change_network', label: 'Change network / VLAN', description: 'Move a VM to another bridge or VLAN.', fields: [
    { key: 'vm', label: 'Virtual machine', kind: 'resource', resourceKind: 'vm' },
    { key: 'bridge', label: 'Bridge', kind: 'network' },
    { key: 'vlan', label: 'VLAN tag', kind: 'number', min: 1, max: 4094, optional: true, hint: 'Empty = untagged.' }] },
  { id: 'scale', label: 'Scale service', description: 'Change the number of replicas of a service.', fields: [
    { key: 'service', label: 'Service', kind: 'resource', resourceKind: 'service' },
    { key: 'replicas', label: 'Replicas', kind: 'number', min: 1, max: 32 }] },
  { id: 'change_version', label: 'Change version / engine', description: 'Move a service to another pinned version or database engine.', fields: [
    { key: 'service', label: 'Service', kind: 'resource', resourceKind: 'service' },
    { key: 'version', label: 'Version', kind: 'text', pattern: VERSION, patternHint: 'Pinned release label such as 2.1.0.' },
    { key: 'engine', label: 'Engine', kind: 'text', optional: true, pattern: /^[a-z][a-z0-9_.-]{0,31}$/, patternHint: 'For example postgres-16.' }] },
  { id: 'backup_policy', label: 'Backup policy', description: 'Change schedule and retention.', fields: [
    { key: 'enabled', label: 'Backups enabled', kind: 'bool', default: true },
    { key: 'schedule', label: 'Schedule', kind: 'choice', choices: [{ value: 'daily', label: 'Daily' }, { value: 'weekly', label: 'Weekly' }], default: 'daily' },
    { key: 'retention_days', label: 'Retention', kind: 'number', min: 1, max: 3650, unit: 'days', default: 14 }] },
  { id: 'monitoring_policy', label: 'Monitoring policy', description: 'Change check interval and alerting.', fields: [
    { key: 'interval_seconds', label: 'Check interval', kind: 'number', min: 15, max: 3600, unit: 's', default: 60 },
    { key: 'alert_on_warning', label: 'Alert on warnings too', kind: 'bool', default: false }] },
]
export const typeById = (id: string) => CHANGE_TYPES.find((t) => t.id === id)

export interface ChangeModel {
  envId: string
  type: string
  values: Record<string, FieldValue>
  preview: ChangePreview | null
  previewKey: string | null
  maintenanceWindow: string
  override: boolean
  confirmed: boolean
}
export function newChangeModel(): ChangeModel {
  return { envId: '', type: '', values: {}, preview: null, previewKey: null, maintenanceWindow: '', override: false, confirmed: false }
}
export function applyDefaults(m: ChangeModel) {
  m.values = {}
  for (const f of typeById(m.type)?.fields ?? []) if (f.default !== undefined) m.values[f.key] = f.default
}

const isBlank = (v: FieldValue | undefined) => v === undefined || v === ''

export function buildChange(m: ChangeModel): ChangeSpec {
  const t = typeById(m.type)!
  const params: ChangeSpec['params'] = {}
  for (const f of t.fields) {
    const v = m.values[f.key]
    if (isBlank(v)) { if (f.optional) params[f.key] = null; continue }
    params[f.key] = f.kind === 'number' ? Number(v) : f.kind === 'bool' ? !!v : String(v)
  }
  return { type: m.type, params }
}
export const changeKey = (m: ChangeModel) => (m.envId && typeById(m.type) ? JSON.stringify([m.envId, buildChange(m)]) : '')

export function validateEnv(m: ChangeModel): Errors { return m.envId ? {} : { envId: 'Choose the environment to change.' } }
export function validateType(m: ChangeModel): Errors { return typeById(m.type) ? {} : { type: 'Choose what you want to change.' } }
export function validateDetails(m: ChangeModel): Errors {
  const e: Errors = {}
  for (const f of typeById(m.type)?.fields ?? []) {
    const v = m.values[f.key]
    if (f.kind === 'bool') continue
    if (isBlank(v)) { if (!f.optional) e[f.key] = `${f.label} is required.`; continue }
    if (f.kind === 'number') {
      if (!intIn(Number(v), f.min ?? 0, f.max ?? Number.MAX_SAFE_INTEGER) || typeof v === 'boolean') e[f.key] = `Enter a whole number from ${f.min} to ${f.max}${f.unit ? ' ' + f.unit : ''}.`
    } else if (f.kind === 'text' && f.pattern && !f.pattern.test(String(v))) e[f.key] = f.patternHint ?? 'Invalid value.'
  }
  return e
}

export function needsWindow(p: ChangePreview | null): boolean { return !!p?.requires_maintenance_window }
export function validateReview(m: ChangeModel): Errors {
  if (!m.preview) return { preview: 'No impact preview has been generated yet.' }
  if (m.previewKey !== changeKey(m)) return { preview: 'The preview is out of date. Refresh it to review the current inputs.' }
  if (m.preview.errors.length) return { preview: 'The preview has blocking errors. Change the inputs and preview again.' }
  if (needsWindow(m.preview) && !m.maintenanceWindow && !m.override) return { window: 'This change is disruptive: pick a maintenance window or request an explicit override.' }
  return {}
}

export const changeSteps: StepDef<ChangeModel>[] = [
  { id: 'environment', title: 'Environment', validate: validateEnv },
  { id: 'type', title: 'Change type', validate: validateType },
  { id: 'details', title: 'Details', validate: validateDetails },
  { id: 'review', title: 'Impact review' },
]

/** Exact params for POST /plans {action:'deployment.change'}. */
export function buildChangeParams(m: ChangeModel): Record<string, unknown> {
  return {
    deployment_id: m.envId,
    change: buildChange(m),
    plan_hash: m.preview!.plan_hash,
    maintenance_window: needsWindow(m.preview) && m.maintenanceWindow ? m.maintenanceWindow : null,
    override: needsWindow(m.preview) && !m.maintenanceWindow ? m.override : false,
  }
}

export function assertSubmittable(m: ChangeModel, onReviewStep: boolean): void {
  if (!onReviewStep) throw new Error('Impact review step has not been reached.')
  const e = validateReview(m)
  const first = Object.values(e)[0]
  if (first) throw new Error(first)
  if (!m.confirmed) throw new Error('Confirm the impact review before submitting.')
}
