// Change wizard: change-type catalog, validation, preview request and deployment.change payload.
// Only changes the backend can express are offered (ADR-0009: a control appears only when its action exists, otherwise it is "Planned").
// They map 1:1 onto the backend ChangeSet {users, tenants, profile, optional, backup_retention_days, allowed_nodes}.
import type { ChangePreview, ChangeSpec } from '../api'
import type { Errors, StepDef } from '../kit'
import { intIn } from '../kit'

export type FieldValue = string | number | boolean
export interface FieldDef {
  key: string
  label: string
  kind: 'number' | 'text' | 'bool' | 'profile' | 'component'
  min?: number; max?: number; unit?: string
  optional?: boolean
  pattern?: RegExp; patternHint?: string
  default?: FieldValue
  hint?: string
}
export interface ChangeType { id: string; label: string; description: string; fields: FieldDef[] }

const NODES = /^[A-Za-z0-9][A-Za-z0-9.-]{0,62}(\s*,\s*[A-Za-z0-9][A-Za-z0-9.-]{0,62})*$/
export const CHANGE_TYPES: ChangeType[] = [
  { id: 'users', label: 'Change user count', description: 'Re-size the environment for a different number of users. Resources are recomputed from the catalog formulas.', fields: [
    { key: 'users', label: 'Users per tenant', kind: 'number', min: 1, max: 100000 }] },
  { id: 'tenants', label: 'Change tenant count', description: 'Add or remove isolated tenants (multi-tenant profiles).', fields: [
    { key: 'tenants', label: 'Tenants', kind: 'number', min: 1, max: 50 }] },
  { id: 'profile', label: 'Move to another profile', description: 'Switch the layout, for example from Small to Medium.', fields: [
    { key: 'profile', label: 'Profile', kind: 'profile' }] },
  { id: 'optional', label: 'Optional component', description: 'Switch an optional component of the profile on or off.', fields: [
    { key: 'component', label: 'Component', kind: 'component' },
    { key: 'enabled', label: 'Enabled', kind: 'bool', default: true }] },
  { id: 'backup_retention', label: 'Backup retention', description: 'Change how long backups are kept (the schedule follows the profile).', fields: [
    { key: 'backup_retention_days', label: 'Retention', kind: 'number', min: 1, max: 3650, unit: 'days', default: 14 }] },
  { id: 'nodes', label: 'Restrict nodes', description: 'Limit which cluster nodes the VMs of this environment may run on.', fields: [
    { key: 'allowed_nodes', label: 'Allowed nodes', kind: 'text', pattern: NODES, patternHint: 'Comma-separated node names, for example pve1, pve2.' }] },
]
/** Change types the backend cannot plan yet: shown as "Planned", never selectable and never sent. */
export const PLANNED_CHANGES: { label: string; description: string }[] = [
  { label: 'Resize CPU / RAM of one VM', description: 'Per-VM sizing outside the catalog formulas.' },
  { label: 'Expand a single disk', description: 'Disks grow today only through the user count or profile.' },
  { label: 'Add or remove a single VM or service', description: 'Use a profile or optional component instead.' },
  { label: 'Move a workload to another node', description: 'Live and offline migration.' },
  { label: 'Change network / VLAN of an existing VM', description: '' },
  { label: 'Scale replicas, change version or database engine', description: '' },
  { label: 'Monitoring policy', description: '' },
]
export const typeById = (id: string) => CHANGE_TYPES.find((t) => t.id === id)

export interface ChangeModel {
  /** Deployment slug. */
  envId: string
  type: string
  values: Record<string, FieldValue>
  preview: ChangePreview | null
  previewKey: string | null
  /** Id of an ACTIVE maintenance window (GET /maintenance); empty = none. */
  maintenanceWindowId: string
  override: boolean
  confirmed: boolean
}
export function newChangeModel(): ChangeModel {
  return { envId: '', type: '', values: {}, preview: null, previewKey: null, maintenanceWindowId: '', override: false, confirmed: false }
}
export function applyDefaults(m: ChangeModel) {
  m.values = {}
  for (const f of typeById(m.type)?.fields ?? []) if (f.default !== undefined) m.values[f.key] = f.default
}

const isBlank = (v: FieldValue | undefined) => v === undefined || v === ''

/** The backend ChangeSet for the current inputs. */
export function buildChange(m: ChangeModel): ChangeSpec {
  const v = m.values
  switch (m.type) {
    case 'users': return { users: Number(v.users) }
    case 'tenants': return { tenants: Number(v.tenants) }
    case 'profile': return { profile: String(v.profile) }
    case 'optional': return { optional: { [String(v.component)]: !!v.enabled } }
    case 'backup_retention': return { backup_retention_days: Number(v.backup_retention_days) }
    case 'nodes': return { allowed_nodes: String(v.allowed_nodes ?? '').split(',').map((x) => x.trim()).filter(Boolean) }
    default: throw new Error('Unknown change type.')
  }
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
      if (typeof v === 'boolean' || !intIn(Number(v), f.min ?? 0, f.max ?? Number.MAX_SAFE_INTEGER)) e[f.key] = `Enter a whole number from ${f.min} to ${f.max}${f.unit ? ' ' + f.unit : ''}.`
    } else if (f.kind === 'text' && f.pattern && !f.pattern.test(String(v))) e[f.key] = f.patternHint ?? 'Invalid value.'
  }
  return e
}

export function needsWindow(p: ChangePreview | null): boolean { return !!p?.requires_maintenance }
export function validateReview(m: ChangeModel): Errors {
  if (!m.preview) return { preview: 'No impact preview has been generated yet.' }
  if (m.previewKey !== changeKey(m)) return { preview: 'The preview is out of date. Refresh it to review the current inputs.' }
  if (m.preview.errors.length) return { preview: 'The preview has blocking errors. Change the inputs and preview again.' }
  if (!m.preview.executable) return { preview: 'This change cannot be executed as planned (see the warnings).' }
  if (needsWindow(m.preview) && !m.maintenanceWindowId && !m.override) return { window: 'This change is disruptive: pick an active maintenance window or request an explicit override.' }
  return {}
}

export const changeSteps: StepDef<ChangeModel>[] = [
  { id: 'environment', title: 'Environment', validate: validateEnv },
  { id: 'type', title: 'Change type', validate: validateType },
  { id: 'details', title: 'Details', validate: validateDetails },
  { id: 'review', title: 'Impact review' },
]

/** Exact params for POST /plans {action:'deployment.change'} (backend DeploymentChange). An override makes the plan high risk (two approvers). */
export function buildChangeParams(m: ChangeModel): Record<string, unknown> {
  const p: Record<string, unknown> = { deployment_id: m.envId, changes: buildChange(m), plan_hash: m.preview!.plan_hash }
  if (needsWindow(m.preview)) {
    if (m.maintenanceWindowId) { p.maintenance = 'window'; p.maintenance_window_id = m.maintenanceWindowId }
    else if (m.override) p.maintenance = 'override'
  }
  return p
}

export function assertSubmittable(m: ChangeModel, onReviewStep: boolean): void {
  if (!onReviewStep) throw new Error('Impact review step has not been reached.')
  const e = validateReview(m)
  const first = Object.values(e)[0]
  if (first) throw new Error(first)
  if (!m.confirmed) throw new Error('Confirm the impact review before submitting.')
}
