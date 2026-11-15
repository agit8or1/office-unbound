// New-deployment wizard: state, validation, request builder (POST /deployments/plan) and plan payload (deployment.create).
import type { DeployRequest, DeploymentPlan, PlanIssue } from '../api'
import type { Errors, StepDef } from '../kit'
import { SLUG_RE, intIn } from '../kit'

export const PROFILE_ORDER = ['lab', 'small', 'medium', 'large', 'ha', 'msp-multi', 'dedicated', 'custom']

export interface DeployModel {
  profile: string
  name: string
  users: number
  tenants: number
  availability: 'single' | 'ha'
  endpointId: string
  storage: string
  bridge: string
  vlan: string
  backupEnabled: boolean
  backupStorage: string
  retentionDays: number
  optional: string[]
  /** The plan the user is reviewing, and the request it was computed from (to detect stale previews). */
  plan: DeploymentPlan | null
  planKey: string | null
  confirmed: boolean
}

export function newDeployModel(): DeployModel {
  return {
    profile: '', name: '', users: 25, tenants: 1, availability: 'single', endpointId: '', storage: '', bridge: '', vlan: '',
    backupEnabled: true, backupStorage: '', retentionDays: 14, optional: [], plan: null, planKey: null, confirmed: false,
  }
}

export function buildRequest(m: DeployModel): DeployRequest {
  return {
    name: m.name.trim(),
    profile: m.profile,
    users: m.users,
    tenants: m.tenants,
    availability: m.availability,
    endpoint_id: m.endpointId,
    storage: m.storage,
    network: { bridge: m.bridge, vlan: m.vlan.trim() ? Number(m.vlan) : null },
    backup: { enabled: m.backupEnabled, storage: m.backupEnabled ? m.backupStorage || null : null, retention_days: m.backupEnabled ? m.retentionDays : 0 },
    optional_components: [...m.optional].sort(),
  }
}
export const requestKey = (m: DeployModel) => JSON.stringify(buildRequest(m))

export function validateProfile(m: DeployModel): Errors { return m.profile ? {} : { profile: 'Choose a profile to continue.' } }
export function validateSizing(m: DeployModel): Errors {
  const e: Errors = {}
  if (!SLUG_RE.test(m.name)) e.name = 'Lower-case letters, digits, "-" or "_" (max 63), starting with a letter or digit.'
  if (!intIn(m.users, 1, 100000)) e.users = 'Whole number of users, 1-100000.'
  if (!intIn(m.tenants, 1, 1000)) e.tenants = 'Whole number of tenants, 1-1000.'
  else if (m.tenants > m.users) e.tenants = 'Tenants cannot outnumber users.'
  return e
}
export function validatePlacement(m: DeployModel): Errors {
  const e: Errors = {}
  if (!m.endpointId) e.endpointId = 'Choose the infrastructure endpoint to deploy onto.'
  if (!m.storage) e.storage = 'Choose a storage for VM disks.'
  if (!m.bridge) e.bridge = 'Choose a bridge.'
  if (m.vlan.trim() && !(/^\d+$/.test(m.vlan.trim()) && intIn(Number(m.vlan), 1, 4094))) e.vlan = 'VLAN tag must be 1-4094, or empty.'
  return e
}
export function validateOptions(m: DeployModel): Errors {
  const e: Errors = {}
  if (m.backupEnabled) {
    if (!m.backupStorage) e.backupStorage = 'Choose a backup destination, or turn backups off.'
    if (!intIn(m.retentionDays, 1, 3650)) e.retentionDays = 'Retention is 1-3650 days.'
  }
  return e
}
export const planBlocked = (p: DeploymentPlan | null): boolean => !p || p.errors.length > 0
export function validatePlan(m: DeployModel): Errors {
  if (!m.plan) return { plan: 'No plan has been generated yet.' }
  if (m.planKey !== requestKey(m)) return { plan: 'The plan is out of date. Re-plan to review the current inputs.' }
  if (planBlocked(m.plan)) return { plan: 'The plan has blocking errors. Adjust the inputs and re-plan.' }
  return {}
}

export const deploySteps: StepDef<DeployModel>[] = [
  { id: 'profile', title: 'Profile', validate: validateProfile },
  { id: 'sizing', title: 'Size', validate: validateSizing },
  { id: 'placement', title: 'Placement', validate: validatePlacement },
  { id: 'options', title: 'Backup and options', validate: validateOptions },
  { id: 'plan', title: 'Review plan' },
]

/** Exact params for POST /plans {action:'deployment.create'}: the request that produced the reviewed plan + that plan's hash. */
export function buildCreateParams(m: DeployModel): Record<string, unknown> {
  return { spec: buildRequest(m), plan_hash: m.plan!.plan_hash }
}

export function assertSubmittable(m: DeployModel, onReviewStep: boolean): void {
  if (!onReviewStep) throw new Error('Plan review step has not been reached.')
  const e = validatePlan(m)
  if (Object.keys(e).length) throw new Error(e.plan)
  if (!m.confirmed) throw new Error('Confirm the plan review before submitting.')
}

export const issueText = (i: PlanIssue) => i.message
