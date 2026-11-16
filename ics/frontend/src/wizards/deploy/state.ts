// New-deployment wizard: state, validation, request builder (POST /deployments/plan = backend PlanInput) and plan payload (deployment.create).
import type { DeployRequest, DeploymentPlan, PlanIssue } from '../api'
import type { Errors, StepDef } from '../kit'
import { DOMAIN_RE, intIn } from '../kit'

/** Plain-language one-liners for the optional collaboration components (shown when the catalog gives no description). */
export const OPTIONAL_HELP: Record<string, string> = {
  chat: 'Team chat (Matrix). Sign-in only through your company directory; no extra passwords.',
  meetings: 'Video meetings (Jitsi). Only signed-in people can open a room. Needs UDP port 10000 reachable by participants.',
  telephony: 'Internal phone system with a browser softphone. Has no outside phone line and cannot place emergency calls.',
}
export const optionalHelp = (id: string, catalogText?: string): string => catalogText || OPTIONAL_HELP[id] || ''

export const PROFILE_ORDER = ['lab', 'small', 'medium', 'large', 'ha', 'msp-multi', 'dedicated', 'custom']
/** Backend slug rule for customer_id / deployment_id (PlanInput). */
export const DEPLOY_SLUG_RE = /^[a-z0-9][a-z0-9-]{1,30}$/
const POOL_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/
const BRIDGE_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,15}$/

export interface DeployModel {
  profile: string
  /** Optional components the chosen profile offers, and which of them are switched on. */
  optionalAvailable: string[]
  optional: string[]
  /** Opt-in ports switched on ('chat:federation'); only sent while their component is enabled. */
  federation: boolean
  customerId: string
  /** deployment_id: names the VMs and the ownership tag `ou-deployment-<id>`. */
  name: string
  users: number
  tenants: number
  domain: string
  /** Registered endpoint NAME (the backend resolves the inventory by name). */
  endpoint: string
  pool: string
  storage: string
  bridge: string
  vlan: string
  osImage: string
  /** Empty = the profile's own retention. */
  retentionDays: string
  /** The plan the user is reviewing, and the request it was computed from (to detect stale previews). */
  plan: DeploymentPlan | null
  planKey: string | null
  confirmed: boolean
}

export function newDeployModel(): DeployModel {
  return {
    profile: '', optionalAvailable: [], optional: [], federation: false, customerId: '', name: '', users: 25, tenants: 1, domain: '', endpoint: '', pool: '', storage: '',
    bridge: '', vlan: '', osImage: '', retentionDays: '', plan: null, planKey: null, confirmed: false,
  }
}

export function buildRequest(m: DeployModel): DeployRequest {
  const r: DeployRequest = {
    customer_id: m.customerId.trim(),
    deployment_id: m.name.trim(),
    profile: m.profile,
    users: m.users,
    tenants: m.tenants,
    domain: m.domain.trim().toLowerCase(),
    endpoint: m.endpoint,
    pool: m.pool,
    bridge: m.bridge,
    vlan: m.vlan.trim() ? Number(m.vlan) : null,
    optional: Object.fromEntries([...m.optionalAvailable].sort().map((c) => [c, m.optional.includes(c)])),
  }
  if (m.federation && m.optional.includes('chat')) r.enabled_ports = ['chat:federation']
  if (m.storage) r.storage = m.storage
  if (m.osImage) r.os_image = m.osImage
  if (m.retentionDays.trim()) r.backup_retention_days = Number(m.retentionDays)
  return r
}
export const requestKey = (m: DeployModel) => JSON.stringify(buildRequest(m))

export function validateProfile(m: DeployModel): Errors { return m.profile ? {} : { profile: 'Choose a profile to continue.' } }
export function validateSizing(m: DeployModel): Errors {
  const e: Errors = {}
  if (!DEPLOY_SLUG_RE.test(m.customerId.trim())) e.customerId = 'Lower-case letters, digits and "-" (2-31 characters), starting with a letter or digit.'
  if (!DEPLOY_SLUG_RE.test(m.name.trim())) e.name = 'Lower-case letters, digits and "-" (2-31 characters), starting with a letter or digit.'
  if (!DOMAIN_RE.test(m.domain.trim())) e.domain = 'Enter the customer domain, for example your-company.tld.'
  if (!intIn(m.users, 1, 100000)) e.users = 'Whole number of users per tenant, 1-100000.'
  if (!intIn(m.tenants, 1, 50)) e.tenants = 'Whole number of tenants, 1-50.'
  return e
}
export function validatePlacement(m: DeployModel): Errors {
  const e: Errors = {}
  if (!m.endpoint) e.endpoint = 'Choose the infrastructure endpoint to deploy onto.'
  if (!POOL_RE.test(m.pool)) e.pool = 'Choose the resource pool the endpoint allows ICS to create guests in.'
  if (!m.storage) e.storage = 'Choose a storage for VM disks.'
  if (!BRIDGE_RE.test(m.bridge)) e.bridge = 'Choose a bridge.'
  if (m.vlan.trim() && !(/^\d+$/.test(m.vlan.trim()) && intIn(Number(m.vlan), 1, 4094))) e.vlan = 'VLAN tag must be 1-4094, or empty.'
  return e
}
export function validateOptions(m: DeployModel): Errors {
  const e: Errors = {}
  if (m.retentionDays.trim() && !(/^\d+$/.test(m.retentionDays.trim()) && intIn(Number(m.retentionDays), 1, 3650))) e.retentionDays = 'Retention is 1-3650 days, or empty for the profile default.'
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
