// "Next steps" after connecting a cluster: import the golden image, add standard alerts, deploy the first service.
// Every state is derived from API data passed in; an input that could not be loaded is `null` and makes the step "unknown" (never guessed).
import { STANDARD_RULES } from '../infra/standardAlerts'

export type StepState = 'done' | 'pending' | 'blocked' | 'unknown' | 'waiting'
export interface NextStep { id: 'image' | 'alerts' | 'deploy'; title: string; state: StepState; reason: string; to: string; action: string }

export interface NsEndpoint { id: string; name: string; enabled: boolean; provision: boolean; pools: string[] }
export interface NsRelease { release: string; verified: boolean; version?: number }
/** `GET /images/releases`: ok, or forbidden (admins only), or null (not loadable). */
export type NsReleases = { state: 'ok'; configured: boolean; releases: NsRelease[] } | { state: 'forbidden' } | null
export interface NsTemplate { vmid: number; name: string | null; pool?: string | null }
export interface NsPlan { id: string; action: string; status: string; params: Record<string, unknown> }
export interface NsJob { id: string; plan_id: string; action: string; status: string }
export interface NsCheck { kind: string; config: Record<string, unknown> }
export interface NsDeployment { endpointId: string | null; status: string }

export interface NsInput {
  ep: NsEndpoint
  releases: NsReleases
  templates: NsTemplate[] | null          // GET /infra/templates?endpoint=<id> (what the read token sees)
  catalogTemplates: string[] | null       // GET /catalog/components -> os_images[].template (what a deployment clones)
  plans: NsPlan[] | null
  jobs: NsJob[] | null
  checks: NsCheck[] | null
  deployments: NsDeployment[] | null
  canDeploy: boolean                      // the New deployment wizard is available to this user
}

const forEp = (p: NsPlan, id: string) => p.params?.endpoint_id === id || (p.params?.config as Record<string, unknown> | undefined)?.endpoint_id === id
const ACTIVE_JOB = ['queued', 'running']

function imageStep(x: NsInput): NextStep {
  const access = `/infrastructure/providers/${x.ep.id}/access`
  const s: NextStep = { id: 'image', title: 'Import the golden image', state: 'unknown', reason: '', to: '/images', action: 'Open Images' }
  if (x.templates && x.catalogTemplates) {
    const t = x.templates.find((r) => r.name && x.catalogTemplates!.includes(r.name))
    if (t) return { ...s, state: 'done', reason: `Template ${t.name} (VM ${t.vmid}) is on the cluster.` }
  }
  if (!x.ep.provision || !x.ep.pools.length) return { ...s, state: 'blocked', reason: 'Needs the Deployment permission level with a resource pool (Manage access).', to: access, action: 'Manage access' }
  if (!x.ep.enabled) return { ...s, state: 'blocked', reason: 'The integration is paused.', to: `/infrastructure/providers/${x.ep.id}`, action: 'Open the cluster' }
  if (x.plans && x.jobs) {
    const mine = x.plans.filter((p) => p.action === 'image.import' && forEp(p, x.ep.id))
    const running = x.jobs.find((j) => j.action === 'image.import' && ACTIVE_JOB.includes(j.status) && mine.some((p) => p.id === j.plan_id))
    if (running) return { ...s, state: 'waiting', reason: 'The import is running.', to: `/jobs/${running.id}`, action: 'Follow the import' }
    const pend = mine.find((p) => p.status === 'pending_approval')
    if (pend) return { ...s, state: 'waiting', reason: 'The import is waiting for approval.', to: `/plans/${pend.id}`, action: 'Open the approval' }
  }
  if (!x.templates || !x.catalogTemplates) return { ...s, reason: 'Could not read the templates on the cluster or the deployment catalog.' }
  if (!x.catalogTemplates.length) return { ...s, state: 'blocked', reason: 'The deployment catalog names no OS template.' }
  const r = x.releases
  if (!r) return { ...s, reason: 'Could not read the image releases.' }
  if (r.state === 'forbidden') return { ...s, state: 'pending', reason: 'No Office Unbound template on the cluster yet. Image releases are visible to administrators only.' }
  if (!r.configured) return { ...s, state: 'blocked', reason: 'No image releases directory is configured on this server.' }
  const ok = r.releases.filter((v) => v.verified)
  if (!ok.length) return { ...s, state: 'blocked', reason: r.releases.length ? 'No release passed signature verification.' : 'No signed image release has been copied to this server yet.' }
  return { ...s, state: 'pending', reason: `No Office Unbound template on the cluster yet. Verified release ${ok[ok.length - 1]!.release} can be imported.`,
    to: `/images?endpoint=${encodeURIComponent(x.ep.id)}`, action: 'Import the image' }
}

function alertStep(x: NsInput): NextStep {
  const s: NextStep = { id: 'alerts', title: 'Add standard alerts', state: 'unknown', reason: 'Could not read the health checks.', to: '/monitoring/infrastructure', action: 'Add standard alerts' }
  if (!x.checks) return s
  const have = STANDARD_RULES.filter((r) => x.checks!.some((c) => c.kind === 'infra' && c.config?.endpoint_id === x.ep.id && c.config?.rule === r.rule)).length
  const total = STANDARD_RULES.length
  if (have === total) return { ...s, state: 'done', reason: `All ${total} standard alert rules are set up.`, action: 'View alerts' }
  const pend = (x.plans ?? []).filter((p) => p.action === 'check.create' && p.status === 'pending_approval' && forEp(p, x.ep.id))
  if (pend.length) return { ...s, state: 'waiting', reason: `${pend.length} alert rule(s) are waiting for approval.`, to: pend.length === 1 ? `/plans/${pend[0]!.id}` : '/plans', action: 'Open approvals' }
  return { ...s, state: 'pending', reason: have ? `${have} of ${total} standard alert rules are set up.` : 'No standard alert rules for this cluster yet.' }
}

function deployStep(x: NsInput, image: NextStep): NextStep {
  const s: NextStep = { id: 'deploy', title: 'Deploy the first service', state: 'unknown', reason: 'Could not read the deployments.', to: '/deployments/new', action: 'Start a deployment' }
  if (!x.deployments) return s
  const all = x.deployments.filter((d) => d.endpointId === x.ep.id)
  const mine = all.filter((d) => !['failed', 'removed', 'deleted'].includes(d.status))
  if (mine.length) return { ...s, state: 'done', reason: `${mine.length} deployment(s) on this cluster.`, to: '/deployments', action: 'Open deployments' }
  if (all.length) return { ...s, state: 'blocked', reason: `The deployment on this cluster ${all[0]!.status === 'failed' ? 'failed' : 'was removed'}. Open it to see why before starting another.`, to: '/deployments', action: 'Open deployments' }
  if (!x.canDeploy) return { ...s, state: 'blocked', reason: 'Starting a deployment needs the operator role.', to: '/deployments', action: 'Open deployments' }
  if (!x.ep.provision || !x.ep.pools.length) return { ...s, state: 'blocked', reason: 'Needs the Deployment permission level with a resource pool (Manage access).', to: `/infrastructure/providers/${x.ep.id}/access`, action: 'Manage access' }
  if (image.state === 'unknown') return { ...s, reason: 'Deploying needs an imported template; whether one exists could not be determined.' }
  if (image.state !== 'done') return { ...s, state: 'blocked', reason: 'Deploying needs an imported template first (step 1).' }
  return { ...s, state: 'pending', reason: 'Everything needed is ready: pick a size and review the plan.' }
}

export function nextSteps(x: NsInput): NextStep[] {
  const image = imageStep(x)
  return [image, alertStep(x), deployStep(x, image)]
}

/** The step the primary button continues into: the first one that is actionable now (pending or waiting), else null. */
export function primaryStep(steps: NextStep[]): NextStep | null {
  return steps.find((s) => s.state === 'pending' || s.state === 'waiting') ?? null
}

export const STATE_LABEL: Record<StepState, string> = { done: 'Done', pending: 'To do', waiting: 'In progress', blocked: 'Blocked', unknown: 'Unknown' }
export const STATE_TONE: Record<StepState, 'ok' | 'warn' | 'bad' | 'idle' | 'info'> = { done: 'ok', pending: 'info', waiting: 'warn', blocked: 'bad', unknown: 'idle' }

/** Overview "Virtual machines" sub-text from GET /infra/summary guest_visibility (null = not reported by this server). */
export function guestVisibilityNote(v: { guest_visibility?: string; guest_visibility_limited?: { endpoint_id: string; name: string }[] } | null | undefined):
  { text: string; to: string } | null {
  if (!v || v.guest_visibility !== 'own_only') return null
  const l = v.guest_visibility_limited ?? []
  return { text: "Only Office Unbound's guests are visible. Enable whole-cluster read-only monitoring to see all.",
    to: l.length === 1 ? `/infrastructure/providers/${l[0]!.endpoint_id}/access` : '/infrastructure/providers' }
}
