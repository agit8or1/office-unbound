// Typed client for the endpoints wizards use (ADR-0009 section 7). Wizards are front ends to POST /plans: every mutation goes through submitPlan().
// A 404 on a read endpoint means "backend not merged / not available yet" and is surfaced as state 'unavailable' (never replaced with fake data).
import { ApiError, get, post } from '../api'
import type { Endpoint, PlanCreated } from '../api'

export { ApiError }
export type { Endpoint, PlanCreated }

export type Loaded<T> = { state: 'ok'; data: T } | { state: 'unavailable'; status: number } | { state: 'error'; message: string }

export async function load<T>(fn: () => Promise<T>): Promise<Loaded<T>> {
  try {
    return { state: 'ok', data: await fn() }
  } catch (e) {
    if (e instanceof ApiError && (e.status === 404 || e.status === 405 || e.status === 501)) return { state: 'unavailable', status: e.status }
    return { state: 'error', message: e instanceof Error ? e.message : String(e) }
  }
}

// ---- setup ----
export type TrustMode = 'fingerprint' | 'ca'
export interface ProbeRequest {
  base_url: string
  token_id: string
  token_secret: string
  fingerprint_sha256?: string
  ca_pem?: string
}
export interface MissingPrivilege { path: string; privilege: string }
/** `unnecessary`: privileges the token holds that ICS never uses (least privilege), e.g. VM.Console. */
export interface CapabilityResult { ok: boolean; missing: MissingPrivilege[]; unnecessary?: MissingPrivilege[]; fix_commands?: string[] }
export interface DiscNode { name: string; status: string; cpu_total: number; cpu_used: number; mem_total_gb: number; mem_used_gb: number }
export interface DiscStorage { id: string; node: string | null; type: string; content: string[]; total_gb: number; used_gb: number; shared?: boolean }
export interface DiscNetwork { name: string; node: string | null; kind: 'bridge' | 'vlan' | 'sdn'; vlan?: number | null }
export interface DiscGuest { vmid: number; name: string; kind: 'vm' | 'lxc'; node: string; status: string; template?: boolean }
export interface Discovery { nodes: DiscNode[]; storage: DiscStorage[]; networks: DiscNetwork[]; guests: DiscGuest[]; pools?: string[] }
/** `presented_fingerprint_sha256` is what the server actually presented, so the admin can compare it out of band BEFORE any token is sent. */
export interface TlsResult { ok: boolean; verified_by?: TrustMode; presented_fingerprint_sha256?: string; subject?: string; not_after?: string; error?: string }
/** Stage 'tls': certificate check only. No credentials are sent or accepted. */
export interface TlsProbeRequest { stage: 'tls'; base_url: string; fingerprint_sha256?: string; ca_pem?: string }
export interface ProbeResult {
  ok: boolean
  version?: string
  cluster_name?: string | null
  tls: TlsResult
  permissions: { inventory: CapabilityResult; provision: CapabilityResult }
  discovery?: Discovery
  error?: string
}
export interface SetupState { has_endpoint: boolean; mfa?: { enrolled_users: number; total_users: number; required: boolean }; alert_channels?: string[] }

// ---- catalog / deployments ----
export interface Profile {
  id: string; label: string; description: string
  users_min?: number; users_max?: number | null; vm_count?: number; ha?: boolean; multi_tenant?: boolean; components: string[]
}
export interface Component { id: string; label: string; description?: string; optional?: boolean; default_on?: boolean }
export interface DeployRequest {
  name: string
  profile: string
  users: number
  tenants: number
  availability: 'single' | 'ha'
  endpoint_id: string
  storage: string
  network: { bridge: string; vlan: number | null }
  backup: { enabled: boolean; storage: string | null; retention_days: number }
  optional_components: string[]
}
export interface PlanVm { name: string; role?: string; os_image: string; cores: number; memory_mb: number; disks: { name: string; size_gb: number; storage: string }[]; nics: { bridge: string; vlan: number | null; ip?: string }[]; node?: string }
export interface PlanContainer { name: string; vm: string; image: string; digest?: string }
export interface PlanService { name: string; component?: string; vm: string; ports?: number[] }
export interface PlanStep { id: string; label: string; depends_on?: string[] }
export interface PlanPort { service: string; port: number; proto: string; exposure: 'internal' | 'external' }
export interface CapacityLine { scope: 'node' | 'storage'; id: string; unit: 'cores' | 'GiB'; total: number; used: number; added: number }
export interface PlanIssue { code?: string; message: string; field?: string }
export interface DeploymentPlan {
  plan_hash: string
  vms: PlanVm[]; containers: PlanContainer[]; services: PlanService[]
  steps: PlanStep[]; ports: PlanPort[]
  backups: { target: string; schedule: string; retention_days: number; items?: string[] }[]
  monitoring: { check: string; target?: string }[]
  consumption: { cores: number; memory_gb: number; disk_gb: number }
  capacity: CapacityLine[]
  warnings: PlanIssue[]; errors: PlanIssue[]
}

export interface Environment { id: string; name: string; profile: string; status: string }
export interface EnvResource { logical_name: string; kind: 'vm' | 'container' | 'service' | 'volume' | 'dns' | 'check'; desired?: Record<string, unknown> }
export interface ChangeSpec { type: string; params: Record<string, string | number | boolean | null> }
export interface DiffRow { resource: string; field: string; current: string | number | null; proposed: string | number | null }
export interface ChangePreview {
  plan_hash: string
  summary?: string
  diff: DiffRow[]
  capacity: CapacityLine[]
  downtime: { seconds: number; steps?: string[] }
  dependencies: string[]
  risk: 'low' | 'medium' | 'high'
  requires_snapshot: boolean; requires_backup: boolean; requires_maintenance_window: boolean
  warnings: PlanIssue[]; errors: PlanIssue[]
}
export interface JobStep { index: number; name: string; type?: string; status: 'pending' | 'running' | 'succeeded' | 'failed' | 'skipped'; progress?: number; attempts?: number; log_excerpt?: string | null }

export const api = {
  probe: (b: ProbeRequest) => post<ProbeResult>('setup/probe', b),
  probeTls: (b: TlsProbeRequest) => post<{ tls: TlsResult }>('setup/probe', b),
  setupState: () => get<SetupState>('setup/state'),
  profiles: () => get<Profile[]>('catalog/profiles'),
  components: () => get<Component[]>('catalog/components'),
  endpoints: () => get<Endpoint[]>('endpoints'),
  infra: <T>(kind: 'nodes' | 'storage' | 'networks') => get<T[]>(`infra/${kind}`),
  planDeployment: (b: DeployRequest) => post<DeploymentPlan>('deployments/plan', b),
  environments: () => get<Environment[]>('deployments'),
  resources: (id: string) => get<EnvResource[]>(`deployments/${encodeURIComponent(id)}/resources`),
  previewChange: (id: string, change: ChangeSpec) => post<ChangePreview>(`deployments/${encodeURIComponent(id)}/changes/preview`, { change }),
  jobSteps: (id: string) => get<JobStep[]>(`jobs/${encodeURIComponent(id)}/steps`),
  /** The only mutation path: a typed action creates a plan (approval by risk happens server-side). */
  submitPlan: (action: 'endpoint.register' | 'endpoint.update' | 'deployment.create' | 'deployment.change', params: Record<string, unknown>) =>
    post<PlanCreated>('plans', { action, params }),
}
