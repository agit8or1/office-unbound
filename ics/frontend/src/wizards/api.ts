// Typed client for the endpoints wizards use (ADR-0009 section 7). Wizards are front ends to POST /plans: every mutation goes through submitPlan().
// A 404 on a read endpoint means "backend not available" and is surfaced as state 'unavailable' (never replaced with fake data).
//
// The backend is authoritative for every shape here: this file maps the real responses (ics/deploy/api.py, ics/inventory/api.py) to the
// small view models the wizards render, and the wizards' state builders produce the real request bodies (PlanInput, ChangeSet, ...).
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

type Raw = Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
const GIB = 1024 ** 3
const gib = (bytes: unknown): number => (typeof bytes === 'number' ? Math.round((bytes / GIB) * 100) / 100 : 0)

// ---- setup (POST /setup/probe, GET /setup/state) ----
export type TrustMode = 'fingerprint' | 'ca'
/** Inventory credential (read-only, PVEAuditor) plus an optional second, pool-scoped provision credential (ADR-0002 section 2). */
export interface ProbeRequest {
  base_url: string
  token_id: string
  token_secret: string
  fingerprint_sha256?: string
  ca_pem?: string
  provision_token_id?: string
  provision_token_secret?: string
  allowed_pools?: string[]
  allowed_storage?: string[]
  allowed_networks?: string[]
}
export interface MissingPrivilege { path: string; privilege: string }
/** `unnecessary`: privileges the token holds that ICS never uses (least privilege), e.g. VM.Console. */
export interface CapabilityResult { ok: boolean; missing: MissingPrivilege[]; unnecessary?: MissingPrivilege[]; fix_commands?: string[] }
/** `managed: false` = the token has no Sys.Audit on that node; capacity is then unknown (null), never zero. */
export interface DiscNode { name: string; status: string; managed?: boolean; cpu_total: number | null; cpu_used: number | null; mem_total_gb: number | null; mem_used_gb: number | null }
export interface DiscStorage { id: string; node: string | null; type: string; content: string[]; total_gb: number; used_gb: number; shared?: boolean }
export interface DiscNetwork { name: string; node: string | null; kind: 'bridge' | 'vlan' | 'sdn'; vlan?: number | null }
export interface DiscGuest { vmid: number; name: string; kind: 'vm' | 'lxc'; node: string; status: string; template?: boolean }
export interface Discovery { nodes: DiscNode[]; storage: DiscStorage[]; networks: DiscNetwork[]; guests: DiscGuest[]; pools?: string[]; warnings?: string[] }
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
  warnings?: string[]
  error?: string
}
export interface SetupState { has_endpoint: boolean; endpoints?: number; discovery_done?: boolean; defaults_saved?: boolean; provision_configured?: boolean; next_step?: string }

// ---- catalog ----
export interface Profile {
  id: string; label: string; description: string
  users_max?: number; vm_count?: number; min_nodes?: number; ha?: boolean; multi_tenant?: boolean; maturity?: string
  components: string[]; optional_components: string[]; default_optional: string[]
}
export interface Component { id: string; label: string; description?: string; unpinned?: boolean }
export interface OsImage { id: string; title: string }
export interface Catalog { profiles: Profile[]; components: Component[]; osImages: OsImage[] }

// ---- deployments ----
/** Body of POST /deployments/plan and `spec` of deployment.create (backend `PlanInput`). */
export interface DeployRequest {
  customer_id: string
  deployment_id: string
  profile: string
  users: number
  tenants: number
  domain: string
  endpoint: string
  pool: string
  storage?: string
  bridge: string
  vlan?: number | null
  os_image?: string
  optional: Record<string, boolean>
  /** Opt-in ports that are closed by default, 'component:port-name' (e.g. 'chat:federation'). */
  enabled_ports?: string[]
  backup_retention_days?: number
}
export interface PlanVm { name: string; role?: string; os_image: string; cores: number; memory_mb: number; disks: { name: string; size_gb: number; storage: string }[]; nics: { bridge: string; vlan: number | null }[]; node?: string }
export interface PlanContainer { name: string; vm: string; image: string; digest?: string }
export interface PlanService { name: string; component?: string; vm: string; package?: string; version?: string }
export interface PlanStep { id: string; label: string; depends_on?: string[]; disruptive?: boolean }
export interface PlanPort { vm: string; port: number; proto: string; from: string; purpose: string }
export interface CapacityLine { scope: 'node' | 'storage'; id: string; text: string }
export interface PlanIssue { code?: string; message: string }
export interface DeploymentPlan {
  plan_hash: string
  executable: boolean
  vms: PlanVm[]; containers: PlanContainer[]; services: PlanService[]
  steps: PlanStep[]; ports: PlanPort[]
  dns: { name: string; type: string; value: string }[]
  backups: { vm: string; component: string; schedule: string; retention_days: number }[]
  checks: { name: string; kind: string; target: string }[]
  consumption: { vms: number; cores: number; memory_mb: number; disk_gb: number; est_seconds: number }
  capacity: CapacityLine[]
  warnings: PlanIssue[]; errors: PlanIssue[]
}

export interface Environment { id: string; name: string; profile: string; status: string }
export interface EnvResource { logical_name: string; kind: 'vm' | 'container' | 'service' | 'volume' | 'dns' | 'check'; state?: string }
/** `changes` of deployment.change / changes/preview (backend `ChangeSet`); only the fields the backend can express exist. */
export interface ChangeSpec {
  users?: number; tenants?: number; profile?: string; optional?: Record<string, boolean>; backup_retention_days?: number; allowed_nodes?: string[]
}
export interface DiffRow { resource: string; field: string; current: string | number | null; proposed: string | number | null }
export interface ChangePreview {
  plan_hash: string
  executable: boolean
  diff: DiffRow[]
  added: string[]; removed: string[]
  capacity: CapacityLine[]
  capacityImpact: { vms: number; cores: number; memory_mb: number; disk_gb: number }
  downtime: { seconds: number; steps: string[] }
  risk: 'normal' | 'high'
  riskReasons: string[]
  requires_snapshot: boolean
  requires_maintenance: boolean
  warnings: PlanIssue[]; errors: PlanIssue[]
}
export interface JobStep { seq: number; step_key: string; kind: string; target: string; op: string; status: 'pending' | 'running' | 'succeeded' | 'failed' | 'cancelled' | 'skipped'; progress?: number; attempts?: number; log_excerpt?: string | null; error_message?: string | null; error_explanation?: string | null }

// ---- mappers: backend -> view models ----
const comps = (vms: Raw[]) => [...new Set(vms.flatMap((v) => (v.components as string[]) ?? []))]

export function mapProfile(p: Raw): Profile {
  return {
    id: p.name, label: p.title, description: p.description, users_max: p.max_users, vm_count: (p.vms ?? []).length, min_nodes: p.min_nodes, ha: !!p.ha,
    multi_tenant: p.tenancy === 'multi', maturity: p.maturity, components: comps(p.vms ?? []),
    optional_components: p.optional_components ?? [], default_optional: p.default_optional ?? [],
  }
}
export const mapComponent = (c: Raw): Component => ({ id: c.name, label: c.title, description: c.description, unpinned: !!(c.unpinned_artifacts && c.unpinned_artifacts.length) })

const issues = (xs: Raw[] | undefined): PlanIssue[] => (xs ?? []).map((x) => ({ code: x.code, message: String(x.message ?? x.code ?? '') }))

function capacityLines(c: Raw | undefined): CapacityLine[] {
  const out: CapacityLine[] = []
  for (const n of c?.nodes ?? []) {
    out.push({ scope: 'node', id: n.name, text: `${gib((n.memory_free_mb ?? 0) * 1024 * 1024)} GiB memory and ${n.vcpu_free} vCPU free after this plan; ${n.vms_placed} VM(s) placed here` })
  }
  for (const s of c?.storage ?? []) out.push({ scope: 'storage', id: s.name, text: `${s.avail_after_gb} GiB free after this plan` })
  return out
}

export function mapPlan(p: Raw): DeploymentPlan {
  return {
    plan_hash: p.plan_hash,
    executable: !!p.executable,
    vms: (p.vms ?? []).map((v: Raw) => ({ name: v.name, role: v.logical, os_image: v.os_image?.id ?? '', cores: v.cores, memory_mb: v.memory_mb, disks: v.disks ?? [], nics: v.nics ?? [], node: v.node })),
    containers: (p.containers ?? []).map((c: Raw) => ({ name: c.name, vm: c.vm, image: c.image, digest: c.digest })),
    services: (p.services ?? []).map((s: Raw) => ({ name: s.name, component: s.component, vm: s.vm, package: s.package, version: s.version })),
    steps: (p.steps ?? []).map((s: Raw) => ({ id: s.key, label: `${String(s.op).replace(/_/g, ' ')} ${s.target}`, depends_on: s.depends_on, disruptive: s.disruptive })),
    ports: p.firewall ?? [],
    dns: (p.dns ?? []).map((d: Raw) => ({ name: d.name, type: d.type, value: d.value })),
    backups: (p.backups ?? []).map((b: Raw) => ({ vm: b.vm, component: b.component, schedule: b.schedule, retention_days: b.retention_days })),
    checks: (p.checks ?? []).map((c: Raw) => ({ name: c.name, kind: c.kind, target: `${c.host ?? ''}:${c.port}` })),
    consumption: p.consumption ?? { vms: 0, cores: 0, memory_mb: 0, disk_gb: 0, est_seconds: 0 },
    capacity: capacityLines(p.capacity),
    warnings: issues(p.warnings), errors: issues(p.errors),
  }
}

const show = (v: unknown): string | number | null => (v === null || v === undefined ? null : typeof v === 'number' || typeof v === 'string' ? v : JSON.stringify(v))
function diffRows(d: Raw): DiffRow[] {
  const rows: DiffRow[] = []
  for (const c of d.changed ?? []) for (const [field, ft] of Object.entries(c.fields ?? {}) as [string, Raw][]) {
    rows.push({ resource: `${c.kind} ${c.name}`, field, current: show(ft.from), proposed: show(ft.to) })
  }
  for (const a of d.added ?? []) rows.push({ resource: `${a.kind} ${a.name}`, field: 'resource', current: null, proposed: 'added' })
  for (const r of d.removed ?? []) rows.push({ resource: `${r.kind} ${r.name}`, field: 'resource', current: 'present', proposed: 'removed' })
  return rows
}

export function mapChangePreview(r: Raw): ChangePreview {
  const d: Raw = r.diff
  const p = mapPlan(r.plan)
  return {
    plan_hash: r.plan.plan_hash,
    executable: !!r.executable,
    diff: diffRows(d),
    added: (d.added ?? []).map((a: Raw) => `${a.kind} ${a.name}`),
    removed: (d.removed ?? []).map((a: Raw) => `${a.kind} ${a.name}`),
    capacity: p.capacity,
    capacityImpact: d.capacity_impact,
    downtime: { seconds: d.downtime_seconds ?? 0, steps: d.disruptive_steps ?? [] },
    risk: d.risk === 'high' ? 'high' : 'normal',
    riskReasons: d.risk_reasons ?? [],
    requires_snapshot: !!d.snapshot_required,
    requires_maintenance: !!d.requires_maintenance,
    warnings: p.warnings, errors: p.errors,
  }
}

/** GET /infra/{nodes,storage,networks} rows -> the same wizard shape as the probe's discovery (bytes -> GiB). */
export function mapInfra(kind: 'nodes', rows: Raw[]): DiscNode[]
export function mapInfra(kind: 'storage', rows: Raw[]): DiscStorage[]
export function mapInfra(kind: 'networks', rows: Raw[]): DiscNetwork[]
export function mapInfra(kind: 'nodes' | 'storage' | 'networks', rows: Raw[]): unknown[] {
  if (kind === 'nodes') {
    return rows.map((n): DiscNode => ({
      name: n.name, status: n.status, managed: n.managed, cpu_total: n.cpu_total, cpu_used: n.cpu_total ? Math.round(((n.cpu_pct ?? 0) / 100) * n.cpu_total * 100) / 100 : null,
      mem_total_gb: n.mem_total === null ? null : gib(n.mem_total), mem_used_gb: n.mem_used === null ? null : gib(n.mem_used),
    }))
  }
  if (kind === 'storage') {
    return rows.map((s) => ({ id: s.name, node: s.node || null, type: s.type, content: s.content ?? [], total_gb: gib(s.total), used_gb: gib(s.used), shared: !!s.shared }))
  }
  return rows.map((n) => ({ name: n.name, node: n.node || null, kind: n.kind === 'bridge' ? 'bridge' : 'sdn', vlan: n.tag ?? null }))
}

export const api = {
  probe: (b: ProbeRequest) => post<ProbeResult>('setup/probe', b),
  probeTls: (b: TlsProbeRequest) => post<{ tls: TlsResult }>('setup/probe', b),
  setupState: () => get<SetupState>('setup/state'),
  profiles: async () => ((await get<Raw>('catalog/profiles')).profiles as Raw[]).map(mapProfile),
  components: async () => ((await get<Raw>('catalog/components')).components as Raw[]).map(mapComponent),
  osImages: async () => ((await get<Raw>('catalog/components')).os_images as Raw[]).map((o): OsImage => ({ id: o.id, title: o.title })),
  endpoints: () => get<Endpoint[]>('endpoints'),
  infra: async (kind: 'nodes' | 'storage' | 'networks', endpointId?: string) => {
    const rows = await get<Raw[]>(`infra/${kind}${endpointId ? `?endpoint=${encodeURIComponent(endpointId)}` : ''}`)
    return mapInfra(kind as 'nodes', rows) as unknown[]
  },
  planDeployment: async (b: DeployRequest) => mapPlan(await post<Raw>('deployments/plan', b)),
  /** Deployments are addressed by slug; `id` here is the slug. */
  environments: async () => (await get<Raw[]>('deployments')).map((d): Environment => ({ id: d.slug, name: d.slug, profile: d.profile, status: d.status })),
  resources: (slug: string) => get<EnvResource[]>(`deployments/${encodeURIComponent(slug)}/resources`),
  deployment: (slug: string) => get<Raw>(`deployments/${encodeURIComponent(slug)}`),
  previewChange: async (slug: string, changes: ChangeSpec) => mapChangePreview(await post<Raw>(`deployments/${encodeURIComponent(slug)}/changes/preview`, { changes })),
  jobSteps: (id: string) => get<JobStep[]>(`jobs/${encodeURIComponent(id)}/steps`),
  /** The only mutation path: a typed action creates a plan (approval by risk happens server-side). */
  submitPlan: (action: 'endpoint.register' | 'endpoint.update' | 'deployment.create' | 'deployment.change', params: Record<string, unknown>) =>
    post<PlanCreated>('plans', { action, params }),
}
