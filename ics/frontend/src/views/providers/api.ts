// Typed client for the provider screens. Reads use the real ICS endpoints; every mutation is a typed action posted to /plans
// (approval by risk, durable job, audit happen server-side). A 404/405/501 on a read means "not available on this server" and is
// reported as such, never replaced with invented data.
import { ApiError, get, post } from '../../api'
import type { PlanCreated } from '../../api'
import type {
  CredentialMeta, InfraGuest, InfraNode, InfraStorage, JobRow, PermissionsView, PlanRow, PlanPreviewOut, ProbeResult, ProviderEndpoint, TlsResult,
} from './model'

export type Loaded<T> = { state: 'ok'; data: T } | { state: 'unavailable' } | { state: 'forbidden' } | { state: 'error'; message: string }
export async function load<T>(fn: () => Promise<T>): Promise<Loaded<T>> {
  try { return { state: 'ok', data: await fn() } } catch (e) {
    if (e instanceof ApiError && [404, 405, 501].includes(e.status)) return { state: 'unavailable' }
    if (e instanceof ApiError && e.status === 403) return { state: 'forbidden' }
    return { state: 'error', message: e instanceof Error ? e.message : String(e) }
  }
}
export const msg = (e: unknown) => (e instanceof Error ? e.message : String(e))

export interface Customer { id: string; name: string; msp_owned: boolean; provisioning_mode: 'auto' | 'customer_approval' | 'monitoring_only'; extra_approvals: Record<string, number>; contact_name: string | null; contact_email: string | null; created_at: string; disabled_at: string | null }
export interface CustomerApproval { id: string; customer_id: string; plan_id: string | null; title: string; status: string; proposal_hash: string; created_at: string; submitted_at: string | null; token_expires_at: string | null; decided_at: string | null; approver_name: string | null; approver_email: string | null; approver_statement: string | null; decision_note: string | null; completed_at: string | null; proposal?: unknown }
export interface AccessEvent { seq: number; at: string; event: string; who: string | null; credential_id: string; label: string; provider: string; purpose: string | null; use: string | null }
export interface MetricOut { points: { ts: string; avg: number | null; max: number | null }[] }
export interface Summary { health: { status: string; reasons: string[] }; endpoints: { active: number; total: number }; nodes: { total: number; online: number; managed: number }; guests: { vms: number; containers: number; running: number }; templates: number; storage: { pools: number; bytes_total: number; bytes_used: number }; networks: number }

export const api = {
  endpoints: () => get<ProviderEndpoint[]>('endpoints'),
  endpoint: (id: string) => get<ProviderEndpoint>(`endpoints/${id}`),
  permissions: (id: string) => get<PermissionsView>(`providers/${id}/permissions`),
  checkPermissions: (id: string) => post<unknown>(`providers/${id}/permissions/check`),
  credentials: () => get<CredentialMeta[]>('credentials'),
  credential: (id: string) => get<CredentialMeta & { history: { at: string; event: string; actor?: string | null; detail?: string | null }[]; used_by_endpoints: string[] }>(`credentials/${id}`),
  accessReview: (id: string) => get<AccessEvent[]>(`credentials/access-review?credential_id=${id}&limit=50`),
  customers: () => get<Customer[]>('customers'),
  approvals: () => get<CustomerApproval[]>('customer-approvals'),
  approval: (id: string) => get<CustomerApproval>(`customer-approvals/${id}`),
  createApproval: (b: { customer_id: string; title: string; params: Record<string, unknown>; plan_id?: string }) => post<{ id: string }>('customer-approvals', b),
  submitApproval: (id: string, ttl_hours: number) => post<{ id: string; link_path: string; expires_at: string }>(`customer-approvals/${id}/submit`, { ttl_hours }),
  cancelApproval: (id: string) => post<unknown>(`customer-approvals/${id}/cancel`),
  summary: () => get<Summary>('infra/summary'),
  nodes: (ep: string) => get<InfraNode[]>(`infra/nodes?endpoint=${ep}`),
  storage: (ep: string) => get<InfraStorage[]>(`infra/storage?endpoint=${ep}`),
  networks: (ep: string) => get<unknown[]>(`infra/networks?endpoint=${ep}`),
  templates: (ep: string) => get<unknown[]>(`infra/templates?endpoint=${ep}`),
  guests: (ep: string) => get<InfraGuest[]>(`infra/guests?endpoint=${ep}`),
  metric: (scope: 'node' | 'storage', id: string, metric: string, range: string) => get<MetricOut>(`infra/metrics?scope=${scope}&id=${id}&metric=${metric}&range=${range}`),
  incidents: () => get<{ id: string; title: string; severity: string; status: string; opened_at: string; check_name: string }[]>('incidents?status=active&limit=50'),
  audit: (n = 40) => get<{ seq: number; at: string; action: string; actor_name: string | null; resource: string | null; resource_id: string | null }[]>(`audit?limit=${n}`),
  plans: () => get<PlanRow[]>('plans?limit=200'),
  jobs: () => get<JobRow[]>('jobs?limit=200'),
  job: (id: string) => get<JobRow>(`jobs/${id}`),
  probeTls: (b: unknown) => post<{ tls: TlsResult }>('setup/probe', b),
  probe: (b: unknown) => post<ProbeResult>('setup/probe', b),
  discover: (b: unknown) => post<unknown>('setup/probe', b),
  packageFiles: (providerId: string, packageId: string) => get<{ package_id: string; plan_hash: string; files: Record<string, string> }>(`providers/${providerId}/provisioning/packages/${packageId}?format=json`),
  /** The only mutation path. */
  submit: (action: string, params: Record<string, unknown>) => post<PlanCreated & { customer_approval_id?: string }>('plans', { action, params }),
}
export const packageUrl = (providerId: string, packageId: string, format: string) => `/api/v1/providers/${providerId}/provisioning/packages/${packageId}?format=${encodeURIComponent(format)}`

/** Watch one submitted plan until its job finishes. Resolves each state through `onUpdate`; stops when `signal.aborted`. */
export async function watchRun(created: PlanCreated, onUpdate: (plan: PlanRow | null, job: JobRow | null) => void, signal: { aborted: boolean }, intervalMs = 1500): Promise<JobRow | null> {
  let jobId = created.job_id
  for (;;) {
    if (signal.aborted) return null
    let plan: PlanRow | null = null, job: JobRow | null = null
    try {
      if (!jobId) {
        const [ps, js] = await Promise.all([api.plans(), api.jobs()])
        plan = ps.find((p) => p.id === created.plan_id) ?? null
        const j = js.find((x) => x.plan_id === created.plan_id)
        if (j) { jobId = j.id; job = j }
      } else job = await api.job(jobId)
    } catch { /* transient: keep polling */ }
    onUpdate(plan ?? ({ id: created.plan_id, status: created.status, approvals_required: created.approvals_required } as PlanRow), job)
    if (job && (job.status === 'succeeded' || job.status === 'failed')) return job
    if (plan?.status === 'rejected') return null
    await new Promise((r) => setTimeout(r, intervalMs))
  }
}
export const previewOf = (job: JobRow): PlanPreviewOut | null => {
  const r = job.result as Partial<PlanPreviewOut> | null
  return r && r.plan && r.preview_id && r.plan_hash ? (r as PlanPreviewOut) : null
}
