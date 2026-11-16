// Thin fetch client for /api/v1. Cookie auth (HttpOnly, set by the server) + X-CSRF-Token on every non-GET.
export const API_BASE = '/api/v1'

export class ApiError extends Error {
  status: number
  retryAfter: number | null
  constructor(status: number, message: string, retryAfter: number | null = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.retryAfter = retryAfter
  }
}

let csrfToken: string | null = null
let onUnauthorized: (() => void) | null = null

export function setCsrf(t: string | null) { csrfToken = t }
export function getCsrf() { return csrfToken }
export function setUnauthorizedHandler(f: (() => void) | null) { onUnauthorized = f }

/** FastAPI errors: {detail: string} or {detail: [{loc, msg}]}. */
export function formatDetail(detail: unknown, fallback: string): string {
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail
      .map((d) => {
        if (d && typeof d === 'object') {
          const o = d as { loc?: unknown[]; msg?: string }
          const loc = Array.isArray(o.loc) ? o.loc.filter((x) => x !== 'body').join('.') : ''
          return loc ? `${loc}: ${o.msg ?? ''}` : String(o.msg ?? '')
        }
        return String(d)
      })
      .join('; ')
  }
  return fallback
}

export async function request<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && method !== 'HEAD' && csrfToken) headers['X-CSRF-Token'] = csrfToken
  let res: Response
  try {
    res = await fetch(path.startsWith('/') ? path : `${API_BASE}/${path}`, {
      method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    throw new ApiError(0, 'Cannot reach the ICS server.')
  }
  let data: unknown = null
  const text = await res.text()
  if (text) { try { data = JSON.parse(text) } catch { data = null } }
  if (!res.ok) {
    const fallback = `${res.status} ${res.statusText}`.trim()
    const ra = Number(res.headers.get('Retry-After'))
    let msg = formatDetail((data as { detail?: unknown } | null)?.detail, fallback)
    if (res.status === 429) msg = `${msg}${ra > 0 ? ` (retry in ${ra}s)` : ''}`
    if (res.status === 401 && !path.endsWith('auth/login') && onUnauthorized) onUnauthorized()
    throw new ApiError(res.status, msg, ra > 0 ? ra : null)
  }
  return data as T
}

export const get = <T>(p: string) => request<T>('GET', p)
export const post = <T>(p: string, b?: unknown) => request<T>('POST', p, b ?? {})

// ---- types (mirror ics/ics/main.py) ----
export type Role = 'viewer' | 'operator' | 'approver' | 'admin'
export const ROLES: Role[] = ['viewer', 'operator', 'approver', 'admin']
export const rank = (r: Role) => ROLES.indexOf(r)

export interface Me { id?: string; username: string; role: Role; csrf_token: string }
export interface Endpoint {
  id: string; name: string; display_name?: string | null; type: string; base_url: string
  trust: 'fingerprint' | 'ca_bundle'
  credentials: { inventory: { present: boolean; token_id: string }; provision: { present: boolean; token_id: string | null } }
  scope: { allowed_pools: string[]; allowed_nodes: string[]; allowed_storage: string[]; allowed_networks: string[] }
  defaults?: { storage?: string; bridge?: string; vlan?: number }
  enabled?: boolean
  fingerprint_sha256: string | null; created_at: string
}
export interface Plan {
  id: string; action: string; params: Record<string, unknown>; risk: 'low' | 'high'
  status: 'pending_approval' | 'approved' | 'rejected'; requested_by: string
  decided_by: string | null; decided_at: string | null; created_at: string
  params_hash?: string; requested_by_username?: string; decided_by_username?: string | null
  approval_count?: number; approvers?: string[]; approvals_required?: number; self_approval?: boolean
}
export interface Job {
  id: string; plan_id: string; action: string; status: 'queued' | 'running' | 'succeeded' | 'failed'
  created_at: string; started_at: string | null; finished_at: string | null
  result: unknown; error: unknown
}
export interface PlanCreated {
  plan_id: string; status: string; risk: string; job_id: string | null
  params_hash: string; approvals_required: number; resolved_ips?: string[]; self_approval?: boolean
}
export interface AuditEvent {
  seq: number; id: string; at: string; action: string; actor_name: string | null; ip: string | null
  resource: string | null; resource_id: string | null; details: Record<string, unknown> | null; hash: string
}
export interface ChainResult {
  ok: boolean; checked: number; head: string; legacy_unauthenticated: number; mac_checked: boolean
  problems: { seq: number; kind: string; detail: string }[]
}
export interface Replication {
  ok: boolean; in_recovery?: boolean; heartbeat_age_seconds: number | null; replay_delay_seconds: number | null
  replay_backlog_bytes: number | null; max_lag_seconds: number
}
/** GET /readyz (public). On a standby `role` is 'standby' and checks.replication carries the lag; a fenced primary has fenced=true. */
export interface Ready {
  ready: boolean; version?: string; role?: 'primary' | 'standby'; epoch?: number; fenced?: boolean
  checks: Record<string, { ok: boolean } & Partial<Replication>>
}
/** /readyz answers 503 when not ready but still returns the JSON body, which the banner needs; so this does not go through request(). */
export async function fetchReady(): Promise<Ready | null> {
  try {
    const res = await fetch('/readyz', { headers: { Accept: 'application/json' }, credentials: 'same-origin' })
    const j = (await res.json()) as Ready
    return j && typeof j === 'object' && 'checks' in j ? j : null
  } catch { return null }
}
export interface ControllerInfo {
  role: 'primary' | 'standby'; epoch: number | null; fenced: boolean | null; node_name: string | null; changed_at: string | null
  replication: Replication | null; max_lag_seconds: number
  last_promotion: { at: string; by: string | null; host: string | null; old_epoch: number | null; new_epoch: number | null; last_replayed_commit: string | null } | null
}
/** GET /api/v1/version: public callers get only product+version; signed-in users get the rest. */
export interface BuildInfo {
  product: string; version: string; codename?: string | null; commit?: string | null; dirty?: boolean | null; built_at?: string | null; build_source?: string; api?: string
  schema?: { build_head: string | null; database: string | null }; components?: Record<string, string>; interfaces?: Record<string, string>
}
export interface UpdateStatus { current: string; latest_known: string | null; latest_date: string | null; notes_url: string | null; update_available: boolean; checked: string }
export interface SystemInfo extends BuildInfo { updates: UpdateStatus }

// ---- monitoring (read-only views; mutations go through typed plans) ----
export type CheckState = 'ok' | 'warning' | 'critical' | 'unknown'
export interface Check {
  id: string; name: string; kind: string; config: Record<string, unknown>; has_secret: boolean; interval_seconds: number
  fail_threshold: number; recover_threshold: number; enabled: boolean; state: CheckState; consecutive_bad: number
  last_run_at: string | null; next_run_at: string | null; last_state_change_at: string | null; last_message: string | null
  last_latency_ms: number | null; remediation: Record<string, unknown> | null; active_incident_id: string | null
}
export interface CheckResult { id: number; at: string; status: string; latency_ms: number | null; message: string | null }
export interface Attempt {
  id: number; runbook: string; attempt_no: number; at: string; status: string; verified: boolean | null; message: string | null
  plan_id: string | null; job_id: string | null; finished_at: string | null
}
export interface Incident {
  id: string; check_id: string; check_name: string; severity: string; status: string; title: string; message: string | null
  opened_at: string; acked_at: string | null; acked_by_username: string | null; recovered_at: string | null; escalated_at: string | null
  notify_count: number
}
export interface Notification { id: number; event: string; status: string; attempts: number; last_error: string | null; detail: string | null
  created_at: string; sent_at: string | null; channel: string; channel_kind: string }
export interface IncidentDetail extends Incident { notifications: Notification[]; remediation: Attempt[] }
export interface NodeInfo { id: string; name: string; address: string; port: number; agent_key_fp: string; agent_version: string | null; last_seen_at: string | null
  capabilities: Record<string, { units?: string[]; paths?: string[] }> }

// ---- releases (GET /releases, read-only; promotion is the release.promote plan) ----
export interface PkgEvidence { test: string; result: 'pass' | 'fail' | null; attestation_sha256: string | null; at: string | null; other: string[] }
export interface ReleasePackage { name: string; version: string; file: string; component: string; sha256: string; arch: string | null; evidence: PkgEvidence | null }
export interface ReleaseChannel { name: 'dev' | 'staging' | 'stable'; available: boolean; indexed_at: string | null; components: { component: string; packages: ReleasePackage[] }[] }
export interface PromoteParams {
  component: string; from_channel: 'dev' | 'staging'; to_channel: 'staging' | 'stable'
  packages: { file: string; sha256: string; name?: string; version?: string }[]
  evidence: { sha256: string; attestation_sha256: string }[]; reason?: string
}
export interface PromotionCandidate {
  component: string; from_channel: 'dev' | 'staging'; to_channel: 'staging' | 'stable'; ready: boolean; blocked: string[]
  approvals_required: number; risk: 'normal' | 'high'; current_in_target: number; params: PromoteParams
}
export interface Releases {
  configured: boolean; promote_enabled: boolean; records_readable?: boolean; evidence_test: string
  approvals_required: { staging: number; stable: number }; channels: ReleaseChannel[]; candidates: PromotionCandidate[]
}

// ---- guest bootstrap (GET /deployments/{slug}/bootstrap) ----
export interface BootstrapVm {
  vm: string; vmid: number; mode: 'callback' | 'ssh-lab'
  state: 'pending' | 'reported' | 'enrolled' | 'sealed' | 'expired' | 'revoked' | 'failed'
  attempts: number; created_at: string; expires_at: string; reported_at: string | null; sealed_at: string | null
  replay_alarm: { count: number; last_at: string; stopped_deployment: boolean } | null; rate_limited: boolean | null
}
export interface BootstrapOut { deployment: string; vms: BootstrapVm[] }

export interface ApprovalPolicy { normal: number; high: number; mode?: 'two_person' | 'single_admin'; self_approval?: boolean }
