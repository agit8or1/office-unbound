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

export interface Me { username: string; role: Role; csrf_token: string }
export interface Endpoint {
  id: string; name: string; type: string; base_url: string; token_id: string
  fingerprint_sha256: string | null; has_ca_bundle: boolean; created_at: string
}
export interface Plan {
  id: string; action: string; params: Record<string, unknown>; risk: 'low' | 'high'
  status: 'pending_approval' | 'approved' | 'rejected'; requested_by: string
  decided_by: string | null; decided_at: string | null; created_at: string
}
export interface Job {
  id: string; plan_id: string; action: string; status: 'queued' | 'running' | 'succeeded' | 'failed'
  created_at: string; started_at: string | null; finished_at: string | null
  result: unknown; error: unknown
}
export interface PlanCreated {
  plan_id: string; status: string; risk: string; job_id: string | null
  params_hash: string; approvals_required: number; resolved_ips?: string[]
}
export interface AuditEvent {
  seq: number; id: string; at: string; action: string; actor_name: string | null; ip: string | null
  resource: string | null; resource_id: string | null; details: Record<string, unknown> | null; hash: string
}
export interface ChainResult {
  ok: boolean; checked: number; head: string; legacy_unauthenticated: number; mac_checked: boolean
  problems: { seq: number; kind: string; detail: string }[]
}
export interface Ready { ready: boolean; checks: Record<string, { ok: boolean }> }
