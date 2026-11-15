// Types and helpers for the Users & roles area. Mutations are always typed plans (POST plans); nothing here edits accounts directly.
import { post, type PlanCreated, type Role } from '../../../api'

export type UserStatus = 'active' | 'disabled' | 'invited' | 'locked' | 'revoked'
export interface DirUser {
  id: string; username: string; role: Role; privileged: boolean; status: UserStatus
  created_by: string | null; created_at: string; role_set_by: string | null; role_set_at: string | null
  last_login_at: string | null; last_login_ip?: string | null; mfa_enrolled: boolean; active_sessions: number; pending_plans: number
}
export interface UserEvent { at: string; action: string; ip?: string; reason?: string | null }
export interface RoleHistory {
  at: string; kind: 'invited' | 'role_change'; role: string; previous_role: string | null; by: string | null
  plan_id: string | null; justification: string | null
}
export interface UserDetail extends DirUser {
  enrollment_expires_at: string | null; recent_events: UserEvent[]; role_history: RoleHistory[]
  sessions?: { created_at: string; last_seen: string; expires_at: string }[]
  pending_plans_detail: { id: string; action: string; risk: string; created_at: string }[]
}
export interface Invitation {
  id: string; username: string; role: Role; privileged: boolean; status: 'pending' | 'expired' | 'revoked'
  token: 'not_issued' | 'issued' | 'expired' | 'none'; invited_by: string | null; invited_at: string; token_expires_at: string | null
}
export interface Policy {
  approvals: { risk: string; required: number; text: string }[]
  sessions: { absolute_seconds: number; idle_seconds: number; max_per_user: number }
  lockout: { max_failures: number; window_seconds: number; backoff_base_seconds: number; backoff_cap_seconds: number; per_ip_max_failures: number }
  mfa: { mandatory: boolean; method: string }
  enrollment: { token_ttl_seconds: number; token_channel: string; password_min_length: number }
  plan_expiry_seconds: number
  rules: { id: string; title: string; text: string }[]
  roles: { role: Role; summary: string }[]
  capabilities: { capability: string; min_role: Role; roles: Record<Role, boolean> }[]
}

export const STATUS_KIND: Record<string, string> = { active: 'ok', invited: 'info', disabled: 'bad', locked: 'warn', revoked: 'bad', pending: 'info', expired: 'warn' }
export const STATUS_LABEL: Record<string, string> = {
  active: 'Active', invited: 'Invited', disabled: 'Disabled', locked: 'Locked', revoked: 'Revoked', pending: 'Pending', expired: 'Expired',
}
export const PRIVILEGED: Role[] = ['approver', 'admin']
export const USERNAME_RE = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$/

export const ACTION_LABEL: Record<string, string> = {
  'auth.login': 'Signed in', 'auth.login_failed': 'Failed sign-in', 'auth.logout': 'Signed out', 'auth.logout_all': 'Signed out everywhere',
  'user.invite': 'Invited', 'user.enrolled': 'Completed enrollment', 'user.enroll_started': 'Started enrollment',
  'user.enrollment_issued': 'One-time token issued (host)', 'user.role_set': 'Role changed', 'user.disabled': 'Disabled',
  'user.enabled': 'Enabled', 'user.sessions_revoked': 'Sessions revoked', 'user.invite_revoked': 'Invitation revoked',
}

export function ago(s: string | null | undefined, now = Date.now()): string {
  if (!s) return 'Never'
  const d = new Date(s).getTime()
  if (isNaN(d)) return s
  const sec = Math.round((now - d) / 1000)
  if (sec < 0) return 'in the future'
  if (sec < 60) return 'just now'
  if (sec < 3600) return `${Math.floor(sec / 60)} min ago`
  if (sec < 86400) return `${Math.floor(sec / 3600)} h ago`
  return `${Math.floor(sec / 86400)} d ago`
}
export function duration(sec: number): string {
  if (sec % 86400 === 0 && sec >= 86400) return `${sec / 86400} d`
  if (sec % 3600 === 0 && sec >= 3600) return `${sec / 3600} h`
  if (sec % 60 === 0 && sec >= 60) return `${sec / 60} min`
  return `${sec} s`
}

/** Host-side command that issues the one-time enrollment token. The token itself is printed once on the host and never travels through this console. */
export const cliCommand = (username: string) => `sudo -u ics .venv/bin/python -m ics.cli issue-enrollment --username ${username}`

export async function submitPlan(action: string, params: Record<string, unknown>): Promise<PlanCreated> {
  return post<PlanCreated>('plans', { action, params })
}
export function outcomeText(p: PlanCreated): string {
  if (p.status === 'approved') return 'Applied: the change is queued and runs now (low-risk actions need no approval).'
  const n = p.approvals_required
  return `Waiting for approval: ${n} approver${n === 1 ? '' : 's'} other than you must approve it before anything changes.`
}
export async function copyText(t: string): Promise<boolean> {
  try { await navigator.clipboard.writeText(t); return true } catch { return false }
}
