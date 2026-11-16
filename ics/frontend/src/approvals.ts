// Approver counts always come from the backend: GET /approvals/policy before submitting, and the plan-created response after.
import type { ApprovalPolicy, PlanCreated } from './api'

export function approversForRisk(risk: string | undefined, policy: ApprovalPolicy | null): number | null {
  if (!policy || !risk) return null
  return risk === 'high' ? policy.high : policy.normal
}

export function scopeApprovalText(risk: string | undefined, policy: ApprovalPolicy | null): string {
  const n = approversForRisk(risk, policy)
  if (n === null) return ''
  return risk === 'high' ? `High risk: ${n} different approvers must agree before anything changes.` : n === 1 ? 'Normal risk: one approver must agree before anything changes.' : `${n} approvers must agree.`
}

/** After submit: the server's own count for this exact plan (it may be higher than the policy because of customer settings). */
export function submittedApprovalText(c: Pick<PlanCreated, 'approvals_required' | 'status'> | null): string {
  if (!c || c.status !== 'pending_approval') return ''
  return `Needs ${c.approvals_required} different approver${c.approvals_required === 1 ? '' : 's'} (not you).`
}
