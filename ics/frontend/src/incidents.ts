import type { Incident } from './api'

/** Deterministic recommended next step, derived only from the incident's recorded state. */
export function nextAction(i: Incident): string {
  if (i.status === 'recovered') return 'Recovered. No action needed; review the timeline if it keeps recurring.'
  if (i.escalated_at) return `Automatic remediation was exhausted. Investigate ${i.check_name} manually, then acknowledge the incident.`
  if (i.status === 'acked') return `Acknowledged${i.acked_by_username ? ' by ' + i.acked_by_username : ''}. Fix the underlying cause; the incident closes itself when the check recovers.`
  if (i.severity === 'critical') return `Acknowledge now and investigate ${i.check_name}; this is service-affecting.`
  return `Review ${i.check_name} and acknowledge the incident to stop re-notification.`
}
export const sevOrder = (s: string) => ({ critical: 0, warning: 1 } as Record<string, number>)[s] ?? 2
export function sortIncidents(list: Incident[]): Incident[] {
  return [...list].sort((a, b) => sevOrder(a.severity) - sevOrder(b.severity) || +new Date(a.opened_at) - +new Date(b.opened_at))
}
