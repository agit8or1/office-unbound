// "Standard alerts" for one cluster: a fixed, disclosed set of read-only `infra` alert rules. Each is a normal check.create plan
// (audited, approval-gated); nothing is created without the operator confirming the exact list.
export interface StdRule { rule: string; label: string; config: Record<string, unknown>; interval: number; fail: number }

export const STANDARD_RULES: StdRule[] = [
  { rule: 'node_offline', label: 'A node goes offline', config: {}, interval: 60, fail: 2 },
  { rule: 'cluster_quorum', label: 'The cluster loses quorum', config: {}, interval: 60, fail: 1 },
  { rule: 'node_cpu', label: 'Node CPU at or above 85 % (warning) / 95 % (critical)', config: { warn_pct: 85, crit_pct: 95 }, interval: 120, fail: 3 },
  { rule: 'node_memory', label: 'Node memory at or above 85 % / 95 %', config: { warn_pct: 85, crit_pct: 95 }, interval: 120, fail: 3 },
  { rule: 'storage_used', label: 'Storage at or above 80 % / 90 %, or inactive', config: { warn_pct: 80, crit_pct: 90 }, interval: 300, fail: 2 },
  { rule: 'ha_state', label: 'An HA service is in error, fence or recovery', config: {}, interval: 60, fail: 2 },
  { rule: 'backup_failed', label: 'A backup job failed in the last 26 h', config: { max_age_hours: 26 }, interval: 900, fail: 1 },
]

/** Check names are unique, at most 63 characters, [A-Za-z0-9_.-], starting alphanumeric. */
export function ruleName(endpointName: string, rule: string): string {
  const base = endpointName.toLowerCase().replace(/[^a-z0-9_.-]+/g, '-').replace(/^[^a-z0-9]+/, '') || 'cluster'
  const suffix = '-' + rule.replace(/_/g, '-')
  return base.slice(0, 63 - suffix.length) + suffix
}

export function planParams(endpointId: string, endpointName: string, r: StdRule) {
  return { action: 'check.create', params: { name: ruleName(endpointName, r.rule), kind: 'infra', interval_seconds: r.interval, fail_threshold: r.fail,
    config: { endpoint_id: endpointId, rule: r.rule, ...r.config } } }
}
