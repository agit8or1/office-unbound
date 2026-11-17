import { describe, expect, it } from 'vitest'
import { STANDARD_RULES, planParams, ruleName } from './standardAlerts'

describe('standard infrastructure alerts', () => {
  it('names are valid check names', () => {
    for (const r of STANDARD_RULES) {
      const n = ruleName('My Cluster!! with a very long name that keeps going and going', r.rule)
      expect(n).toMatch(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/)
      expect(n.endsWith(r.rule.replace(/_/g, '-'))).toBe(true)
    }
    expect(ruleName('---', 'node_offline')).toBe('cluster-node-offline')
  })
  it('builds read-only infra check plans bound to the endpoint', () => {
    const p = planParams('e1', 'pve', STANDARD_RULES[2])
    expect(p).toEqual({ action: 'check.create', params: { name: 'pve-node-cpu', kind: 'infra', interval_seconds: 120, fail_threshold: 3,
      config: { endpoint_id: 'e1', rule: 'node_cpu', warn_pct: 85, crit_pct: 95 } } })
    expect(new Set(STANDARD_RULES.map((r) => r.rule)).size).toBe(STANDARD_RULES.length)
  })
})
