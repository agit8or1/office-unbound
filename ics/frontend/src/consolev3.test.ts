import { describe, expect, it } from 'vitest'
import type { BootstrapVm, PromotionCandidate, Ready, ReleaseChannel, Releases } from './api'
import { bootstrapView, summary, worstTone } from './bootstrap'
import { bannerView, fmtSeconds, lagState, roleLabel } from './controller'
import { approversForRisk, scopeApprovalText, submittedApprovalText } from './approvals'
import { asPromoteParams, canPromote, componentSummary, evidenceView, pageState, promotePlanParams, releaseDiff } from './releases'

const pkg = (name: string, version: string, sha: string, result: 'pass' | 'fail' | null = 'pass') => ({
  name, version, file: `${name}_${version}_amd64.deb`, component: 'agent', sha256: sha, arch: 'amd64',
  evidence: result ? { test: 'install-smoke', result, attestation_sha256: 'e'.repeat(64), at: null, other: [] } : null,
})
const chan = (name: ReleaseChannel['name'], pk: ReturnType<typeof pkg>[]): ReleaseChannel => ({ name, available: true, indexed_at: null, components: pk.length ? [{ component: 'agent', packages: pk }] : [] })
const cand = (over: Partial<PromotionCandidate> = {}): PromotionCandidate => ({
  component: 'agent', from_channel: 'staging', to_channel: 'stable', ready: true, blocked: [], approvals_required: 2, risk: 'high', current_in_target: 1,
  params: { component: 'agent', from_channel: 'staging', to_channel: 'stable', packages: [{ file: 'a_2_amd64.deb', sha256: 'b'.repeat(64), name: 'a', version: '2' }], evidence: [{ sha256: 'b'.repeat(64), attestation_sha256: 'e'.repeat(64) }] }, ...over,
})
const rel = (over: Partial<Releases> = {}): Releases => ({ configured: true, promote_enabled: true, evidence_test: 'install-smoke', approvals_required: { staging: 1, stable: 2 }, channels: [], candidates: [], ...over })

describe('releases page state', () => {
  it('distinguishes loading, not configured, empty and ready', () => {
    expect(pageState(null)).toBe('loading')
    expect(pageState(rel({ configured: false }))).toBe('not_configured')
    expect(pageState(rel({ channels: [chan('dev', [])] }))).toBe('empty')
    expect(pageState(rel({ channels: [chan('dev', [pkg('a', '1', 'a'.repeat(64))])] }))).toBe('ready')
  })
  it('explains test evidence in plain words', () => {
    expect(evidenceView(pkg('a', '1', 'x'))).toMatchObject({ tone: 'ok' })
    expect(evidenceView(pkg('a', '1', 'x', 'fail'))).toMatchObject({ tone: 'bad' })
    expect(evidenceView(pkg('a', '1', 'x', null))).toMatchObject({ tone: 'warn', text: 'No install test recorded' })
    expect(evidenceView({ file: 'a.dsc', evidence: null }).tone).toBe('idle')
    expect(evidenceView(pkg('a', '1', 'x'), false).tone).toBe('idle')
  })
  it('summarises versions per channel', () => {
    expect(componentSummary(chan('stable', [pkg('a', '1', 'x')]), 'agent')).toBe('a 1')
    expect(componentSummary(chan('stable', []), 'agent')).toBe('not present')
  })
  it('promote button rules: admin, pipeline connected, evidence complete', () => {
    expect(canPromote(cand(), rel(), 'admin').ok).toBe(true)
    expect(canPromote(cand(), rel(), 'operator').ok).toBe(false)
    expect(canPromote(cand(), rel({ promote_enabled: false }), 'admin').why).toMatch(/pipeline/)
    expect(canPromote(cand({ ready: false }), rel(), 'admin').why).toMatch(/install test/)
  })
  it('the plan params are exactly the backend proposal plus an optional trimmed reason', () => {
    const c = cand()
    expect(promotePlanParams(c, '  ')).toEqual(c.params)
    expect(promotePlanParams(c, ' ship it ').reason).toBe('ship it')
    expect(promotePlanParams(c, 'x'.repeat(900)).reason).toHaveLength(500)
  })
})

describe('release.promote diff for approvers', () => {
  const stable = chan('stable', [pkg('a', '1', 'a'.repeat(64)), pkg('k', '3', 'k'.repeat(64))])
  it('marks new, replaced and unchanged packages and carries the evidence hash', () => {
    const p = asPromoteParams({ ...cand().params, packages: [
      { file: 'a_2_amd64.deb', sha256: 'b'.repeat(64), name: 'a', version: '2' },
      { file: 'k_3_amd64.deb', sha256: 'k'.repeat(64), name: 'k', version: '3' },
      { file: 'n_1_amd64.deb', sha256: 'n'.repeat(64), name: 'n', version: '1' }] })!
    const d = releaseDiff(p, [stable])
    expect(d.map((r) => r.kind)).toEqual(['replaces', 'unchanged', 'new'])
    expect(d[0]).toMatchObject({ was: '1', evidence: 'e'.repeat(64) })
    expect(d[2].evidence).toBeNull()
  })
  it('rejects malformed stored params instead of throwing', () => {
    expect(asPromoteParams(null)).toBeNull()
    expect(asPromoteParams({ component: 'x' })).toBeNull()
  })
})

const ready = (over: Partial<Ready>): Ready => ({ ready: true, checks: {}, role: 'primary', epoch: 3, fenced: false, ...over })
describe('controller banner', () => {
  it('shows nothing on a healthy primary or before /readyz answered', () => {
    expect(bannerView(null).show).toBe(false)
    expect(bannerView(ready({})).show).toBe(false)
  })
  it('standby: read-only wording, epoch and lag from the backend', () => {
    const v = bannerView(ready({ role: 'standby', ready: true, checks: { replication: { ok: true, heartbeat_age_seconds: 6, replay_delay_seconds: 1, replay_backlog_bytes: 0, max_lag_seconds: 60 } } }))
    expect(v).toMatchObject({ show: true, kind: 'warn', lag: 'ok' })
    expect(v.facts.join(' ')).toMatch(/epoch 3/)
    expect(v.facts.join(' ')).toMatch(/6 seconds old \(limit 60 seconds\)/)
  })
  it('standby that fell behind turns red and warns against taking over', () => {
    const v = bannerView(ready({ role: 'standby', ready: false, checks: { replication: { ok: false, heartbeat_age_seconds: 400, replay_delay_seconds: null, replay_backlog_bytes: 2048, max_lag_seconds: 60 } } }))
    expect(v.kind).toBe('bad')
    expect(v.text).toMatch(/runbook/)
    expect(v.facts.join(' ')).toMatch(/7 minutes/)
  })
  it('a fenced primary is called out', () => {
    expect(bannerView(ready({ fenced: true }))).toMatchObject({ show: true, kind: 'bad' })
  })
  it('helpers', () => {
    expect(lagState(null)).toBe('unknown')
    expect(fmtSeconds(null)).toBe('unknown')
    expect(fmtSeconds(7200)).toBe('2 hours')
    expect(roleLabel({ role: 'standby', fenced: false }).tone).toBe('warn')
    expect(roleLabel({ role: 'primary', fenced: true }).tone).toBe('bad')
    expect(roleLabel({ role: 'primary', fenced: false }).text).toBe('Primary')
  })
})

const vm = (over: Partial<BootstrapVm>): BootstrapVm => ({ vm: 'mail', vmid: 101, mode: 'callback', state: 'pending', attempts: 0, created_at: '', expires_at: '', reported_at: null, sealed_at: null, replay_alarm: null, rate_limited: false, ...over })
describe('guest bootstrap health', () => {
  it('maps every stored state to a label, tone and next step', () => {
    const states = ['pending', 'reported', 'enrolled', 'sealed', 'expired', 'revoked', 'failed'] as const
    const out = states.map((s) => bootstrapView(vm({ state: s })))
    expect(out.map((o) => o.tone)).toEqual(['warn', 'warn', 'ok', 'ok', 'bad', 'idle', 'bad'])
    for (const o of out) { expect(o.label).not.toMatch(/_/); expect(o.next.length).toBeGreaterThan(5) }
  })
  it('replay alarm beats rate limiting beats the stored state', () => {
    const a = { count: 2, last_at: '', stopped_deployment: true }
    expect(bootstrapView(vm({ state: 'enrolled', replay_alarm: a, rate_limited: true })).key).toBe('replay')
    expect(bootstrapView(vm({ state: 'enrolled', replay_alarm: a })).detail).toMatch(/stopped/)
    expect(bootstrapView(vm({ state: 'pending', rate_limited: true })).key).toBe('limited')
    expect(bootstrapView(vm({ state: 'enrolled', rate_limited: null })).key).toBe('enrolled')
  })
  it('rolls up per deployment', () => {
    const v = (s: BootstrapVm['state']) => bootstrapView(vm({ state: s }))
    expect(summary([])).toMatch(/No guest/)
    expect(summary([v('enrolled')])).toBe('All VMs are enrolled.')
    expect(summary([v('enrolled'), v('pending')])).toBe('1 VM is still starting up.')
    expect(summary([v('expired'), v('failed')])).toBe('2 VMs need attention.')
    expect(worstTone([v('enrolled'), v('pending')])).toBe('warn')
  })
})

describe('approver counts come from the backend', () => {
  it('uses the policy for the previewed risk and the server count after submit', () => {
    const pol = { normal: 1, high: 3 }
    expect(approversForRisk('high', pol)).toBe(3)
    expect(approversForRisk('normal', pol)).toBe(1)
    expect(approversForRisk('high', null)).toBeNull()
    expect(scopeApprovalText('high', pol)).toMatch(/3 different approvers/)
    expect(scopeApprovalText('normal', pol)).toMatch(/one approver/)
    expect(scopeApprovalText('high', null)).toBe('')
    expect(submittedApprovalText({ approvals_required: 4, status: 'pending_approval' })).toMatch(/4 different approvers/)
    expect(submittedApprovalText({ approvals_required: 1, status: 'approved' })).toBe('')
  })
})
