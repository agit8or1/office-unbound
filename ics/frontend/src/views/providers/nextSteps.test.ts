import { describe, expect, it } from 'vitest'
import { guestVisibilityNote, nextSteps, primaryStep, type NsInput } from './nextSteps'
import { STANDARD_RULES } from '../infra/standardAlerts'

const EP = 'e1'
const base = (o: Partial<NsInput> = {}): NsInput => ({
  ep: { id: EP, name: 'pve', enabled: true, provision: true, pools: ['office-unbound'] },
  releases: { state: 'ok', configured: true, releases: [{ release: 'ubuntu-2404-v3', verified: true, version: 3 }] },
  templates: [], catalogTemplates: ['ou-tpl-ubuntu-2404'], plans: [], jobs: [], checks: [], deployments: [], canDeploy: true, ...o,
})
const by = (x: NsInput) => Object.fromEntries(nextSteps(x).map((s) => [s.id, s]))
const allRules = STANDARD_RULES.map((r) => ({ kind: 'infra', config: { endpoint_id: EP, rule: r.rule } }))

describe('next steps after connecting a cluster', () => {
  it('fresh connection: import is the next step, deploy is blocked on the template, primary continues into the import', () => {
    const s = by(base())
    expect(s.image).toMatchObject({ state: 'pending', to: `/images?endpoint=${EP}` })
    expect(s.image!.reason).toContain('ubuntu-2404-v3')
    expect(s.alerts!.state).toBe('pending')
    expect(s.deploy).toMatchObject({ state: 'blocked', reason: expect.stringContaining('imported template first') })
    expect(primaryStep(nextSteps(base()))!.id).toBe('image')
  })

  it('template visible on the cluster -> image done; all rules -> alerts done; deploy becomes the primary step', () => {
    const x = base({ templates: [{ vmid: 9000, name: 'ou-tpl-ubuntu-2404', pool: 'office-unbound' }], checks: allRules })
    const s = by(x)
    expect(s.image!.state).toBe('done')
    expect(s.alerts!.state).toBe('done')
    expect(s.deploy).toMatchObject({ state: 'pending', to: '/deployments/new' })
    expect(primaryStep(nextSteps(x))!.id).toBe('deploy')
  })

  it('a template with another name does not count; rules of another endpoint do not count', () => {
    const s = by(base({ templates: [{ vmid: 100, name: 'my-own-template' }], checks: allRules.map((c) => ({ ...c, config: { ...c.config, endpoint_id: 'other' } })) }))
    expect(s.image!.state).toBe('pending')
    expect(s.alerts!.reason).toContain('No standard alert rules')
  })

  it('partial alert rules are reported with counts', () => {
    expect(by(base({ checks: allRules.slice(0, 3) })).alerts!.reason).toBe(`3 of ${STANDARD_RULES.length} standard alert rules are set up.`)
  })

  it('unreadable inputs are unknown, never guessed', () => {
    const s = by(base({ templates: null, checks: null, deployments: null }))
    expect(s.image!.state).toBe('unknown')
    expect(s.alerts!.state).toBe('unknown')
    expect(s.deploy!.state).toBe('unknown')
    const t = by(base({ releases: null }))
    expect(t.image!.state).toBe('unknown')
    expect(t.deploy!.state).toBe('unknown')
    expect(primaryStep(nextSteps(base({ templates: null, checks: null, deployments: null })))).toBeNull()
  })

  it('import blocked without a provisioning token / pool, or without a verified release', () => {
    const s = by(base({ ep: { id: EP, name: 'pve', enabled: true, provision: false, pools: [] } }))
    expect(s.image).toMatchObject({ state: 'blocked', to: `/infrastructure/providers/${EP}/access` })
    expect(s.deploy!.state).toBe('blocked')
    expect(by(base({ releases: { state: 'ok', configured: true, releases: [{ release: 'r', verified: false }] } })).image!.state).toBe('blocked')
    expect(by(base({ releases: { state: 'ok', configured: false, releases: [] } })).image!.reason).toContain('directory')
    expect(by(base({ releases: { state: 'forbidden' } })).image!.state).toBe('pending')
  })

  it('an import awaiting approval or running is shown as in progress with a link to it', () => {
    const plan = { id: 'p1', action: 'image.import', status: 'pending_approval', params: { endpoint_id: EP } }
    expect(by(base({ plans: [plan] })).image).toMatchObject({ state: 'waiting', to: '/plans/p1' })
    const run = by(base({ plans: [{ ...plan, status: 'approved' }], jobs: [{ id: 'j1', plan_id: 'p1', action: 'image.import', status: 'running' }] }))
    expect(run.image).toMatchObject({ state: 'waiting', to: '/jobs/j1' })
    expect(by(base({ plans: [{ ...plan, params: { endpoint_id: 'other' } }] })).image!.state).toBe('pending')
  })

  it('alert plans waiting for approval are in progress', () => {
    const p = { id: 'c1', action: 'check.create', status: 'pending_approval', params: { config: { endpoint_id: EP, rule: 'node_offline' } } }
    expect(by(base({ plans: [p] })).alerts).toMatchObject({ state: 'waiting', to: '/plans/c1' })
  })

  it('deploy done when this endpoint has a deployment; blocked for roles without the wizard', () => {
    expect(by(base({ deployments: [{ endpointId: EP, status: 'ready' }] })).deploy!.state).toBe('done')
    expect(by(base({ deployments: [{ endpointId: 'other', status: 'ready' }] })).deploy!.state).toBe('blocked')
    expect(by(base({ deployments: [{ endpointId: EP, status: 'failed' }] })).deploy).toMatchObject({ state: 'blocked', reason: expect.stringContaining('failed') })
    const tpl = [{ vmid: 9000, name: 'ou-tpl-ubuntu-2404' }]
    expect(by(base({ templates: tpl, canDeploy: false })).deploy).toMatchObject({ state: 'blocked', reason: expect.stringContaining('operator') })
  })

  it('everything done -> no primary step', () => {
    const x = base({ templates: [{ vmid: 9000, name: 'ou-tpl-ubuntu-2404' }], checks: allRules, deployments: [{ endpointId: EP, status: 'ready' }] })
    expect(nextSteps(x).every((s) => s.state === 'done')).toBe(true)
    expect(primaryStep(nextSteps(x))).toBeNull()
  })
})

describe('guest visibility note', () => {
  it('only for own_only, linking to the single limited integration', () => {
    expect(guestVisibilityNote(null)).toBeNull()
    expect(guestVisibilityNote({ guest_visibility: 'cluster' })).toBeNull()
    expect(guestVisibilityNote({ guest_visibility: 'unknown' })).toBeNull()
    expect(guestVisibilityNote({ guest_visibility: 'own_only', guest_visibility_limited: [{ endpoint_id: EP, name: 'pve' }] }))
      .toEqual({ text: expect.stringContaining('whole-cluster read-only monitoring'), to: `/infrastructure/providers/${EP}/access` })
    expect(guestVisibilityNote({ guest_visibility: 'own_only', guest_visibility_limited: [{ endpoint_id: 'a', name: 'a' }, { endpoint_id: 'b', name: 'b' }] })!.to)
      .toBe('/infrastructure/providers')
  })
})
