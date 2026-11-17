import { describe, expect, it } from 'vitest'
import { choicesMatch, conflictsOf, emptyChoices, leftoversOf, needsAck, seedChoices, toChoicesParam, type ConflictEntry } from './conflicts'

const opts = (avail: Record<string, boolean>) => (['use_existing', 'overwrite', 'recreate', 'create_new'] as const).map((a) => ({ action: a, available: !!avail[a], why_not: avail[a] ? null : 'no' }))
const ROLE: ConflictEntry = { kind: 'role', target: 'OfficeUnboundDeploy', default: 'create_new', chosen: 'create_new',
  existing: { privileges: ['VM.Audit'], used_by_others: ['bob@pve on /pool/x'] }, options: opts({ use_existing: true, overwrite: true, create_new: true }) }
const TOKEN: ConflictEntry = { kind: 'token', target: 'ics-svc@pve!ics-inv', default: null, chosen: null, existing: {}, options: opts({ recreate: true, create_new: true }) }

describe('conflict choices', () => {
  it('reads the server lists defensively', () => {
    expect(conflictsOf(undefined)).toEqual([])
    expect(leftoversOf({ leftovers: 'x' })).toEqual([])
    expect(conflictsOf({ conflict_options: [ROLE] })).toHaveLength(1)
  })
  it('seeds from the server defaults and sends only explicit, available, non-default picks', () => {
    const st = emptyChoices()
    seedChoices(st, [ROLE, TOKEN], null)
    expect(st.pick).toEqual({ 'role|OfficeUnboundDeploy': 'create_new', 'token|ics-svc@pve!ics-inv': '' })
    expect(toChoicesParam(st, [ROLE, TOKEN])).toBeNull()
    st.pick['role|OfficeUnboundDeploy'] = 'recreate'                        // not available: never sent
    st.pick['token|ics-svc@pve!ics-inv'] = 'recreate'
    st.cleanup = ['pool:b', 'pool:a', 'pool:a']
    expect(toChoicesParam(st, [ROLE, TOKEN])).toEqual({ items: [{ kind: 'token', target: 'ics-svc@pve!ics-inv', action: 'recreate' }], cleanup: ['pool:a', 'pool:b'] })
  })
  it('asks for acknowledgement when an overwrite changes other users\' rights', () => {
    const st = emptyChoices()
    st.pick['role|OfficeUnboundDeploy'] = 'overwrite'
    expect(needsAck(ROLE, st)).toBe(true)
    expect(toChoicesParam(st, [ROLE])!.items[0].acknowledge_shared).toBeUndefined()
    st.ack['role|OfficeUnboundDeploy'] = true
    expect(toChoicesParam(st, [ROLE])!.items[0].acknowledge_shared).toBe(true)
  })
  it('apply waits until the plan on screen was calculated with the selected choices', () => {
    const wanted = { items: [{ kind: 'role' as const, target: 'R', action: 'overwrite' as const }], cleanup: [] }
    expect(choicesMatch({}, null)).toBe(true)
    expect(choicesMatch(undefined, wanted)).toBe(false)
    expect(choicesMatch({ items: [{ kind: 'role', target: 'R', action: 'overwrite', acknowledge_shared: false }], cleanup: [] }, wanted)).toBe(true)
    expect(choicesMatch({ items: [], cleanup: ['pool:a'] }, wanted)).toBe(false)
  })
})
