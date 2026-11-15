import { describe, expect, it } from 'vitest'
import { reactive } from 'vue'
import { useWizard } from './useWizard'
import type { StepDef } from './useWizard'
import type { Errors } from './validate'
import { isHost, normalizeFingerprint, looksLikePem, intIn } from './validate'
import { fmtDuration, pct } from './format'

interface S { a: string; b: string }
const steps: StepDef<S>[] = [
  { id: 'one', title: 'One', validate: (s): Errors => (s.a ? {} : { a: 'a required' }) },
  { id: 'two', title: 'Two', validate: (s): Errors => (s.b ? {} : { b: 'b required' }) },
  { id: 'three', title: 'Three' },
]

describe('useWizard state machine', () => {
  it('blocks next until the step validates and reports field errors', () => {
    const s = reactive<S>({ a: '', b: '' })
    const w = useWizard(steps, s)
    expect(w.next()).toBe(false)
    expect(w.m.index).toBe(0)
    expect(w.m.errors).toEqual({ a: 'a required' })
    s.a = 'x'
    expect(w.next()).toBe(true)
    expect(w.m.index).toBe(1)
    expect(w.m.errors).toEqual({})
  })
  it('preserves state on back and allows revisiting reached steps only', () => {
    const s = reactive<S>({ a: 'x', b: 'y' })
    const w = useWizard(steps, s)
    w.next(); w.next()
    expect(w.isLast.value).toBe(true)
    w.back()
    expect(s).toEqual({ a: 'x', b: 'y' })
    expect(w.m.reached).toBe(2)
    expect(w.goto(2)).toBe(true)
    const fresh = useWizard(steps, reactive<S>({ a: 'x', b: 'y' }))
    expect(fresh.goto(2)).toBe(false) // not reached yet: cannot skip ahead
  })
  it('goto re-validates every step it skips and stops at the first invalid one', () => {
    const s = reactive<S>({ a: 'x', b: 'y' })
    const w = useWizard(steps, s)
    w.next(); w.next(); w.goto(0)
    s.b = ''
    expect(w.goto(2)).toBe(false)
    expect(w.m.index).toBe(1)
    expect(w.m.errors.b).toBe('b required')
  })
  it('never moves past the last step', () => {
    const w = useWizard(steps, reactive<S>({ a: 'x', b: 'y' }))
    w.next(); w.next()
    expect(w.next()).toBe(false)
    expect(w.m.index).toBe(2)
  })
})

describe('validators and formatters', () => {
  it('normalises SHA-256 fingerprints', () => {
    const hex = 'ab'.repeat(32)
    const colon = hex.toUpperCase().match(/../g)!.join(':')
    expect(normalizeFingerprint(hex)).toBe(colon)
    expect(normalizeFingerprint(`sha256 Fingerprint=${colon}`)).toBe(colon)
    expect(normalizeFingerprint('abc')).toBeNull()
  })
  it('validates hosts, ports and PEM shape', () => {
    expect(isHost('pve1.example.internal')).toBe(true)
    expect(isHost('192.168.22.17')).toBe(true)
    expect(isHost('https://pve')).toBe(false)
    expect(isHost('999.1.1.1')).toBe(false)
    expect(intIn(8006, 1, 65535)).toBe(true)
    expect(intIn(1.5, 1, 10)).toBe(false)
    expect(looksLikePem('-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----')).toBe(true)
    expect(looksLikePem('hello')).toBe(false)
  })
  it('formats durations and percentages', () => {
    expect(fmtDuration(0)).toBe('none expected')
    expect(fmtDuration(180)).toBe('~3 min')
    expect(pct(5, 0)).toBe(0)
    expect(pct(150, 100)).toBe(100)
  })
})
