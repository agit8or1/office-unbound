import { describe, expect, it } from 'vitest'
import { NAV } from '../../nav'
import { dnsTone, type DnsRow } from './tenants'

const row = (o: Partial<DnsRow>): DnsRow => ({ group: 'Mail', name: 'x', type: 'TXT', expected: 'v', status: 'ok', found: [], why: '', how: '', required: true, ...o })

describe('tenant DNS checker display', () => {
  it('fails a missing required record but only suggests an optional one', () => {
    expect(dnsTone(row({ status: 'ok' })).s).toBe('ok')
    expect(dnsTone(row({ status: 'missing' }))).toEqual({ s: 'failed', text: 'Missing' })
    expect(dnsTone(row({ status: 'differs', required: false }))).toEqual({ s: 'pending', text: 'Different (optional)' })
    expect(dnsTone(row({ status: 'not_available' })).text).toBe('Not available')
    expect(dnsTone(row({ status: 'unknown' })).text).toBe('Could not check')
  })
})

describe('ADR-0021 navigation', () => {
  it('has Tenants and Platform admins, and no longer Users & roles or Customers', () => {
    const labels = NAV.flatMap((g) => g.items.map((i) => i.label))
    expect(labels).toContain('Tenants')
    expect(labels).toContain('Platform admins')
    expect(labels).not.toContain('Users & roles')
    expect(labels).not.toContain('Customers')
  })
})
