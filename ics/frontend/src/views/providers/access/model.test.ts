import { describe, expect, it } from 'vitest'
import type { InvGuest } from './api'
import { apiUrl, diffSelection, emptySelection, filterGuests, toPolicy, toScopeTarget, validate, visibleNodes } from './model'

const g = (vmid: number, node: string, extra: Partial<InvGuest> = {}): InvGuest => ({ vmid, type: 'qemu', name: `vm${vmid}`, node, status: 'running', cpus: 2, cpu: 0, mem: 0,
  maxmem: 2 ** 31, maxdisk: 2 ** 33, pool: null, template: false, tags: '', ...extra })
const GUESTS = [g(105, 'pve06'), g(106, 'pve01', { type: 'lxc' }), g(9612, 'pve06', { template: true }), g(126, 'pve06')]

describe('access wizard model', () => {
  it('selecting a node never selects its guests; operated guests make their node visible only', () => {
    const s = { ...emptySelection(), operate: [106], level: 'operations' as const }
    expect(visibleNodes(s, GUESTS)).toEqual(['pve01'])
    const p = toPolicy(s, GUESTS) as { preset: string; scope: { managed_vmids: number[]; pools: string[]; nodes: string[] } }
    expect(p.preset).toBe('operations')
    expect(p.scope.managed_vmids).toEqual([106])
    expect(p.scope.pools).toEqual([])
    const s2 = { ...emptySelection(), nodes: ['pve06'], pools: ['ou'], storages: ['local-lvm'], level: 'deploy' as const }
    expect((toPolicy(s2, GUESTS) as { scope: { managed_vmids: number[] } }).scope.managed_vmids).toEqual([])
  })
  it('deployment targets are only granted with the deployment level', () => {
    const s = { ...emptySelection(), operate: [105], nodes: ['pve06'], pools: ['ou'], storages: ['s'], networks: ['vmbr0'], templates: [9612], level: 'operations' as const }
    const p = toPolicy(s, GUESTS) as { scope: Record<string, unknown[]> }
    expect(p.scope.pools).toEqual([]) ; expect(p.scope.storages).toEqual([]); expect(p.scope.template_vmids).toEqual([])
    expect(toScopeTarget({ ...s, level: 'deploy' }, GUESTS)).toMatchObject({ mode: 'single_node', pools: ['ou'], managed_vmids: [105], preset: 'deploy' })
  })
  it('validates the choices', () => {
    expect(validate(emptySelection(), GUESTS).select).toBeTruthy()
    expect(validate({ ...emptySelection(), nodes: ['pve06'], level: 'operations' }, GUESTS).level).toBeTruthy()
    expect(validate({ ...emptySelection(), nodes: ['pve06'], level: 'deploy' }, GUESTS)).toMatchObject({ pools: expect.any(String), storages: expect.any(String) })
    expect(validate({ ...emptySelection(), operate: [126], protected: [126] }, GUESTS).select).toMatch(/protected/)
    expect(validate({ ...emptySelection(), operate: [9612] }, GUESTS).select).toMatch(/Templates/)
    expect(validate({ ...emptySelection(), operate: [105] }, GUESTS)).toEqual({})
  })
  it('diffs before and after for the review and the result', () => {
    const a = { ...emptySelection(), operate: [105, 106] }
    expect(diffSelection(a, { ...a, operate: [105, 107] })).toEqual({ added: ['Guest 107'], removed: ['Guest 106'] })
  })
  it('filters the tree and hides templates', () => {
    const s = { ...emptySelection(), operate: [105] }
    expect(filterGuests(GUESTS, '', 'all', 'all', s).map((x) => x.vmid)).toEqual([105, 106, 126])
    expect(filterGuests(GUESTS, 'pve01', 'all', 'all', s).map((x) => x.vmid)).toEqual([106])
    expect(filterGuests(GUESTS, '', 'lxc', 'all', s).map((x) => x.vmid)).toEqual([106])
    expect(filterGuests(GUESTS, '', 'all', 'selected', s).map((x) => x.vmid)).toEqual([105])
    expect(filterGuests([g(1, 'a', { seen: false }), g(2, 'a', { seen: true })], '', 'all', 'new', s).map((x) => x.vmid)).toEqual([1])
  })
  it('builds the API address', () => {
    expect(apiUrl('pve.example.com', 8006)).toBe('https://pve.example.com:8006')
    expect(apiUrl('https://pve.example.com:443/', 8006)).toBe('https://pve.example.com:443')
    expect(apiUrl(' 10.0.0.5 ', '')).toBe('https://10.0.0.5:8006')
  })
})

describe('edit mode', () => {
  it('starts from the approved scope and level', async () => {
    const { fromApproved } = await import('./model')
    const inv = { approved_scope: { nodes: ['pve06'], pools: [], storages: [], networks: ['vmbr0/20'], templates: [], managed_vmids: [105], protected_vmids: [126], preset: 'operations' } }
    const s = fromApproved(inv as never)
    expect(s.level).toBe('operations')
    expect(s.nodes).toEqual([])                       // not deployment nodes at the operations level
    expect(s.networks).toEqual(['vmbr0'])
    expect(s.operate).toEqual([105])
  })
})
