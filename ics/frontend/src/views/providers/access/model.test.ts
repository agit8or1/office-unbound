import { describe, expect, it } from 'vitest'
import type { InvGuest } from './api'
import { apiUrl, diffSelection, emptySelection, filterGuests, permissionSummary, suggestTargets, toPolicy, toScopeTarget, validate, visibleNodes } from './model'

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

describe('monitored nodes', () => {
  it('a ticked node is visible on its own, never with its guests, and is enough to continue', () => {
    const s = { ...emptySelection(), nodes: ['pve06'] }
    expect(validate(s, GUESTS)).toEqual({})
    const p = toPolicy(s, GUESTS) as { scope: { nodes: string[]; managed_vmids: number[] } }
    expect(p.scope.nodes).toEqual(['pve06']); expect(p.scope.managed_vmids).toEqual([])
    expect(diffSelection(emptySelection(), s).added).toEqual(['Node pve06'])
  })
})

describe('deployment targets Office Unbound picks itself', () => {
  const st = (storage: string, nodes: string[], free: number, content = 'images,rootdir') => ({ storage, type: 'lvmthin', content, shared: false, nodes, used: 0, total: free })
  const net = (name: string, nodes: string[], kind: 'bridge' | 'vnet' = 'bridge') => ({ name, kind, zone: null, nodes })
  const inv = { storages: [st('local', ['pve06'], 9e12, 'iso,vztmpl'), st('small', ['pve06'], 1e9), st('big', ['pve06'], 5e11), st('other', ['pve01'], 9e12)],
                networks: [net('vmbr1', ['pve06']), net('vmbr0', ['pve06', 'pve01']), net('vn1', ['pve06'], 'vnet')] }
  it('new pool, roomiest disk storage on the node, vmbr0; nothing before a node is chosen; never overrides a choice', () => {
    expect(suggestTargets(emptySelection(), inv)).toEqual({})
    expect(suggestTargets({ ...emptySelection(), nodes: ['pve06'] }, inv)).toEqual({ pools: ['office-unbound'], storages: ['big'], networks: ['vmbr0'] })
    expect(suggestTargets({ ...emptySelection(), nodes: ['pve06'], pools: ['mine'], networks: ['vmbr1'] }, inv)).toEqual({ storages: ['big'] })
  })
  it('validates the pool name and asks for a network', () => {
    const base = { ...emptySelection(), nodes: ['pve06'], storages: ['big'], level: 'deploy' as const }
    expect(validate({ ...base, pools: ['bad name'], networks: ['vmbr0'] }, GUESTS).pools).toBeTruthy()
    expect(validate({ ...base, pools: ['office-unbound'] }, GUESTS).networks).toBeTruthy()
    expect(validate({ ...base, pools: ['office-unbound'], networks: ['vmbr0'] }, GUESTS)).toEqual({})
  })
})

describe('edit mode', () => {
  it('starts from the approved scope and level', async () => {
    const { fromApproved } = await import('./model')
    const inv = { approved_scope: { nodes: ['pve06'], pools: [], storages: [], networks: ['vmbr0/20'], templates: [], managed_vmids: [105], protected_vmids: [126], preset: 'operations' } }
    const s = fromApproved(inv as never)
    expect(s.level).toBe('operations')
    expect(s.nodes).toEqual(['pve06'])                // the chosen hypervisors, at every level
    expect(s.networks).toEqual(['vmbr0'])
    expect(s.operate).toEqual([105])
  })
})

describe('permission summary', () => {
  it('monitoring modifies nothing; deployment names the real resources; delete-after-approval is labelled as Office Unbound enforced', () => {
    const mon = permissionSummary({ ...emptySelection(), nodes: ['pve06'] })
    expect(mon.modify).toEqual([])
    expect(mon.observe[0].text).toContain('pve06')
    const dep = permissionSummary({ ...emptySelection(), nodes: ['pve06'], pools: ['office-unbound'], storages: ['local-lvm'], networks: ['vmbr0'], level: 'deploy' })
    expect(dep.modify.map((m) => m.text).join(' ')).toMatch(/office-unbound.*pve06/)
    expect(dep.modify.find((m) => m.text.startsWith('Delete its own'))?.by).toBe('ou')
    expect(dep.never.find((m) => m.text.startsWith('Change Proxmox users'))?.by).toBe('proxmox')
    expect(permissionSummary({ ...emptySelection(), nodes: ['pve06'], monitorCluster: true }).observe[0].text).toContain('whole cluster')
  })
  it('the cluster-monitoring choice reaches the policy and the scope target', () => {
    const s = { ...emptySelection(), nodes: ['pve06'], monitorCluster: true }
    expect((toPolicy(s, GUESTS) as { monitor_cluster: boolean }).monitor_cluster).toBe(true)
    expect(toScopeTarget(s, GUESTS)).toMatchObject({ monitor_cluster: true })
  })
})
