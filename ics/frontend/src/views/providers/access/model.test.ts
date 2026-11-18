import { describe, expect, it } from 'vitest'
import type { InvGuest } from './api'
import { apiUrl, diffSelection, emptySelection, filterGuests, fromApproved, importBlocked, importCandidates, needsImportEnable, outsideNodes, permissionSummary, suggestTargets, toPolicy, toScopeTarget, validate, visibleNodes } from './model'

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
  it('never suggests storage that also exists on other nodes (shared / HA, e.g. ha-zfs): disks could land outside the selection', () => {
    const shared = { ...st('ha-zfs', ['pve06', 'pve04', 'pve05', 'pve2', 'pve3'], 9e13), shared: true }
    expect(suggestTargets({ ...emptySelection(), nodes: ['pve06'] }, { storages: [shared, st('PVE06-Storage', ['pve06'], 1e11)], networks: [] }).storages).toEqual(['PVE06-Storage'])
    expect(suggestTargets({ ...emptySelection(), nodes: ['pve06'] }, { storages: [shared], networks: [] }).storages).toBeUndefined()
    expect(outsideNodes(shared, ['pve06'])).toEqual(['pve04', 'pve05', 'pve2', 'pve3'])
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

describe('image import storage', () => {
  const ALL = ['pve01', 'pve2', 'pve3', 'pve04', 'pve05', 'pve06']
  const st = (storage: string, content: string, nodes: string[], type = 'dir') => ({ storage, type, content, shared: false, nodes, used: 0, total: 1e12 })
  const local = st('local', 'iso,vztmpl,backup,import', ALL)
  const localNoImport = st('local', 'iso,vztmpl,backup', ALL)
  const diskDir = st('dirdisks', 'images,import', ALL)
  const node06 = st('PVE06-Storage', 'images,rootdir', ['pve06'], 'lvmthin')
  const sel = { ...emptySelection(), nodes: ['pve06'] }
  it('lists storages with the import content type or a type that supports it; a storage that can also hold disks on other nodes is still offered (the import grant cannot place disks)', () => {
    expect(importCandidates([local, node06, diskDir], ['pve06']).map((s) => s.storage)).toEqual(['local', 'dirdisks'])
    expect(importCandidates([st('nfs1', 'backup', ALL, 'nfs'), localNoImport, st('pbs', 'backup', ALL, 'pbs')], ['pve06']).map((s) => s.storage)).toEqual(['local', 'nfs1'])
    expect(importBlocked(local, ['pve06'])).toBe(false)              // on every node, but it cannot place a VM disk
    expect(importBlocked(diskDir, ['pve06'])).toBe(false)            // images on other nodes: still fine as an IMPORT storage (no Datastore.AllocateSpace)
    expect(importBlocked(st('d6', 'images,import', ['pve06']), ['pve06'])).toBe(false)
  })
  it('preselects the import storage when deploying (local first, also when it holds disks) and never overrides a choice', () => {
    expect(suggestTargets(sel, { storages: [node06, local], networks: [] }).importStorages).toEqual(['local'])
    expect(suggestTargets(sel, { storages: [node06, diskDir], networks: [] }).importStorages).toEqual(['dirdisks'])
    expect(suggestTargets({ ...sel, importStorages: ['mine'] }, { storages: [local], networks: [] }).importStorages).toBeUndefined()
  })
  it('local without import is offered (Office Unbound enables import on it) and preselected; other types are not offered', () => {
    expect(importCandidates([localNoImport, node06], ['pve06']).map((s) => s.storage)).toEqual(['local'])
    expect(needsImportEnable(localNoImport)).toBe(true)
    expect(needsImportEnable(local)).toBe(false)
    expect(suggestTargets(sel, { storages: [st('aaa', 'iso,import', ALL), localNoImport, node06], networks: [] }).importStorages).toEqual(['local'])
    expect(importCandidates([node06, st('pbs', 'backup', ALL, 'pbs')], ['pve06'])).toEqual([])
  })
  it('reaches the policy, the scope target and the permission summary only with the deployment level', () => {
    const dep = { ...sel, level: 'deploy' as const, pools: ['office-unbound'], storages: ['PVE06-Storage'], networks: ['vmbr0'], importStorages: ['local'] }
    expect((toPolicy(dep, GUESTS) as { scope: { import_storages: string[]; storages: string[] } }).scope).toMatchObject({ import_storages: ['local'], storages: ['PVE06-Storage'] })
    expect(toScopeTarget(dep, GUESTS)).toMatchObject({ import_storages: ['local'], storages: ['PVE06-Storage'] })
    expect((toPolicy({ ...dep, level: 'monitoring' }, GUESTS) as { scope: { import_storages: string[] } }).scope.import_storages).toEqual([])
    const m = permissionSummary(dep).modify.find((x) => x.text === 'Upload signed golden images to local')
    expect(m?.by).toBe('proxmox')
    expect(permissionSummary({ ...dep, level: 'monitoring' }).modify).toEqual([])
    expect(diffSelection(sel, dep).added).toContain('Image import storage local')
  })
  it('edit mode keeps the import storage apart from the disk storages', () => {
    const inv = { approved_scope: { nodes: ['pve06'], pools: ['office-unbound'], storages: ['PVE06-Storage'], import_storages: ['local'], networks: ['vmbr0'], templates: [], managed_vmids: [], protected_vmids: [], preset: 'deploy' } }
    const s = fromApproved(inv as never)
    expect(s.importStorages).toEqual(['local'])
    expect(s.storages).toEqual(['PVE06-Storage'])
  })
})
