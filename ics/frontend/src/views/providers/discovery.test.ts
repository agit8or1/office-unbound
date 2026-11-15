import { describe, expect, it } from 'vitest'
import { fromAdminDiscovery } from './model'

describe('admin discovery adapter', () => {
  it('maps the read-only discovery answer to the wizard model without inventing values', () => {
    const d = fromAdminDiscovery({ nodes: [{ name: 'pve06', status: 'online' }], storages: [{ name: 'S1', type: 'lvmthin', shared: false, content: 'images,rootdir', nodes: ['pve06'] }],
      bridges: [{ name: 'vmbr0', zone: 'localnetwork' }], templates: [{ vmid: 131, name: 'tpl', node: 'pve06', pool: 'p1' }], pools: ['p1'], notes: ['n'] })!
    expect(d.nodes[0].name).toBe('pve06')
    expect(d.storage[0].content).toEqual(['images', 'rootdir'])
    expect(d.networks[0].name).toBe('vmbr0')
    expect(d.templates[0].vmid).toBe(131)
    expect(d.pools).toEqual(['p1'])
    expect(d.guests).toEqual([])
    expect(fromAdminDiscovery(null)).toBeNull()
  })
})
