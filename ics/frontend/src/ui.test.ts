import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, h } from 'vue'
import { donutArcs, linePath, makeScale, niceMax } from './charts/geometry'
import { tone, worst } from './ui/status'
import { asList, belongs, infraHealth, loadMetric, normCluster, normDeployment, normGuest, normNode, normStorage, parseSamples, tryGet, type Infra } from './infra'
import { nextAction, sortIncidents } from './incidents'
import { fmtDuration } from './format'
import { ApiError, type Incident } from './api'
import StatusBadge from './ui/StatusBadge.vue'
import DataTable from './ui/DataTable.vue'
import EmptyState from './ui/EmptyState.vue'
import StatCard from './ui/StatCard.vue'

function mount(comp: object, props: Record<string, unknown> = {}, slots: Record<string, () => unknown> = {}) {
  const el = document.createElement('div')
  createApp({ render: () => h(comp, props, slots as never) }).mount(el)
  return el
}

describe('chart geometry', () => {
  it('rounds the axis maximum to a nice number', () => {
    expect(niceMax(0)).toBe(1); expect(niceMax(3.2)).toBe(5); expect(niceMax(73)).toBe(100); expect(niceMax(1.4e6)).toBe(2e6)
  })
  it('breaks the line across gaps instead of interpolating missing data', () => {
    const s = makeScale(100, 100, { l: 0, r: 0, t: 0, b: 0 }, 0, 100, 10)
    const d = linePath([{ t: 0, v: 0 }, { t: 10, v: 5 }, { t: 90, v: 10 }], s, 20)
    expect(d.match(/M/g)?.length).toBe(2)
    expect(d.startsWith('M0.0 100.0')).toBe(true)
  })
  it('splits donut arcs proportionally', () => {
    const a = donutArcs([1, 3], 100)
    expect(a[0]!.dash).toBeCloseTo(25); expect(a[1]!.dash).toBeCloseTo(75); expect(a[1]!.offset).toBeCloseTo(-25)
    expect(donutArcs([0, 0], 100)[0]!.dash).toBe(0)
  })
})

describe('status mapping', () => {
  it('maps states to tones', () => {
    expect(tone('running')).toBe('ok'); expect(tone('pending_approval')).toBe('warn'); expect(tone('Failed')).toBe('bad'); expect(tone('whatever')).toBe('idle')
    expect(worst(['ok', 'warn', 'bad'])).toBe('bad'); expect(worst([])).toBe('idle')
  })
  it('renders a badge with a readable label', () => {
    const el = mount(StatusBadge, { s: 'pending_approval' })
    expect(el.textContent).toBe('pending approval'); expect(el.querySelector('.badge.warn')).not.toBeNull()
  })
})

describe('infra normalisation', () => {
  it('accepts fractions and percentages, and used/total', () => {
    expect(normNode({ id: 'a', name: 'pve1', status: 'online', cpu: 0.42, mem: 50, maxmem: 100 }).cpu).toBe(42)
    expect(normNode({ id: 'a', name: 'pve1', mem: 50, maxmem: 200 }).mem).toBe(25)
    expect(normNode({ id: 'a', name: 'x' }).cpu).toBeNull()
  })
  it('distinguishes VMs from containers and links guests to nodes by name or id', () => {
    const g = normGuest({ vmid: 101, name: 'web', type: 'lxc', node: 'pve1' }), n = normNode({ id: 'n1', name: 'pve1' })
    expect(g.kind).toBe('lxc'); expect(belongs(g, n)).toBe(true)
    expect(belongs(normGuest({ vmid: 2, node_id: 'n1' }), n)).toBe(true); expect(belongs(normGuest({ vmid: 3, node: 'pve9' }), n)).toBe(false)
  })
  it('reads the real /infra rows: cpu_pct is already a percent, status falls back to health, nodes join clusters by endpoint', () => {
    const n = normNode({ id: 'u1', endpoint_id: 'e1', name: 'pve06', status: 'online', cpu_pct: 0.5, mem_used: 25, mem_total: 100, disk_used: 1, disk_total: 4 })
    expect(n.cpu).toBe(0.5); expect(n.mem).toBe(25); expect(n.disk).toBe(25)
    const c = normCluster({ id: 'c1', endpoint_id: 'e1', name: 'pve', quorate: true, health: { status: 'critical' } })
    expect(c.status).toBe('offline'); expect(belongs(n, c)).toBe(true)
    expect(normStorage({ id: 's', name: 'local', node: 'pve06', used: 10, total: 40, health: { status: 'warning' } })).toMatchObject({ disk: 25, status: 'degraded' })
    expect(normGuest({ id: 'g', vmid: 5, kind: 'lxc', node: 'pve06', status: 'running', mem_used: 1, mem_max: 4 })).toMatchObject({ kind: 'lxc', mem: 25 })
    expect(normDeployment({ id: 'uuid', slug: 'prod', customer_id: 'acme', status: 'active' })).toMatchObject({ id: 'prod', name: 'prod' })
  })
  it('loads metrics from the real /infra/metrics (named series, avg points, ratios)', async () => {
    const urls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      urls.push(url)
      const m = /metric=(\w+)/.exec(url)![1]
      const v = m.endsWith('total_bytes') ? 100 : m.startsWith('mem_used') ? 25 : 5
      return new Response(JSON.stringify({ points: [{ ts: '2026-01-01T00:00:00+00:00', avg: v, max: v }] }), { status: 200 })
    }))
    const mem = await loadMetric('node', 'u1', 'memory', '24h')
    expect(mem.points.map((p) => p.v)).toEqual([25]); expect(urls[0]).toContain('scope=node&id=u1&metric=mem_used_bytes&range=24h')
    expect((await loadMetric('node', 'u1', 'network', '1h')).points.map((p) => p.v)).toEqual([10])
    expect((await loadMetric('cluster', 'x', 'cpu', '1h')).points).toEqual([])
    vi.unstubAllGlobals()
  })
  it('unwraps list envelopes and parses sample shapes', () => {
    expect(asList({ items: [{ a: 1 }] })).toHaveLength(1)
    const p = parseSamples({ points: [{ ts: 1700000100, value: 2 }, [1700000000, '1.5'], { ts: 'bad', value: 1 }] })
    expect(p.map((x) => x.v)).toEqual([1.5, 2]); expect(p[0]!.t).toBe(1700000000 * 1000)
  })
  it('reports a missing endpoint as a state, not an error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"detail":"Not Found"}', { status: 404 })))
    expect((await tryGet('infra/clusters', [])).state).toBe('missing')
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 500 })))
    await expect(tryGet('infra/clusters', [])).rejects.toBeInstanceOf(ApiError)
  })
  it('never claims health without data', () => {
    const none: Infra = { clusters: [], nodes: [], storage: [], networks: [], guests: [], connected: false, missing: true }
    expect(infraHealth(none, 0, 0, 0).tone).toBe('idle')
    expect(infraHealth(none, 1, 0, 0).tone).toBe('bad')
    expect(infraHealth({ ...none, connected: true, nodes: [normNode({ id: '1', name: 'a', status: 'online' })] }, 0, 0, 0).tone).toBe('ok')
  })
})

describe('incidents and formatting', () => {
  const base: Incident = { id: '1', check_id: 'c', check_name: 'SMTP', severity: 'warning', status: 'open', title: 't', message: null, opened_at: '2026-01-01T00:00:00Z', acked_at: null, acked_by_username: null, recovered_at: null, escalated_at: null, notify_count: 0 }
  it('recommends a next action from recorded state', () => {
    expect(nextAction({ ...base, escalated_at: 'x' })).toMatch(/exhausted/)
    expect(nextAction({ ...base, status: 'acked', acked_by_username: 'ann' })).toMatch(/ann/)
    expect(nextAction({ ...base, severity: 'critical' })).toMatch(/Acknowledge now/)
  })
  it('sorts critical first, then oldest', () => {
    const s = sortIncidents([{ ...base, id: 'w' }, { ...base, id: 'c', severity: 'critical', opened_at: '2026-02-01T00:00:00Z' }])
    expect(s[0]!.id).toBe('c')
  })
  it('formats durations', () => { expect(fmtDuration(45e3)).toBe('45s'); expect(fmtDuration(125 * 60e3)).toBe('2h 5m'); expect(fmtDuration(3 * 86400e3)).toBe('3d 0h') })
})

describe('components', () => {
  afterEach(() => { document.body.innerHTML = '' })
  it('DataTable renders rows, a link in the first cell and slot overrides', () => {
    const el = mount(DataTable, { cols: [{ key: 'name', label: 'Name' }, { key: 'st', label: 'State' }], rows: [{ id: '1', name: 'pve1', st: 'ok' }], rowKey: (r: { id: string }) => r.id, href: (r: { id: string }) => '/x/' + r.id },
      { 'cell-st': () => 'custom' })
    expect(el.querySelectorAll('tbody tr')).toHaveLength(1)
    expect(el.querySelector('td a')?.getAttribute('href')).toBe('#/x/1'); expect(el.textContent).toContain('custom')
  })
  it('EmptyState shows title, text and actions', () => {
    const el = mount(EmptyState, { title: 'Connect your first Proxmox cluster', text: 'help' }, { default: () => h('a', { href: '#/setup' }, 'Start') })
    expect(el.textContent).toContain('Connect your first Proxmox cluster'); expect(el.querySelector('a')?.getAttribute('href')).toBe('#/setup')
  })
  it('StatCard links to its list page and avoids inline style attributes (CSP)', () => {
    const el = mount(StatCard, { label: 'Nodes', value: 2, of: 3, to: '/infrastructure/nodes', tone: 'ok', loading: false })
    expect(el.querySelector('a.stat.ok')?.getAttribute('href')).toBe('#/infrastructure/nodes'); expect(el.textContent).toContain('/ 3')
    expect(el.querySelector('[style]')).toBeNull()
  })
})
