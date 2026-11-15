// Typed client + normalisers for the ADR-0009 section 7 read endpoints (/infra/*, /deployments, /approvals).
// The server may not have an endpoint yet (404/405/501): callers get state 'missing' and render a proper
// "not connected yet" state; numbers are never invented. Normalisers tolerate field-name variants (cpu 0..1 vs 0..100 etc).
import { ApiError, get } from './api'
import type { Pt } from './charts/geometry'

export type LoadState = 'ok' | 'missing' | 'forbidden'
export interface Loaded<T> { state: LoadState; data: T }

export async function tryGet<T>(path: string, empty: T): Promise<Loaded<T>> {
  try { return { state: 'ok', data: await get<T>(path) } } catch (e) {
    if (e instanceof ApiError && [404, 405, 501].includes(e.status)) return { state: 'missing', data: empty }
    if (e instanceof ApiError && e.status === 403) return { state: 'forbidden', data: empty }
    throw e
  }
}

type Raw = Record<string, unknown>
const num = (v: unknown): number | null => { const n = typeof v === 'string' ? parseFloat(v) : (v as number); return typeof n === 'number' && isFinite(n) ? n : null }
const str = (v: unknown): string | null => (v === null || v === undefined || v === '' ? null : String(v))
function first(o: Raw, ...keys: string[]): unknown { for (const k of keys) if (o[k] !== undefined && o[k] !== null) return o[k]; return undefined }
export function asList(x: unknown): Raw[] {
  if (Array.isArray(x)) return x as Raw[]
  if (x && typeof x === 'object') { for (const v of Object.values(x as Raw)) if (Array.isArray(v)) return v as Raw[] }
  return []
}
/** Utilisation as a percentage: accepts a 0..1 fraction or a 0..100 value, or used/total. */
export function pct(o: Raw, pctKeys: string[], usedKeys: string[], totalKeys: string[]): number | null {
  const direct = num(first(o, ...pctKeys))
  if (direct !== null) return Math.round((direct <= 1 ? direct * 100 : direct) * 10) / 10
  const used = num(first(o, ...usedKeys)), total = num(first(o, ...totalKeys))
  return used !== null && total ? Math.round((used / total) * 1000) / 10 : null
}

export interface Res {
  id: string; name: string; status: string; kind: string
  clusterId: string | null; nodeId: string | null; nodeName: string | null
  cpu: number | null; mem: number | null; disk: number | null
  raw: Raw
}
function base(o: Raw, kind: string): Res {
  const id = String(first(o, 'id', 'vmid', 'name') ?? '')
  return {
    id, kind, name: String(first(o, 'name', 'node', 'hostname') ?? id), status: String(first(o, 'status', 'state') ?? 'unknown').toLowerCase(),
    clusterId: str(first(o, 'cluster_id', 'cluster')), nodeId: str(first(o, 'node_id')), nodeName: str(first(o, 'node_name', 'node')),
    cpu: pct(o, ['cpu_percent', 'cpu_pct', 'cpu', 'cpu_usage'], [], []),
    mem: pct(o, ['mem_percent', 'mem_pct', 'memory_percent', 'mem_usage'], ['mem', 'mem_used', 'memory_used'], ['maxmem', 'mem_total', 'memory_total', 'mem_max']),
    disk: pct(o, ['disk_percent', 'disk_pct', 'usage', 'used_percent', 'used_pct'], ['used', 'used_bytes', 'disk', 'disk_used'], ['total', 'total_bytes', 'maxdisk', 'disk_total', 'size']),
    raw: o,
  }
}
export const normCluster = (o: Raw): Res => base(o, 'cluster')
export const normNode = (o: Raw): Res => base(o, 'node')
export const normStorage = (o: Raw): Res => base(o, 'storage')
export const normNetwork = (o: Raw): Res => base(o, 'network')
export function normGuest(o: Raw): Res {
  const r = base(o, 'vm')
  const t = String(first(o, 'kind', 'type', 'guest_type') ?? 'vm').toLowerCase()
  r.kind = t === 'lxc' || t === 'container' ? 'lxc' : 'vm'
  if (r.nodeName === null) r.nodeName = str(first(o, 'node'))
  r.name = String(first(o, 'name', 'hostname') ?? first(o, 'vmid', 'id') ?? '')
  return r
}

export interface Infra { clusters: Res[]; nodes: Res[]; storage: Res[]; networks: Res[]; guests: Res[]; connected: boolean; missing: boolean }
export async function loadInfra(): Promise<Infra> {
  const [c, n, s, w, g] = await Promise.all([
    tryGet<unknown>('infra/clusters', []), tryGet<unknown>('infra/nodes', []), tryGet<unknown>('infra/storage', []),
    tryGet<unknown>('infra/networks', []), tryGet<unknown>('infra/guests', []),
  ])
  const clusters = asList(c.data).map(normCluster), nodes = asList(n.data).map(normNode)
  const storage = asList(s.data).map(normStorage), networks = asList(w.data).map(normNetwork), guests = asList(g.data).map(normGuest)
  const missing = [c, n, s, w, g].every((x) => x.state === 'missing')
  return { clusters, nodes, storage, networks, guests, missing, connected: clusters.length + nodes.length + guests.length > 0 }
}

export const isUp = (s: string) => ['online', 'running', 'ok', 'available', 'active', 'up'].includes(s)
export const isDown = (s: string) => ['offline', 'down', 'failed', 'error', 'unreachable'].includes(s)
export const runningGuests = (gs: Res[]) => gs.filter((g) => g.status === 'running')
/** Children of a resource (guests of a node, nodes of a cluster ...) matched by id or name. */
export function belongs(child: Res, parent: Res): boolean {
  const key = child.kind === 'storage' || child.kind === 'network' || child.kind === 'vm' || child.kind === 'lxc' ? 'node' : 'cluster'
  if (key === 'node') return (child.nodeId !== null && child.nodeId === parent.id) || (child.nodeName !== null && child.nodeName === parent.name)
  return child.clusterId !== null && (child.clusterId === parent.id || child.clusterId === parent.name)
}

// ---- metrics ----
export type MetricName = 'cpu' | 'memory' | 'storage' | 'network'
export interface MetricSeries { points: Pt[]; state: LoadState }
/** Accepts [{ts,value}] | [[ts,value]] | {points|samples|data: ...}. ts may be seconds, ms or ISO. */
export function parseSamples(x: unknown): Pt[] {
  const arr = Array.isArray(x) ? x : asList(x)
  const out: Pt[] = []
  for (const s of arr as unknown[]) {
    let t: unknown, v: unknown
    if (Array.isArray(s)) [t, v] = s
    else if (s && typeof s === 'object') { const o = s as Raw; t = first(o, 'ts', 't', 'time', 'at', 'timestamp'); v = first(o, 'value', 'v', 'avg') }
    let ms = typeof t === 'string' && isNaN(Number(t)) ? Date.parse(t) : Number(t)
    const val = num(v)
    if (!isFinite(ms) || val === null) continue
    if (ms < 1e11) ms *= 1000
    out.push({ t: ms, v: val })
  }
  return out.sort((a, b) => a.t - b.t)
}
export async function loadMetric(scope: string, id: string, metric: MetricName, range: string): Promise<MetricSeries> {
  const r = await tryGet<unknown>(`infra/metrics?scope=${encodeURIComponent(scope)}&id=${encodeURIComponent(id)}&metric=${metric}&range=${range}`, [])
  return { state: r.state, points: parseSamples(r.data) }
}

// ---- deployments ----
export interface Deployment { endpointId: string | null; id: string; name: string; status: string; profile: string | null; updated: string | null; created: string | null }
export function normDeployment(o: Raw): Deployment {
  const id = String(first(o, 'id') ?? '')
  return { endpointId: str(first(o, 'endpoint_id')), id, name: String(first(o, 'name', 'customer', 'customer_id') ?? id.slice(0, 8)), status: String(first(o, 'status', 'state') ?? 'unknown').toLowerCase(), profile: str(first(o, 'profile')), updated: str(first(o, 'updated_at')), created: str(first(o, 'created_at')) }
}
export async function loadDeployments(): Promise<Loaded<Deployment[]>> {
  const r = await tryGet<unknown>('deployments', [])
  return { state: r.state, data: asList(r.data).map(normDeployment) }
}
export const DEPLOY_ACTIVE = ['planning', 'applying', 'in_progress', 'running', 'deploying', 'changing', 'pending']

/** Deterministic roll-up used by the dashboard. */
export type Health = 'ok' | 'warn' | 'bad' | 'idle'
export function infraHealth(i: Infra, critical: number, warning: number, incidents: number): { tone: Health; text: string; sub: string } {
  const downNodes = i.nodes.filter((n) => isDown(n.status)).length
  const unhealthyStorage = i.storage.filter((s) => (s.disk ?? 0) >= 90 || isDown(s.status)).length
  if (!i.connected && !critical && !warning) return { tone: 'idle', text: 'No data', sub: 'Connect a cluster to track health' }
  if (critical || downNodes || incidents) return { tone: 'bad', text: 'Critical', sub: [critical && `${critical} failing check${critical > 1 ? 's' : ''}`, downNodes && `${downNodes} node${downNodes > 1 ? 's' : ''} down`].filter(Boolean).join(', ') || `${incidents} active incident${incidents > 1 ? 's' : ''}` }
  if (warning || unhealthyStorage) return { tone: 'warn', text: 'Degraded', sub: warning ? `${warning} warning${warning > 1 ? 's' : ''}` : `${unhealthyStorage} storage pool${unhealthyStorage > 1 ? 's' : ''} near capacity` }
  return { tone: 'ok', text: 'Healthy', sub: 'All checks passing' }
}

export interface MaintenanceWindow { id: string; name: string; check_id: string | null; check_name: string | null; starts_at: string; ends_at: string; reason: string | null; active: boolean }
