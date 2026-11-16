// Pure model of the access wizard (ADR-0016): what the administrator selected -> the policy (first connection) or the scope target (Manage access).
// Checkboxes are AUTHORIZATION scope: selecting a node never selects its guests; each operated guest is chosen one by one.
import type { Inventory, InvGuest } from './api'

export type Level = 'monitoring' | 'operations' | 'deploy'
export interface Selection {
  operate: number[]        // existing guests Office Unbound may see and (operations/deploy) power-control
  watch: string[]          // nodes Office Unbound may SEE (status, health, metrics); never their guests
  nodes: string[]          // nodes where new guests may be deployed
  pools: string[]
  storages: string[]
  networks: string[]
  templates: number[]
  level: Level
  allowMigrate: boolean
  protected: number[]
}

export const LEVELS: { id: Level; title: string; text: string; can: string[] }[] = [
  { id: 'monitoring', title: 'Monitoring', text: 'Read status and metrics of the selected resources, monitor health and send alerts.', can: ['Read status and metrics', 'Health checks and alerts'] },
  { id: 'operations', title: 'Operations', text: 'Everything in Monitoring, plus start, shut down and reboot the selected existing guests.', can: ['Everything in Monitoring', 'Start / shut down / reboot selected guests'] },
  { id: 'deploy', title: 'Deployment', text: 'Everything in Monitoring, plus create and manage its own new guests on the selected nodes, in its own pool, storage and network.', can: ['Everything in Monitoring', 'Create guests in the selected pools', 'Controlled updates and rollback of its own guests'] },
]
// Shown as switches that stay OFF unless chosen; presets never turn them on.
export const NEVER = ['Delete VMs or disks that Office Unbound did not create', 'Change storage, network or cluster configuration', 'Change Proxmox users or permissions', 'Open consoles or run commands in guests']

export function emptySelection(): Selection {
  return { operate: [], watch: [], nodes: [], pools: [], storages: [], networks: [], templates: [], level: 'monitoring', allowMigrate: false, protected: [] }
}

export function fromApproved(inv: Inventory): Selection {
  const a = inv.approved_scope
  if (!a) return emptySelection()
  const level: Level = a.preset === 'deploy' || a.preset === 'operations' ? a.preset : 'monitoring'
  // deployment nodes are only meaningful with the deployment level; otherwise the stored nodes are just the visible ones (derived again on save)
  const guestNodes = new Set((inv.guests ?? []).filter((g) => a.managed_vmids.includes(g.vmid)).map((g) => g.node))
  // the chosen hypervisors are `nodes` at every level (owner decision: nodes only); nodes that are visible only because an operated guest runs there are not
  return { operate: [...a.managed_vmids], watch: [], nodes: a.nodes.filter((n) => level === 'deploy' || !guestNodes.has(n)), pools: [...a.pools], storages: [...a.storages],
           networks: a.networks.map((n) => n.split('/')[0]), templates: [...a.templates], level, allowMigrate: !!a.allow_migrate, protected: [...a.protected_vmids] }
}

/** Nodes that become visible (Sys.Audit only): monitored nodes, deployment nodes and the nodes the operated guests run on. Never their guests. */
export function visibleNodes(sel: Selection, guests: InvGuest[]): string[] {
  const g = new Map(guests.map((x) => [x.vmid, x.node]))
  return [...new Set([...sel.watch, ...sel.nodes, ...sel.operate.map((v) => g.get(v)).filter((x): x is string => !!x)])].sort()
}

export function deploysAnything(sel: Selection): boolean { return sel.level === 'deploy' }

export const DEFAULT_POOL = 'office-unbound'
export const POOL_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$/

/** Deployment targets Office Unbound picks itself once deployment nodes are chosen; only EMPTY fields are filled, the administrator can change all of it.
 *  Pool: its own new pool (created on apply). Storage: the disk storage on all chosen nodes with the most free space. Network: a bridge every chosen
 *  node has (vmbr0 first). Bridges are never created: changing host networking can cut a node off. Templates: none (image.import creates its own). */
export function suggestTargets(sel: Selection, inv: Pick<Inventory, 'storages' | 'networks'>): Partial<Pick<Selection, 'pools' | 'storages' | 'networks'>> {
  if (!sel.nodes.length) return {}
  const onAll = (nodes: string[]) => sel.nodes.every((n) => nodes.includes(n))
  const out: Partial<Pick<Selection, 'pools' | 'storages' | 'networks'>> = {}
  if (!sel.pools.length) out.pools = [DEFAULT_POOL]
  if (!sel.storages.length) {
    const st = inv.storages.filter((s) => s.content.split(',').includes('images') && onAll(s.nodes)).sort((a, b) => (b.total - b.used) - (a.total - a.used))[0]
    if (st) out.storages = [st.storage]
  }
  if (!sel.networks.length) {
    const br = inv.networks.filter((x) => onAll(x.nodes)).sort((a, b) => Number(b.name === 'vmbr0') - Number(a.name === 'vmbr0') || Number(a.kind !== 'bridge') - Number(b.kind !== 'bridge') || a.name.localeCompare(b.name))[0]
    if (br) out.networks = [br.name]
  }
  return out
}

export function validate(sel: Selection, guests: InvGuest[]): Record<string, string> {
  const e: Record<string, string> = {}
  if (!sel.operate.length && !sel.nodes.length && !sel.watch.length) e.select = 'Select at least one node.'
  if (sel.level === 'operations' && !sel.operate.length) e.level = 'Operations needs at least one selected existing guest.'
  if (sel.level === 'deploy') {
    if (!sel.nodes.length) e.nodes = 'Choose at least one node.'
    if (!sel.pools.length) e.pools = 'Choose the resource pool new guests are placed in.'
    else if (!sel.pools.every((x) => POOL_NAME.test(x))) e.pools = 'A pool name uses letters, digits, - _ . (up to 40 characters).'
    if (!sel.networks.length) e.networks = 'Choose the network new guests connect to.'
    if (!sel.storages.length) e.storages = 'Choose at least one storage for new disks.'
  }
  const prot = new Set(sel.protected)
  if (sel.operate.some((v) => prot.has(v))) e.select = 'A protected guest cannot be operated.'
  const tpl = new Set(guests.filter((g) => g.template).map((g) => g.vmid))
  if (sel.operate.some((v) => tpl.has(v))) e.select = 'Templates are authorized as clone sources, not as operated guests.'
  return e
}

export function toPolicy(sel: Selection, guests: InvGuest[]): Record<string, unknown> {
  const deploy = sel.level === 'deploy'
  return {
    preset: sel.level, scope_mode: 'single_node', allow_migrate: deploy && sel.allowMigrate,
    scope: {
      nodes: visibleNodes(sel, guests), managed_vmids: [...sel.operate].sort((a, b) => a - b), protected_vmids: [...sel.protected],
      pools: deploy ? [...sel.pools] : [], storages: deploy ? [...sel.storages] : [], networks: deploy ? [...sel.networks] : [],
      template_vmids: deploy ? [...sel.templates] : [], guest_types: ['qemu', 'lxc'],
    },
  }
}

export function toScopeTarget(sel: Selection, guests: InvGuest[]): Record<string, unknown> {
  const p = toPolicy(sel, guests) as { scope: Record<string, unknown>; preset: Level; allow_migrate: boolean }
  const s = p.scope
  return { mode: 'single_node', nodes: s.nodes, storages: s.storages, template_vmids: s.template_vmids, pools: s.pools, networks: s.networks,
           managed_vmids: s.managed_vmids, preset: p.preset, allow_migrate: p.allow_migrate }
}

export interface Diff { added: string[]; removed: string[] }
export function diffSelection(before: Selection, after: Selection): Diff {
  const lab = (s: Selection) => new Set([...s.operate.map((v) => `Guest ${v}`), ...s.watch.map((n) => `Monitor node ${n}`), ...s.nodes.map((n) => `Node ${n}`), ...s.pools.map((n) => `Pool ${n}`),
    ...s.storages.map((n) => `Storage ${n}`), ...s.networks.map((n) => `Network ${n}`), ...s.templates.map((n) => `Template ${n}`)])
  const a = lab(before), b = lab(after)
  return { added: [...b].filter((x) => !a.has(x)), removed: [...a].filter((x) => !b.has(x)) }
}

export function filterGuests(guests: InvGuest[], q: string, kind: 'all' | 'qemu' | 'lxc', only: 'all' | 'selected' | 'new', sel: Selection): InvGuest[] {
  const t = q.trim().toLowerCase()
  const s = new Set(sel.operate)
  return guests.filter((g) => !g.template && (kind === 'all' || g.type === kind)
    && (only === 'all' || (only === 'selected' ? s.has(g.vmid) : g.seen === false))
    && (!t || String(g.vmid).includes(t) || g.name.toLowerCase().includes(t) || (g.node || '').toLowerCase().includes(t) || (g.tags || '').toLowerCase().includes(t)))
}

export const gib = (b: number) => `${(b / 2 ** 30).toFixed(b >= 100 * 2 ** 30 ? 0 : 1)} GiB`
export const pctOf = (u: number, t: number) => (t > 0 ? Math.round((u / t) * 100) : 0)
export function apiUrl(host: string, port: number | string): string {
  const h = host.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
  const hasPort = /:\d+$/.test(h) && !h.startsWith('[')
  return `https://${hasPort ? h : `${h}:${port || 8006}`}`
}
