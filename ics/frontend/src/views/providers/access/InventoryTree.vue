<script setup lang="ts">
// Cluster > node > guest tree. Two independent choices, deliberately separate: "Deploy here" on a node (where NEW guests may be created) and a
// checkbox per existing guest (Office Unbound may see / operate THAT guest). Ticking a node never ticks its guests.
import { computed, ref } from 'vue'
import type { Inventory, InvGuest } from './api'
import { filterGuests, gib, pctOf, type Selection } from './model'

const props = defineProps<{ inv: Inventory; sel: Selection; edit: boolean; deployNodes: boolean }>()
const q = ref('')
const kind = ref<'all' | 'qemu' | 'lxc'>('all')
const only = ref<'all' | 'selected' | 'new'>('all')
const open = ref<Record<string, boolean>>({})
const prot = computed(() => new Set(props.sel.protected))
const guests = computed(() => filterGuests(props.inv.guests, q.value, kind.value, only.value, props.sel))
const byNode = computed(() => {
  const m = new Map<string, InvGuest[]>()
  for (const g of guests.value) (m.get(g.node) ?? m.set(g.node, []).get(g.node)!).push(g)
  return m
})
const filtering = computed(() => !!q.value.trim() || kind.value !== 'all' || only.value !== 'all')
const isOpen = (n: string) => open.value[n] ?? (filtering.value || props.inv.nodes.length <= 3)
function toggleGuest(v: number) {
  const i = props.sel.operate.indexOf(v)
  if (i >= 0) props.sel.operate.splice(i, 1)
  else props.sel.operate.push(v)
}
function toggleNode(n: string) {
  const i = props.sel.nodes.indexOf(n)
  if (i >= 0) props.sel.nodes.splice(i, 1)
  else props.sel.nodes.push(n)
}
function toggleWatch(n: string) {
  const i = props.sel.watch.indexOf(n)
  if (i >= 0) props.sel.watch.splice(i, 1)
  else props.sel.watch.push(n)
}
const guestNode = computed(() => new Set(props.inv.guests.filter((g) => props.sel.operate.includes(g.vmid)).map((g) => g.node)))
function selectAllShown(node: string, on: boolean) {
  for (const g of byNode.value.get(node) ?? []) {
    if (prot.value.has(g.vmid)) continue
    const has = props.sel.operate.includes(g.vmid)
    if (on && !has) props.sel.operate.push(g.vmid)
    if (!on && has) props.sel.operate.splice(props.sel.operate.indexOf(g.vmid), 1)
  }
}
const badge = (a?: string, seen?: boolean) => (a === 'protected' ? ['Protected', 'bad'] : a === 'operated' ? ['Authorized', 'ok'] : a === 'deployment_pool' ? ['In deployment pool', 'info']
  : a === 'template' ? ['Template', 'info'] : props.edit && seen === false ? ['New', 'warn'] : null)
</script>

<template>
  <div class="ax-tree">
    <div class="ax-filters" role="search">
      <input v-model="q" type="search" placeholder="Search by name, ID, node or tag" aria-label="Search guests" />
      <select v-model="kind" aria-label="Guest type"><option value="all">VMs and containers</option><option value="qemu">VMs only</option><option value="lxc">Containers only</option></select>
      <select v-model="only" aria-label="Show"><option value="all">All</option><option value="selected">Selected</option><option v-if="edit" value="new">New since last sync</option></select>
    </div>
    <ul class="ax-nodes" role="tree" aria-label="Cluster inventory">
      <li v-for="n in inv.nodes" :key="n.name" role="treeitem" :aria-expanded="isOpen(n.name)">
        <div class="ax-node" :class="{ off: n.status !== 'online' }">
          <button type="button" class="ax-twist" :aria-label="(isOpen(n.name) ? 'Collapse ' : 'Expand ') + n.name" @click="open[n.name] = !isOpen(n.name)">{{ isOpen(n.name) ? '▾' : '▸' }}</button>
          <span class="ax-name">{{ n.name }}</span>
          <span class="ax-dot" :class="n.status === 'online' ? 'ok' : 'bad'">{{ n.status }}</span>
          <span v-if="n.audited" class="muted small">{{ n.maxcpu }} CPU · {{ pctOf(n.cpu * n.maxcpu, n.maxcpu) }}% used · {{ gib(n.mem) }} / {{ gib(n.maxmem) }}</span>
          <span class="muted small">{{ n.guests.length }} guest(s)</span>
          <span v-if="edit && n.authorization === 'authorized'" class="ax-badge ok">Deployment target</span>
          <span class="spacer" />
          <label v-if="!deployNodes" class="ax-deploy" :title="'Office Unbound may see the status, health and metrics of ' + n.name + '. Its guests are NOT included: tick those one by one.'">
            <input type="checkbox" :checked="sel.watch.includes(n.name) || guestNode.has(n.name)" :disabled="guestNode.has(n.name)" @change="toggleWatch(n.name)" />
            {{ guestNode.has(n.name) ? 'Monitored (a selected guest runs here)' : 'Monitor this node' }}
          </label>
          <label v-if="deployNodes" class="ax-deploy" :title="'Allow Office Unbound to create NEW guests on ' + n.name + '. Existing guests are not affected.'">
            <input type="checkbox" :checked="sel.nodes.includes(n.name)" :disabled="n.status !== 'online'" @change="toggleNode(n.name)" /> Deploy new guests here
          </label>
        </div>
        <div v-if="isOpen(n.name)" class="ax-guests" role="group">
          <div v-if="(byNode.get(n.name) ?? []).length" class="ax-bulk muted small">
            <button type="button" class="linkish" @click="selectAllShown(n.name, true)">Select all shown</button> ·
            <button type="button" class="linkish" @click="selectAllShown(n.name, false)">Clear</button>
          </div>
          <label v-for="g in byNode.get(n.name) ?? []" :key="g.vmid" class="ax-guest" :class="{ sel: sel.operate.includes(g.vmid), prot: prot.has(g.vmid) }">
            <input type="checkbox" :checked="sel.operate.includes(g.vmid)" :disabled="prot.has(g.vmid)" @change="toggleGuest(g.vmid)" />
            <span class="ax-kind">{{ g.type === 'lxc' ? 'CT' : 'VM' }} {{ g.vmid }}</span>
            <span class="ax-gname">{{ g.name || '(no name)' }}</span>
            <span class="ax-dot" :class="g.status === 'running' ? 'ok' : 'idle'">{{ g.status }}</span>
            <span class="muted small">{{ g.cpus }} vCPU · {{ gib(g.maxmem) }} RAM · {{ gib(g.maxdisk) }} disk<span v-if="g.pool"> · pool {{ g.pool }}</span></span>
            <span v-if="badge(g.authorization, g.seen)" class="ax-badge" :class="badge(g.authorization, g.seen)![1]">{{ badge(g.authorization, g.seen)![0] }}</span>
          </label>
          <p v-if="!(byNode.get(n.name) ?? []).length" class="muted small">No guests{{ filtering ? ' match the filter' : '' }}.</p>
        </div>
      </li>
    </ul>
    <p class="muted small"><span v-if="!deployNodes">{{ sel.watch.length }} node(s) monitored · </span>{{ sel.operate.length }} existing guest(s) selected<span v-if="deployNodes"> · {{ sel.nodes.length }} node(s) for new deployments</span>. Templates are chosen with the deployment targets.</p>
  </div>
</template>

<style scoped>
.ax-filters { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
.ax-filters input { flex: 1 1 220px; min-width: 0; }
.ax-nodes { list-style: none; padding: 0; margin: 0; border: 1px solid var(--border, #d0d5dd); border-radius: 8px; }
.ax-nodes > li + li { border-top: 1px solid var(--border, #d0d5dd); }
.ax-node { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; padding: 10px 12px; }
.ax-node.off { opacity: .65; }
.ax-twist { background: none; border: 0; cursor: pointer; font-size: 14px; width: 22px; color: inherit; }
.ax-name { font-weight: 600; }
.spacer { flex: 1; }
.ax-deploy { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; }
.ax-guests { padding: 0 12px 10px 44px; display: grid; gap: 2px; }
.ax-bulk { margin: 2px 0 4px; }
.ax-guest { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; padding: 6px 8px; border-radius: 6px; cursor: pointer; }
.ax-guest.sel { background: var(--accent-bg, rgba(59, 130, 246, .08)); }
.ax-guest.prot { cursor: not-allowed; opacity: .7; }
.ax-kind { font-family: var(--mono, ui-monospace, monospace); font-size: 12px; min-width: 72px; }
.ax-gname { font-weight: 500; }
.ax-dot { font-size: 12px; }
.ax-dot::before { content: '●'; margin-right: 4px; }
.ax-dot.ok::before { color: #12b76a; } .ax-dot.bad::before { color: #f04438; } .ax-dot.idle::before { color: #98a2b3; }
.ax-badge { font-size: 11px; padding: 1px 8px; border-radius: 999px; border: 1px solid currentColor; }
.ax-badge.ok { color: #067647; } .ax-badge.info { color: #175cd3; } .ax-badge.warn { color: #b54708; } .ax-badge.bad { color: #b42318; }
.linkish { background: none; border: 0; padding: 0; color: var(--link, #175cd3); cursor: pointer; font: inherit; }
</style>
