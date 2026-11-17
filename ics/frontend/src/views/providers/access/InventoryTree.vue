<script setup lang="ts">
// The cluster's hypervisors (ADR-0016, owner decision 2026-11-16): the administrator picks only the NODES Office Unbound may use. Existing VMs and
// containers are never selectable here: Office Unbound gets no access to them (their count is shown for orientation only).
import type { Inventory } from './api'
import { gib, pctOf, type Selection } from './model'

const props = defineProps<{ inv: Inventory; sel: Selection; edit: boolean }>()
function toggle(n: string) {
  const i = props.sel.nodes.indexOf(n)
  if (i >= 0) props.sel.nodes.splice(i, 1)
  else props.sel.nodes.push(n)
}
</script>

<template>
  <div class="ax-tree">
    <ul class="ax-nodes" aria-label="Cluster nodes">
      <li v-for="n in inv.nodes" :key="n.name">
        <label class="ax-node" :class="{ off: n.status !== 'online', on: sel.nodes.includes(n.name) }">
          <input type="checkbox" :checked="sel.nodes.includes(n.name)" :disabled="n.status !== 'online'" @change="toggle(n.name)" />
          <span class="ax-name">{{ n.name }}</span>
          <span class="ax-dot" :class="n.status === 'online' ? 'ok' : 'bad'">{{ n.status }}</span>
          <span v-if="n.audited" class="muted small">{{ n.maxcpu }} CPU · {{ pctOf(n.cpu * n.maxcpu, n.maxcpu) }}% used · {{ gib(n.mem) }} / {{ gib(n.maxmem) }} RAM</span>
          <span class="muted small">{{ n.guests.length }} existing guest(s), not shared</span>
          <span v-if="edit && n.authorization === 'authorized'" class="ax-badge ok">In use</span>
        </label>
      </li>
    </ul>
    <p class="muted small">{{ sel.nodes.length }} of {{ inv.nodes.length }} node(s) selected. Office Unbound never gets access to your existing VMs and containers.</p>
  </div>
</template>

<style scoped>
.ax-nodes { list-style: none; padding: 0; margin: 0; border: 1px solid var(--line); border-radius: 8px; }
.ax-nodes > li + li { border-top: 1px solid var(--line); }
.ax-node { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; padding: 12px; cursor: pointer; }
.ax-node.on { background: var(--accent-bg, rgba(59, 130, 246, .08)); }
.ax-node.off { opacity: .65; cursor: not-allowed; }
.ax-name { font-weight: 600; }
.ax-dot { font-size: 12px; }
.ax-dot::before { content: '●'; margin-right: 4px; }
.ax-dot.ok::before { color: var(--ok); } .ax-dot.bad::before { color: var(--bad); }
.ax-badge { font-size: 11px; padding: 1px 8px; border-radius: 999px; border: 1px solid currentColor; }
.ax-badge.ok { color: var(--ok); }
</style>
