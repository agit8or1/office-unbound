<script setup lang="ts">
import { computed } from 'vue'
import type { Check } from '../api'
import { belongs, type Infra, type Res } from '../infra'
import { tone } from '../ui/status'
import Card from '../ui/Card.vue'
import EmptyState from '../ui/EmptyState.vue'
import Button from '../ui/Button.vue'
import StatusDot from '../ui/StatusDot.vue'

// cluster -> node -> storage / network / guests; every cell links to its drill-down page.
const props = defineProps<{ infra: Infra; checks?: Check[] }>()
const PATH: Record<string, string> = { cluster: 'clusters', node: 'nodes', vm: 'vms', lxc: 'containers', storage: 'storage', network: 'networks' }
const link = (r: Res) => `/infrastructure/${PATH[r.kind]}/${encodeURIComponent(r.id)}`
const cellTone = (r: Res) => { const t = tone(r.status); return t === 'bad' ? 'bad' : t === 'warn' ? 'warn' : '' }
const tree = computed(() => {
  const i = props.infra
  const clusters = i.clusters.length ? i.clusters : [{ id: '', name: 'Nodes', status: 'unknown', kind: 'cluster', clusterId: null, nodeId: null, nodeName: null, cpu: null, mem: null, disk: null, raw: {} } as Res]
  return clusters.map((c) => ({
    c, nodes: i.nodes.filter((n) => !i.clusters.length || belongs(n, c)).map((n) => ({
      n, storage: i.storage.filter((s) => belongs(s, n)), networks: i.networks.filter((s) => belongs(s, n)), guests: i.guests.filter((g) => belongs(g, n)),
    })),
  }))
})
const MAXG = 14
// nodes with nothing of ours on them: one line, not a row each saying "No resources reported"
const busy = (x: { storage: Res[]; networks: Res[]; guests: Res[] }) => x.storage.length + x.networks.length + x.guests.length > 0
// health checks grouped by their owner (the deployment or cluster the name starts with), full names without that prefix
const checkGroups = computed(() => {
  const g = new Map<string, Check[]>()
  for (const c of props.checks ?? []) { const k = c.name.split('-')[0] || c.name; g.set(k, [...(g.get(k) ?? []), c]) }
  return [...g.entries()].map(([k, list]) => ({ k, list, ok: list.filter((c) => c.state === 'ok').length }))
})
const rest = (c: Check, k: string) => (c.name.startsWith(k + '-') ? c.name.slice(k.length + 1) : c.name)
</script>
<template>
  <Card title="Health matrix" hint="Cluster, node, storage, network and guests. Select any item to drill down.">
    <EmptyState v-if="!infra.connected && !checks?.length" compact icon="cluster" title="Nothing to show yet" text="Once a cluster is connected, its nodes, storage, networks and guests appear here with live status."><Button size="sm" to="/endpoints">Connect a cluster</Button></EmptyState>
    <div v-else class="matrix">
      <div v-for="t in (infra.connected ? tree : [])" :key="t.c.id" class="mcluster">
        <div class="mh"><StatusDot :s="t.c.status" /><router-link v-if="t.c.id" :to="link(t.c)">{{ t.c.name }}</router-link><span v-else>{{ t.c.name }}</span><span class="muted small">{{ t.nodes.length }} node{{ t.nodes.length === 1 ? '' : 's' }}</span></div>
        <div v-for="x in t.nodes.filter(busy)" :key="x.n.id" class="mnode">
          <div class="nm"><StatusDot :s="x.n.status" /><router-link :to="link(x.n)">{{ x.n.name }}</router-link></div>
          <div class="mlayers">
            <div v-if="x.storage.length" class="mlayer"><span class="lt">Storage</span><router-link v-for="s in x.storage" :key="s.id" :to="link(s)" class="cell" :class="cellTone(s)"><StatusDot :s="(s.disk ?? 0) >= 90 ? 'critical' : (s.disk ?? 0) >= 80 ? 'warning' : s.status" /><span>{{ s.name }}<template v-if="s.disk !== null"> <b>{{ Math.round(s.disk) }}%</b></template></span></router-link></div>
            <div v-if="x.networks.length" class="mlayer"><span class="lt">Network</span><router-link v-for="s in x.networks" :key="s.id" :to="link(s)" class="cell" :class="cellTone(s)"><StatusDot :s="s.status" /><span>{{ s.name }}</span></router-link></div>
            <div v-if="x.guests.length" class="mlayer"><span class="lt">Guests</span>
              <router-link v-for="g in x.guests.slice(0, MAXG)" :key="g.id" :to="link(g)" class="cell" :class="cellTone(g)"><StatusDot :s="g.status" /><span>{{ g.name }}</span></router-link>
              <router-link v-if="x.guests.length > MAXG" :to="'/infrastructure/vms'" class="cell"><span>+{{ x.guests.length - MAXG }} more</span></router-link>
            </div>
          </div>
        </div>
        <div v-if="t.nodes.some((x) => !busy(x))" class="mnode idle">
          <div class="nm muted small">No guests of ours</div>
          <div class="mlayer"><router-link v-for="x in t.nodes.filter((y) => !busy(y))" :key="x.n.id" :to="link(x.n)" class="cell" :class="cellTone(x.n)"><StatusDot :s="x.n.status" /><span>{{ x.n.name }}</span></router-link></div>
        </div>
      </div>
      <div v-if="checks?.length" class="mcluster">
        <div class="mh"><span>Health checks</span><span class="muted small">{{ (checks ?? []).filter((c) => c.state === 'ok').length }} of {{ checks.length }} passing</span></div>
        <div v-for="g in checkGroups" :key="g.k" class="mnode">
          <div class="nm"><StatusDot :s="g.ok === g.list.length ? 'ok' : 'warning'" /><span>{{ g.k }}</span><span class="muted small">{{ g.ok }}/{{ g.list.length }}</span></div>
          <div class="mlayer chks"><router-link v-for="c in g.list" :key="c.id" :to="'/checks/' + c.id" class="cell" :class="cellTone({ status: c.state } as Res)" :title="c.name + (c.last_message ? ': ' + c.last_message : '')"><StatusDot :s="c.state" /><span>{{ rest(c, g.k) }}</span></router-link></div>
        </div>
      </div>
    </div>
  </Card>
</template>
<style scoped>
.chks .cell { max-width: 100%; }   /* full check names on one line; the 200px cap is for guest names */
.mnode.idle { align-items: center; }
</style>
