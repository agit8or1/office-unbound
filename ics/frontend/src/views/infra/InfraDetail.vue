<script setup lang="ts">
import { computed, watchEffect } from 'vue'
import { useLoad } from '../../store'
import { belongs, loadInfra, type Res } from '../../infra'
import { crumbLabel, fmtPct } from '../../format'
import UtilizationPanel from '../../components/UtilizationPanel.vue'
import ErrorBox from '../../components/ErrorBox.vue'
import PageHeader from '../../ui/PageHeader.vue'
import Card from '../../ui/Card.vue'
import StatusBadge from '../../ui/StatusBadge.vue'
import ProgressBar from '../../ui/ProgressBar.vue'
import EmptyState from '../../ui/EmptyState.vue'
import Button from '../../ui/Button.vue'
import Skeleton from '../../ui/Skeleton.vue'
import DataTable, { type Col } from '../../ui/DataTable.vue'

const props = defineProps<{ kind: string; id: string }>()
const infra = useLoad(loadInfra, 30000)
const PATH: Record<string, string> = { cluster: 'clusters', node: 'nodes', vm: 'vms', lxc: 'containers', storage: 'storage', network: 'networks' }
const POOL = computed(() => {
  const i = infra.data.value
  if (!i) return []
  return ({ cluster: i.clusters, node: i.nodes, vm: i.guests, lxc: i.guests, storage: i.storage, network: i.networks } as Record<string, Res[]>)[props.kind] ?? []
})
const res = computed(() => POOL.value.find((r) => r.id === props.id && (r.kind === props.kind || props.kind === 'cluster' || props.kind === 'node' || props.kind === 'storage' || props.kind === 'network')) ?? null)
watchEffect(() => { crumbLabel.value = res.value?.name ?? '' })

const children = computed(() => {
  const i = infra.data.value, r = res.value
  if (!i || !r) return []
  if (r.kind === 'cluster') return [{ title: 'Nodes', list: i.nodes.filter((n) => belongs(n, r)), kind: 'node' }]
  if (r.kind === 'node') return [
    { title: 'Virtual machines', list: i.guests.filter((g) => g.kind === 'vm' && belongs(g, r)), kind: 'vm' },
    { title: 'Containers', list: i.guests.filter((g) => g.kind === 'lxc' && belongs(g, r)), kind: 'lxc' },
    { title: 'Storage', list: i.storage.filter((g) => belongs(g, r)), kind: 'storage' },
    { title: 'Networks', list: i.networks.filter((g) => belongs(g, r)), kind: 'network' },
  ].filter((c) => c.list.length)
  return []
})
const up = computed(() => {
  const i = infra.data.value, r = res.value
  if (!i || !r) return []
  const out: { label: string; res: Res; kind: string }[] = []
  const node = r.nodeName ? i.nodes.find((n) => n.name === r.nodeName || n.id === r.nodeId) : undefined
  if (node) out.push({ label: 'Node', res: node, kind: 'node' })
  const cl = i.clusters.find((c) => c.id === (r.clusterId ?? node?.clusterId) || c.name === (r.clusterId ?? node?.clusterId))
  if (cl) out.push({ label: 'Cluster', res: cl, kind: 'cluster' })
  return out
})
const HIDE = new Set(['id', 'name', 'status', 'state', 'cluster_id', 'cpu', 'mem', 'maxmem', 'disk', 'maxdisk'])
const SECRET = /secret|token|password|key|credential|cert/i
const facts = computed(() => {
  const r = res.value
  if (!r) return []
  const out: { k: string; v: string }[] = []
  for (const [k, v] of Object.entries(r.raw)) {
    if (HIDE.has(k) || SECRET.test(k) || v === null || v === undefined || v === '' || typeof v === 'object') continue
    let s = String(v)
    if (/(_at|^at|seen)$/.test(k) && !isNaN(Date.parse(s))) s = new Date(s).toLocaleString()
    else if (/(bytes|mem|disk|size|total|used)$/.test(k) && typeof v === 'number' && v > 1e6) s = (v / 2 ** 30).toFixed(1) + ' GiB'
    out.push({ k: k.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase()), v: s })
  }
  return out
})
const cols: Col[] = [{ key: 'name', label: 'Name' }, { key: 'status', label: 'Status' }]
const scopes = computed(() => (res.value && ['cluster', 'node', 'vm', 'lxc'].includes(res.value.kind) ? [{ scope: res.value.kind === 'lxc' ? 'guest' : res.value.kind, id: res.value.id, name: res.value.name }] : []))
const hrefFor = (kind: string) => (r: Res) => `/infrastructure/${PATH[kind]}/${encodeURIComponent(r.id)}`
const label = (k: string) => ({ cluster: 'Cluster', node: 'Node', vm: 'Virtual machine', lxc: 'Container', storage: 'Storage pool', network: 'Network' } as Record<string, string>)[k]
</script>
<template>
  <div class="page">
    <ErrorBox :error="infra.error.value" />
    <Skeleton v-if="!infra.data.value && !infra.error.value" />
    <EmptyState v-else-if="!res" icon="inbox" title="Not found" text="This resource is not reported by your connected clusters. It may have been removed or renamed.">
      <Button :to="'/infrastructure/' + PATH[kind]">Back to list</Button>
    </EmptyState>
    <template v-else>
      <PageHeader :title="res.name" :sub="label(res.kind)"><template #actions><StatusBadge :s="res.status" /></template></PageHeader>
      <div class="statgrid">
        <div v-if="res.cpu !== null" class="stat info"><div class="lbl">CPU</div><div class="val">{{ fmtPct(res.cpu) }}</div><ProgressBar :pct="res.cpu" label="CPU" /></div>
        <div v-if="res.mem !== null" class="stat info"><div class="lbl">Memory</div><div class="val">{{ fmtPct(res.mem) }}</div><ProgressBar :pct="res.mem" label="Memory" /></div>
        <div v-if="res.disk !== null" class="stat info"><div class="lbl">{{ res.kind === 'storage' ? 'Used' : 'Disk' }}</div><div class="val">{{ fmtPct(res.disk) }}</div><ProgressBar :pct="res.disk" label="Disk" /></div>
        <div v-for="u in up" :key="u.label" class="stat idle"><div class="lbl">{{ u.label }}</div><router-link class="val small-val" :to="hrefFor(u.kind)(u.res)">{{ u.res.name }}</router-link><div class="sub"><StatusBadge :s="u.res.status" /></div></div>
      </div>
      <div class="grid main-side">
        <UtilizationPanel v-if="scopes.length" :scopes="scopes" connected :title="'Utilization'" />
        <Card title="Details">
          <dl v-if="facts.length" class="kv"><template v-for="f in facts" :key="f.k"><dt>{{ f.k }}</dt><dd>{{ f.v }}</dd></template></dl>
          <p v-else class="muted">No further details reported.</p>
        </Card>
      </div>
      <Card v-for="c in children" :key="c.title" :title="c.title" flush>
        <DataTable :cols="cols" :rows="c.list" :row-key="(r: Res) => r.id" :href="hrefFor(c.kind)" dense>
          <template #cell-status="{ row }"><StatusBadge :s="row.status" /></template>
        </DataTable>
      </Card>
    </template>
  </div>
</template>
