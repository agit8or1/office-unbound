<script setup lang="ts">
import { computed, ref } from 'vue'
import { useLoad } from '../../store'
import { belongs, loadInfra, type Infra, type Res } from '../../infra'
import { hasPath } from '../../router'
import DataTable, { type Col } from '../../ui/DataTable.vue'
import PageHeader from '../../ui/PageHeader.vue'
import StatusBadge from '../../ui/StatusBadge.vue'
import ProgressBar from '../../ui/ProgressBar.vue'
import EmptyState from '../../ui/EmptyState.vue'
import Button from '../../ui/Button.vue'
import Card from '../../ui/Card.vue'
import Skeleton from '../../ui/Skeleton.vue'
import ErrorBox from '../../components/ErrorBox.vue'
import { fmtPct } from '../../format'
import type { IconName } from '../../ui/icons'

const props = defineProps<{ kind: string }>()
const infra = useLoad(loadInfra, 30000)
const q = ref('')

const META: Record<string, { title: string; path: string; singular: string; icon: IconName; help: string }> = {
  cluster: { title: 'Clusters', path: 'clusters', singular: 'cluster', icon: 'cluster', help: 'A cluster is a group of Proxmox nodes managed together.' },
  node: { title: 'Nodes', path: 'nodes', singular: 'node', icon: 'server', help: 'Physical or virtual Proxmox hosts that run your guests.' },
  vm: { title: 'Virtual machines', path: 'vms', singular: 'virtual machine', icon: 'vm', help: 'QEMU virtual machines discovered on connected clusters.' },
  lxc: { title: 'Containers', path: 'containers', singular: 'container', icon: 'box', help: 'LXC containers discovered on connected clusters.' },
  storage: { title: 'Storage', path: 'storage', singular: 'storage pool', icon: 'database', help: 'Datastores available to your nodes, with capacity usage.' },
  network: { title: 'Networks', path: 'networks', singular: 'network', icon: 'network', help: 'Bridges and VLAN networks configured on your nodes.' },
}
const meta = computed(() => META[props.kind]!)
const all = computed<Res[]>(() => {
  const i: Infra | null = infra.data.value
  if (!i) return []
  return ({ cluster: i.clusters, node: i.nodes, vm: i.guests.filter((g) => g.kind === 'vm'), lxc: i.guests.filter((g) => g.kind === 'lxc'), storage: i.storage, network: i.networks } as Record<string, Res[]>)[props.kind] ?? []
})
const rows = computed(() => all.value.filter((r) => !q.value || (r.name + ' ' + r.status + ' ' + (r.nodeName ?? '')).toLowerCase().includes(q.value.toLowerCase())))
const count = (parent: Res, list: Res[]) => list.filter((c) => belongs(c, parent)).length

const cols = computed<Col[]>(() => ({
  cluster: [{ key: 'name', label: 'Name' }, { key: 'status', label: 'Status' }, { key: 'nodes', label: 'Nodes', num: true }, { key: 'vms', label: 'VMs', num: true }, { key: 'lxc', label: 'Containers', num: true }],
  node: [{ key: 'name', label: 'Name' }, { key: 'status', label: 'Status' }, { key: 'cluster', label: 'Cluster' }, { key: 'cpu', label: 'CPU' }, { key: 'mem', label: 'Memory' }, { key: 'guests', label: 'Guests', num: true }],
  vm: [{ key: 'name', label: 'Name' }, { key: 'status', label: 'Status' }, { key: 'node', label: 'Node' }, { key: 'cpu', label: 'CPU' }, { key: 'mem', label: 'Memory' }],
  lxc: [{ key: 'name', label: 'Name' }, { key: 'status', label: 'Status' }, { key: 'node', label: 'Node' }, { key: 'cpu', label: 'CPU' }, { key: 'mem', label: 'Memory' }],
  storage: [{ key: 'name', label: 'Name' }, { key: 'status', label: 'Status' }, { key: 'node', label: 'Node' }, { key: 'type', label: 'Type' }, { key: 'disk', label: 'Used' }],
  network: [{ key: 'name', label: 'Name' }, { key: 'status', label: 'Status' }, { key: 'node', label: 'Node' }, { key: 'type', label: 'Type' }],
} as Record<string, Col[]>)[props.kind] ?? [])
const href = (r: Res) => `/infrastructure/${meta.value.path}/${encodeURIComponent(r.id)}`
const rawStr = (r: Res, k: string) => (r.raw[k] === undefined || r.raw[k] === null ? '-' : String(r.raw[k]))
const connectTo = computed(() => (hasPath('/setup') ? '/setup' : '/endpoints'))
</script>
<template>
  <div class="page">
    <PageHeader :title="meta.title" :help="meta.help" :sub="all.length ? `${all.length} ${all.length === 1 ? meta.singular : meta.title.toLowerCase()} across your connected infrastructure.` : undefined">
      <template #actions><Button size="sm" icon="refresh" :loading="infra.loading.value" @click="infra.reload()">Refresh</Button></template>
    </PageHeader>
    <ErrorBox :error="infra.error.value" />
    <Skeleton v-if="!infra.data.value && !infra.error.value" />
    <Card v-else-if="infra.data.value" flush>
      <EmptyState v-if="!all.length && (infra.data.value.missing || !infra.data.value.connected)" :icon="meta.icon" title="Connect your first Proxmox cluster" :text="`${meta.title} are discovered from your Proxmox clusters. Connect one and they will appear here automatically.`">
        <Button variant="primary" icon="plus" :to="connectTo">{{ connectTo === '/setup' ? 'Start setup wizard' : 'Add a cluster' }}</Button>
      </EmptyState>
      <EmptyState v-else-if="!all.length" :icon="meta.icon" :title="`No ${meta.title.toLowerCase()} found`" text="Nothing of this kind was reported by your connected clusters yet. Discovery runs periodically." />
      <template v-else>
        <div class="cardhead filterbar"><input v-model="q" type="search" :placeholder="`Filter ${meta.title.toLowerCase()}`" :aria-label="`Filter ${meta.title}`"></div>
        <DataTable :cols="cols" :rows="rows" :row-key="(r: Res) => r.id" :href="href">
          <template #cell-status="{ row }"><StatusBadge :s="row.status" /></template>
          <template #cell-cluster="{ row }">{{ infra.data.value.clusters.find((c) => c.id === row.clusterId || c.name === row.clusterId)?.name ?? row.clusterId ?? '-' }}</template>
          <template #cell-node="{ row }">{{ row.nodeName ?? '-' }}</template>
          <template #cell-nodes="{ row }">{{ count(row, infra.data.value.nodes) }}</template>
          <template #cell-vms="{ row }">{{ count(row, infra.data.value.nodes) ? infra.data.value.guests.filter((g) => g.kind === 'vm' && infra.data.value!.nodes.some((n) => belongs(n, row) && belongs(g, n))).length : 0 }}</template>
          <template #cell-lxc="{ row }">{{ infra.data.value.guests.filter((g) => g.kind === 'lxc' && infra.data.value!.nodes.some((n) => belongs(n, row) && belongs(g, n))).length }}</template>
          <template #cell-guests="{ row }">{{ count(row, infra.data.value.guests) }}</template>
          <template #cell-cpu="{ row }"><div class="meter"><ProgressBar :pct="row.cpu" :label="'CPU ' + row.name" /><span class="small">{{ fmtPct(row.cpu) }}</span></div></template>
          <template #cell-mem="{ row }"><div class="meter"><ProgressBar :pct="row.mem" :label="'Memory ' + row.name" /><span class="small">{{ fmtPct(row.mem) }}</span></div></template>
          <template #cell-disk="{ row }"><div class="meter"><ProgressBar :pct="row.disk" :label="'Used ' + row.name" /><span class="small">{{ fmtPct(row.disk) }}</span></div></template>
          <template #cell-type="{ row }">{{ rawStr(row, 'type') }}</template>
        </DataTable>
        <p v-if="!rows.length" class="empty">No match for "{{ q }}".</p>
      </template>
    </Card>
  </div>
</template>
