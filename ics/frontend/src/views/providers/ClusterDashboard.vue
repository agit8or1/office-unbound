<script setup lang="ts">
// Cluster dashboard: status, nodes, utilisation, guests, deployable capacity, alerts and recent activity. All figures come from the collected inventory.
import { computed, ref, watch } from 'vue'
import { useLoad } from '../../store'
import { ago } from '../../format'
import { RANGES } from '../../charts/geometry'
import LineChart from '../../charts/LineChart.vue'
import Card from '../../ui/Card.vue'
import StatCard from '../../ui/StatCard.vue'
import ProgressBar from '../../ui/ProgressBar.vue'
import Segmented from '../../ui/Segmented.vue'
import Button from '../../ui/Button.vue'
import EmptyState from '../../ui/EmptyState.vue'
import ErrorBox from '../../components/ErrorBox.vue'
import StatusBadge from '../../ui/StatusBadge.vue'
import ClusterHeader from './ClusterHeader.vue'
import NextSteps from './NextSteps.vue'
import { api, load } from './api'
import { accessApi } from './access/api'
import {
  capacityHeadroom, credentialState, credentialsFor, driftItems, fmtBytes, healthTone, mergeSeries, pctOf, policyStatus, ratioSeries, toPoints,
  type InfraGuest, type InfraNode, type InfraStorage, type Pt,
} from './model'
import './providers.css'

const props = defineProps<{ id: string }>()
const data = useLoad(async () => {
  const [ep, nodes, storage, guests] = await Promise.all([api.endpoint(props.id), api.nodes(props.id), api.storage(props.id), api.guests(props.id)])
  const [perms, creds, inc, audit] = await Promise.all([load(() => api.permissions(props.id)), load(() => api.credentials()), load(() => api.incidents()), load(() => api.audit(60))])
  return { ep, nodes, storage, guests, perms: perms.state === 'ok' ? perms.data : null, creds: creds.state === 'ok' ? credentialsFor(ep, creds.data) : [], incidents: inc.state === 'ok' ? inc.data : [], audit }
}, 30000)
const d = computed(() => data.data.value)
const cap = computed(() => (d.value ? capacityHeadroom(d.value.nodes, d.value.storage, d.value.ep.scope, d.value.guests) : null))
const allowedNodes = computed(() => d.value?.perms?.scope?.nodes ?? [])
const onlineNodes = computed(() => d.value?.nodes.filter((n) => n.status === 'online') ?? [])
const uniqueStorage = computed(() => { const seen = new Set<string>(); return (d.value?.storage ?? []).filter((s) => (seen.has(s.name) ? false : (seen.add(s.name), true))) })
const authorised = (name: string) => d.value?.ep.scope.allowed_storage.includes(name)

// ---- charts from /infra/metrics (real samples only)
const range = ref('24h')
const rangeMs = computed(() => RANGES.find((r) => r.value === range.value)?.ms ?? 86400e3)
const series = ref<{ cpu: Pt[]; mem: Pt[]; sto: Pt[] }>({ cpu: [], mem: [], sto: [] })
const chartState = ref<'loading' | 'ok' | 'empty' | 'error'>('loading')
async function loadCharts() {
  const nodes = (d.value?.nodes ?? []).filter((n) => n.managed && n.status === 'online'), stor = uniqueStorage.value.filter((s) => s.total)
  if (!nodes.length) { chartState.value = 'empty'; return }
  chartState.value = 'loading'
  try {
    const get = async (scope: 'node' | 'storage', rows: { id: string }[], metric: string) => (await Promise.all(rows.map((r) => api.metric(scope, r.id, metric, range.value).then(toPoints)))).filter((p) => p.length)
    const [cpu, mu, mt, su, st] = await Promise.all([get('node', nodes, 'cpu_pct'), get('node', nodes, 'mem_used_bytes'), get('node', nodes, 'mem_total_bytes'), get('storage', stor, 'used_bytes'), get('storage', stor, 'total_bytes')])
    series.value = { cpu: mergeSeries(cpu, 'mean'), mem: ratioSeries(mergeSeries(mu, 'sum'), mergeSeries(mt, 'sum')), sto: ratioSeries(mergeSeries(su, 'sum'), mergeSeries(st, 'sum')) }
    chartState.value = series.value.cpu.length || series.value.mem.length || series.value.sto.length ? 'ok' : 'empty'
  } catch { chartState.value = 'error' }
}
watch([() => d.value?.nodes.map((n) => n.id).join(), range], loadCharts, { immediate: true })
const last = (p: Pt[]) => (p.length ? `${Math.round(p[p.length - 1]!.v)}%` : '-')
const pctFmt = (v: number) => `${Math.round(v)}%`

// ---- inventory changes (never authorizes anything; opens Manage access)
const acc = useLoad(() => accessApi.access(props.id), 120000)

// ---- alerts
const alerts = computed(() => {
  const x = d.value; if (!x) return []
  const out: { tone: 'bad' | 'warn' | 'info'; text: string; to?: string }[] = []
  const ac = acc.data.value?.counts
  if (ac?.new) out.push({ tone: 'info', text: `${ac.new} new infrastructure resource(s) created outside Office Unbound (review them in Manage access; nothing is authorized by this).`, to: `/infrastructure/providers/${props.id}/access` })
  if (ac?.changed) out.push({ tone: 'warn', text: `${ac.changed} authorized resource(s) were renamed, moved or re-created in Proxmox.`, to: `/infrastructure/providers/${props.id}/access` })
  if (ac?.missing) out.push({ tone: 'warn', text: `${ac.missing} authorized resource(s) are no longer found in Proxmox.`, to: `/infrastructure/providers/${props.id}/access` })
  if (x.ep.health.status === 'critical' || x.ep.health.status === 'warning') out.push({ tone: x.ep.health.status === 'critical' ? 'bad' : 'warn', text: x.ep.health.reason ?? 'The cluster needs attention.' })
  for (const w of x.ep.last_discovery.warnings) out.push({ tone: 'warn', text: w })
  const ps = policyStatus(x.perms)
  const di = driftItems(x.perms?.last_drift)
  if (x.perms?.managed_by_provisioning && ps.tone !== 'ok' && !(ps.text === 'Drift detected' && di.length)) out.push({ tone: ps.tone === 'bad' ? 'bad' : 'warn', text: `${ps.text}: ${ps.detail}`, to: `/infrastructure/providers/${props.id}/permissions` })
  if (di.length) out.push({ tone: 'warn', text: `${di.length} permission difference(s) from the approved policy.`, to: `/infrastructure/providers/${props.id}/permissions` })
  for (const c of x.creds) { const s = credentialState(c); if (s.tone === 'warn' || s.tone === 'bad') out.push({ tone: s.tone, text: `Credential ${c.label}: ${s.text}.`, to: `/infrastructure/providers/${props.id}/credentials` }) }
  for (const n of x.nodes) if (n.status !== 'online' && n.managed) out.push({ tone: 'bad', text: `Node ${n.name} is ${n.status}.`, to: `/infrastructure/nodes/${n.id}` })
  for (const s of uniqueStorage.value) { const p = pctOf(s.used, s.total); if (p !== null && p >= 85) out.push({ tone: p >= 95 ? 'bad' : 'warn', text: `Storage ${s.name} is ${Math.round(p)}% full.`, to: `/infrastructure/storage/${s.id}` }) }
  return out
})
const activity = computed(() => {
  const a = d.value?.audit
  if (!a || a.state !== 'ok') return a?.state ?? 'loading'
  return a.data.filter((e) => e.resource_id === props.id || /^(provider|endpoint|credential)\./.test(e.action)).slice(0, 8)
})
const guestPath = (g: InfraGuest) => `/infrastructure/${g.kind === 'lxc' ? 'containers' : 'vms'}/${g.id}`
const nodeMem = (n: InfraNode) => pctOf(n.mem_used, n.mem_total)
</script>

<template>
  <div class="pv">
    <ClusterHeader :id="id" :ep="d?.ep ?? null" />
    <ErrorBox v-if="data.error.value" :error="data.error.value" />
    <template v-if="d && cap">
      <div class="pv-stats">
        <StatCard label="Connection" :value="d.ep.enabled ? ({ ok: 'Healthy', warning: 'Attention', critical: 'Problem', unknown: 'Unknown' } as Record<string, string>)[d.ep.health.status] ?? d.ep.health.status : 'Paused'" :tone="healthTone(d.ep.health.status)" icon="plug" :sub="'Synced ' + ago(d.ep.last_discovery.at)" />
        <StatCard label="Nodes online" :value="onlineNodes.length" :of="d.nodes.length" icon="server" :tone="onlineNodes.length === d.nodes.length ? 'ok' : 'bad'" :sub="allowedNodes.length ? allowedNodes.length + ' authorised' : 'no node limit set'" />
        <StatCard label="Running" :value="cap.running" :of="d.guests.length" icon="vm" tone="info" :sub="`${cap.vmsRunning} VMs, ${cap.ctsRunning} containers`" />
        <StatCard label="Stopped" :value="cap.stopped" icon="box" tone="idle" :sub="`${cap.vmsStopped} VMs, ${cap.ctsStopped} containers`" />
        <StatCard label="Room to deploy" :value="cap.authorisedStorage ? fmtBytes(cap.diskFree) : 'Not set'" icon="rocket" :tone="cap.authorisedStorage ? 'ok' : 'warn'" :sub="cap.authorisedStorage ? `free on ${cap.authorisedStorage} authorised storage, ${fmtBytes(cap.memFree)} memory` : 'Authorise storage to plan deployments'" />
      </div>

      <div v-if="alerts.length" class="card pv-alerts"><h2>Needs attention</h2>
        <ul><li v-for="(a, i) in alerts" :key="i" :class="a.tone"><span class="badge" :class="a.tone">{{ a.tone === 'bad' ? 'Problem' : 'Warning' }}</span> <router-link v-if="a.to" :to="a.to">{{ a.text }}</router-link><span v-else>{{ a.text }}</span></li></ul></div>
      <div v-else class="card pv-ok"><span class="badge ok">All clear</span> Nothing needs attention on this cluster.<template v-if="d.incidents.length"> There are {{ d.incidents.length }} active health-check incident(s) elsewhere in the console. <router-link to="/incidents">View</router-link></template></div>

      <NextSteps :id="id" hide-when-done />

      <Card title="Utilisation" hint="Average across nodes and authorised storage from collected samples">
        <template #actions><Segmented v-model="range" :options="RANGES.map((r) => ({ value: r.value, label: r.label }))" label="Time range" /></template>
        <EmptyState v-if="chartState === 'empty'" compact icon="activity" title="Collecting samples" text="Charts fill in once metrics have been collected for this cluster." />
        <EmptyState v-else-if="chartState === 'error'" compact icon="alert" title="Metrics are unavailable" text="We could not load utilisation right now." ><Button size="sm" @click="loadCharts">Retry</Button></EmptyState>
        <div v-else class="charts">
          <div class="chartbox"><div class="ct"><span>CPU</span><b>{{ last(series.cpu) }}</b></div><LineChart :series="[{ name: 'CPU', points: series.cpu }]" :range-ms="rangeMs" :fmt="pctFmt" :y-max="100" /></div>
          <div class="chartbox"><div class="ct"><span>Memory</span><b>{{ last(series.mem) }}</b></div><LineChart :series="[{ name: 'Memory', points: series.mem }]" :range-ms="rangeMs" :fmt="pctFmt" :y-max="100" /></div>
          <div class="chartbox"><div class="ct"><span>Storage</span><b>{{ last(series.sto) }}</b></div><LineChart :series="[{ name: 'Storage', points: series.sto }]" :range-ms="rangeMs" :fmt="pctFmt" :y-max="100" /></div>
        </div>
      </Card>

      <div class="grid cols-2">
        <Card title="Nodes" hint="Select one for details" flush>
          <div class="tablewrap"><table><thead><tr><th>Node</th><th>Status</th><th>CPU</th><th>Memory</th><th>Authorised</th></tr></thead><tbody>
            <tr v-for="n in d.nodes" :key="n.id"><td><router-link :to="`/infrastructure/nodes/${n.id}`">{{ n.name }}</router-link></td><td><StatusBadge :s="n.managed ? n.status : 'unknown'" :text="n.managed ? undefined : 'not visible'" /></td>
              <td><ProgressBar :pct="n.managed ? n.cpu_pct : null" :label="n.name + ' CPU'" /></td><td><ProgressBar :pct="n.managed ? nodeMem(n) : null" :label="n.name + ' memory'" /></td>
              <td>{{ allowedNodes.length ? (allowedNodes.includes(n.name) ? 'Yes' : 'No') : 'No limit' }}</td></tr>
          </tbody></table></div>
        </Card>
        <Card title="Storage" hint="Authorised storage can receive new disks" flush>
          <div class="tablewrap"><table><thead><tr><th>Storage</th><th>Used</th><th>Free</th><th>Authorised</th></tr></thead><tbody>
            <tr v-for="s in uniqueStorage" :key="s.id"><td><router-link :to="`/infrastructure/storage/${s.id}`">{{ s.name }}</router-link><div class="muted small">{{ s.type }}</div></td>
              <td><ProgressBar :pct="pctOf(s.used, s.total)" :label="s.name + ' used'" /></td><td class="num">{{ s.total ? fmtBytes(s.total - (s.used ?? 0)) : '-' }}</td><td><span class="badge" :class="authorised(s.name) ? 'ok' : 'idle'">{{ authorised(s.name) ? 'Yes' : 'No' }}</span></td></tr>
            <tr v-if="!uniqueStorage.length"><td colspan="4" class="muted">No storage discovered yet.</td></tr>
          </tbody></table></div>
        </Card>
      </div>

      <div class="grid cols-2">
        <Card title="Virtual machines and containers" hint="Newest first, up to 8" flush>
          <div class="tablewrap"><table><thead><tr><th>Name</th><th>Type</th><th>Node</th><th>State</th></tr></thead><tbody>
            <tr v-for="g in [...d.guests].sort((a, b) => b.vmid - a.vmid).slice(0, 8)" :key="g.id"><td><router-link :to="guestPath(g)">{{ g.name ?? 'VM ' + g.vmid }}</router-link> <span class="muted small mono">#{{ g.vmid }}</span></td><td>{{ g.kind === 'lxc' ? 'Container' : 'VM' }}</td><td>{{ g.node }}</td><td><StatusBadge :s="g.status" /></td></tr>
            <tr v-if="!d.guests.length"><td colspan="4" class="muted">No guests discovered yet.</td></tr>
          </tbody></table></div>
        </Card>
        <Card title="Recent activity" hint="Changes made through Office Unbound">
          <p v-if="activity === 'forbidden'" class="muted small">The audit log is visible to approvers.</p>
          <p v-else-if="activity === 'unavailable' || activity === 'error'" class="muted small">Activity is unavailable.</p>
          <ul v-else-if="Array.isArray(activity) && activity.length" class="pv-activity"><li v-for="e in activity" :key="e.seq"><b>{{ e.action.replace(/[._]/g, ' ') }}</b><span class="muted small"> by {{ e.actor_name ?? 'system' }}, {{ ago(e.at) }}</span></li></ul>
          <p v-else class="muted small">No activity recorded for this cluster yet.</p>
          <Button size="sm" variant="ghost" to="/audit">Open the audit log</Button>
        </Card>
      </div>
    </template>
  </div>
</template>
