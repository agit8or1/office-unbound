<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { get, type Check, type Incident, type Job, type Plan, type Ready } from '../api'
import { useLoad } from '../store'
import { ago } from '../format'
import { DEPLOY_ACTIVE, infraHealth, isDown, isUp, loadDeployments, loadInfra, runningGuests, tryGet, type Infra, type MaintenanceWindow } from '../infra'
import { hasPath } from '../router'
import ErrorBox from '../components/ErrorBox.vue'
import HealthMatrix from '../components/HealthMatrix.vue'
import IncidentList from '../components/IncidentList.vue'
import UtilizationPanel from '../components/UtilizationPanel.vue'
import Donut from '../charts/Donut.vue'
import Card from '../ui/Card.vue'
import StatCard from '../ui/StatCard.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import PageHeader from '../ui/PageHeader.vue'
import Button from '../ui/Button.vue'
import EmptyState from '../ui/EmptyState.vue'
import Icon from '../ui/Icon.vue'

const EMPTY: Infra = { clusters: [], nodes: [], storage: [], networks: [], guests: [], connected: false, missing: true }
const infra = useLoad(loadInfra, 30000)
const checks = useLoad(() => get<Check[]>('checks'), 15000)
const incidents = useLoad(() => get<Incident[]>('incidents?status=active&limit=100'), 15000)
const jobs = useLoad(() => get<Job[]>('jobs'), 15000)
const plans = useLoad(() => get<Plan[]>('plans'), 15000)
const deployments = useLoad(loadDeployments, 30000)
const windows = useLoad(async () => (await tryGet<MaintenanceWindow[]>('maintenance', [])).data, 60000)
const ready = useLoad(async () => { const r = await fetch('/readyz', { credentials: 'same-origin' }); try { return (await r.json()) as Ready } catch { return null } }, 30000)

const now = ref(Date.now())
let tick: number | undefined
onMounted(() => { tick = window.setInterval(() => { now.value = Date.now() }, 30000) })
onUnmounted(() => clearInterval(tick))

const i = computed(() => infra.data.value ?? EMPTY)
const loaded = computed(() => infra.data.value !== null && checks.data.value !== null)
const inc = computed(() => incidents.data.value ?? [])
const critical = computed(() => (checks.data.value ?? []).filter((c) => c.state === 'critical').length)
const warning = computed(() => (checks.data.value ?? []).filter((c) => c.state === 'warning').length)
const health = computed(() => infraHealth(i.value, critical.value, warning.value, inc.value.length))
const vms = computed(() => i.value.guests.filter((g) => g.kind === 'vm'))
const lxc = computed(() => i.value.guests.filter((g) => g.kind === 'lxc'))
const nodesUp = computed(() => i.value.nodes.filter((n) => isUp(n.status)).length)
const activeDeploys = computed(() => (deployments.data.value?.data ?? []).filter((d) => DEPLOY_ACTIVE.includes(d.status)))
const pendingPlans = computed(() => (plans.data.value ?? []).filter((p) => p.status === 'pending_approval'))
const activeJobs = computed(() => (jobs.data.value ?? []).filter((j) => j.status === 'running' || j.status === 'queued'))
const pendingOps = computed(() => pendingPlans.value.length + activeJobs.value.length)
const failedJobs = computed(() => (jobs.data.value ?? []).filter((j) => j.status === 'failed' && now.value - +new Date(j.created_at) < 7 * 86400e3).slice(0, 5))
const failedDeploys = computed(() => (deployments.data.value?.data ?? []).filter((d) => d.status === 'failed'))
const recent = computed(() => (jobs.data.value ?? []).filter((j) => j.status === 'succeeded' || j.status === 'failed').slice(0, 6))
const activeWindows = computed(() => (windows.data.value ?? []).filter((w) => w.active))
const upcoming = computed(() => (windows.data.value ?? []).filter((w) => !w.active && +new Date(w.starts_at) > now.value))

const scopes = computed(() => i.value.clusters.length ? i.value.clusters.map((c) => ({ scope: 'cluster', id: c.id, name: c.name })) : [])
const guestDist = computed(() => [
  { label: 'Running', value: i.value.guests.filter((g) => g.status === 'running').length },
  { label: 'Stopped', value: i.value.guests.filter((g) => ['stopped', 'shutdown'].includes(g.status)).length },
  { label: 'Other', value: i.value.guests.filter((g) => !['running', 'stopped', 'shutdown'].includes(g.status)).length },
].filter((x) => x.value > 0))
const perNode = computed(() => i.value.nodes.map((n) => ({ label: n.name, value: i.value.guests.filter((g) => g.nodeName === n.name || g.nodeId === n.id).length })).filter((x) => x.value > 0).slice(0, 4))
const err = computed(() => checks.error.value ?? incidents.error.value ?? jobs.error.value ?? plans.error.value)
const refresh = () => { for (const l of [infra, checks, incidents, jobs, plans, deployments, windows, ready]) void l.reload() }
const notReady = computed(() => ready.data.value && !ready.data.value.ready ? Object.entries(ready.data.value.checks).filter(([, v]) => !v.ok).map(([k]) => k) : [])
</script>
<template>
  <div class="page">
    <PageHeader title="Overview" sub="Live status of your infrastructure, deployments and incidents." help="Counts and charts are real data from connected clusters, health checks and jobs. Nothing here is estimated.">
      <template #actions><Button size="sm" icon="refresh" @click="refresh">Refresh</Button></template>
    </PageHeader>
    <ErrorBox :error="err" />
    <div v-if="notReady.length" class="alert warn" role="alert"><Icon name="alert" /><span>ICS service component not ready: {{ notReady.join(', ').replace('_', ' ') }}. Operations may be delayed.</span></div>

    <div v-if="loaded && !i.connected" class="card">
      <EmptyState icon="cluster" title="Connect your first Proxmox cluster" text="Once a cluster is connected, this dashboard fills with live node, VM and storage status, utilization charts and a health matrix. Health checks and jobs already work.">
        <Button variant="primary" icon="plus" :to="hasPath('/setup') ? '/setup' : '/endpoints'">{{ hasPath('/setup') ? 'Start setup wizard' : 'Add a cluster' }}</Button>
      </EmptyState>
    </div>

    <section class="statgrid" aria-label="Status summary">
      <StatCard label="Infrastructure health" :value="health.text" :sub="health.sub" icon="shield" :tone="health.tone" :loading="!loaded" />
      <StatCard label="Clusters" :value="i.clusters.length" :sub="i.clusters.length ? i.clusters.filter((c) => isUp(c.status)).length + ' online' : 'None connected'" icon="cluster" :tone="i.clusters.some((c) => isDown(c.status)) ? 'bad' : i.clusters.length ? 'ok' : 'idle'" to="/infrastructure/clusters" :loading="!loaded" />
      <StatCard label="Nodes" :value="nodesUp" :of="i.nodes.length" :sub="i.nodes.length - nodesUp ? i.nodes.length - nodesUp + ' not online' : 'All online'" icon="server" :tone="!i.nodes.length ? 'idle' : nodesUp < i.nodes.length ? 'bad' : 'ok'" to="/infrastructure/nodes" :loading="!loaded" />
      <StatCard label="Virtual machines" :value="runningGuests(vms).length" :of="vms.length" sub="running" icon="vm" :tone="vms.length ? 'info' : 'idle'" to="/infrastructure/vms" :loading="!loaded" />
      <StatCard label="Containers" :value="runningGuests(lxc).length" :of="lxc.length" sub="running" icon="box" :tone="lxc.length ? 'info' : 'idle'" to="/infrastructure/containers" :loading="!loaded" />
      <StatCard label="Active deployments" :value="deployments.data.value?.state === 'ok' ? activeDeploys.length : '-'" :sub="deployments.data.value?.state === 'ok' ? 'in progress' : 'None yet'" icon="rocket" :tone="activeDeploys.length ? 'warn' : 'idle'" to="/deployments" :loading="!loaded" />
      <StatCard label="Pending operations" :value="pendingOps" :sub="`${pendingPlans.length} awaiting approval, ${activeJobs.length} running`" icon="list" :tone="pendingPlans.length ? 'warn' : 'idle'" to="/plans" :loading="!loaded" />
      <StatCard label="Active incidents" :value="inc.length" :sub="inc.length ? inc.filter((x) => x.severity === 'critical').length + ' critical' : 'All clear'" icon="bell" :tone="inc.some((x) => x.severity === 'critical') ? 'bad' : inc.length ? 'warn' : 'ok'" to="/incidents" :loading="!loaded" />
    </section>

    <Card title="Active incidents" :hint="inc.length ? 'Most severe first. Each shows the affected resource, how long it has lasted, and what to do next.' : undefined">
      <template #actions><Button size="sm" variant="ghost" to="/incidents">All incidents</Button></template>
      <IncidentList v-if="inc.length" :incidents="inc" :now="now" :limit="5" />
      <div v-else class="allclear"><Icon name="check" />No active incidents. All monitored services are healthy.</div>
    </Card>

    <div v-if="i.connected" class="grid main-side">
      <UtilizationPanel :scopes="scopes" :connected="i.connected" />
      <Card title="Distribution" hint="Where your guests live">
        <div v-if="i.guests.length">
          <p class="subhead">By state</p>
          <Donut :items="guestDist" caption="guests" />
          <p v-if="perNode.length" class="subhead">By node</p>
          <Donut v-if="perNode.length" :items="perNode" caption="guests" />
        </div>
        <EmptyState v-else compact icon="vm" title="No guests yet" text="Virtual machines and containers show up here once discovered or deployed." />
      </Card>
    </div>

    <div class="grid main-side">
      <HealthMatrix :infra="i" :checks="checks.data.value ?? []" />
      <Card title="Deployment activity">
        <template #actions><Button size="sm" variant="ghost" to="/deployments">Deployments</Button></template>
        <p class="subhead">In progress</p>
        <ul v-if="activeDeploys.length || activeJobs.length" class="feed">
          <li v-for="d in activeDeploys" :key="d.id"><StatusBadge :s="d.status" /><router-link class="t" :to="'/deployments/' + d.id">{{ d.name }}</router-link></li>
          <li v-for="j in activeJobs.slice(0, 4)" :key="j.id"><StatusBadge :s="j.status" /><router-link class="t" :to="'/jobs/' + j.id">{{ j.action }}</router-link><span class="w">{{ ago(j.created_at, now) }}</span></li>
        </ul>
        <p v-else class="muted small">Nothing running.</p>
        <p class="subhead">Pending approvals</p>
        <ul v-if="pendingPlans.length" class="feed">
          <li v-for="p in pendingPlans.slice(0, 4)" :key="p.id"><StatusBadge :s="p.risk" :text="p.risk + ' risk'" /><router-link class="t" :to="'/plans/' + p.id">{{ p.action }}</router-link><span class="w">{{ ago(p.created_at, now) }}</span></li>
        </ul>
        <p v-else class="muted small">No plans waiting for approval.</p>
        <p v-if="failedJobs.length || failedDeploys.length" class="subhead">Failed</p>
        <ul v-if="failedJobs.length || failedDeploys.length" class="feed">
          <li v-for="d in failedDeploys" :key="d.id"><StatusBadge s="failed" /><router-link class="t" :to="'/deployments/' + d.id">{{ d.name }}</router-link></li>
          <li v-for="j in failedJobs" :key="j.id"><StatusBadge s="failed" /><router-link class="t" :to="'/jobs/' + j.id">{{ j.action }}</router-link><span class="w">{{ ago(j.created_at, now) }}</span></li>
        </ul>
        <p class="subhead">Maintenance</p>
        <ul v-if="activeWindows.length || upcoming.length" class="feed">
          <li v-for="w in activeWindows" :key="w.id"><StatusBadge s="maintenance" text="active" /><span class="t">{{ w.name }}</span></li>
          <li v-for="w in upcoming.slice(0, 2)" :key="w.id"><StatusBadge s="planned" text="scheduled" /><span class="t">{{ w.name }}</span><span class="w">{{ new Date(w.starts_at).toLocaleDateString() }}</span></li>
        </ul>
        <p v-else class="muted small">No maintenance windows.</p>
        <p class="subhead">Recent changes</p>
        <ul v-if="recent.length" class="feed">
          <li v-for="j in recent" :key="j.id"><StatusBadge :s="j.status" /><router-link class="t" :to="'/jobs/' + j.id">{{ j.action }}</router-link><span class="w">{{ ago(j.finished_at ?? j.created_at, now) }}</span></li>
        </ul>
        <p v-else class="muted small">No completed jobs yet.</p>
      </Card>
    </div>
  </div>
</template>
