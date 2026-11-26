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
import AppsDashboard from '../components/AppsDashboard.vue'
import UtilizationPanel from '../components/UtilizationPanel.vue'
import Card from '../ui/Card.vue'
import StatCard from '../ui/StatCard.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import PageHeader from '../ui/PageHeader.vue'
import Button from '../ui/Button.vue'
import EmptyState from '../ui/EmptyState.vue'
import Icon from '../ui/Icon.vue'
import { guestVisibilityNote } from './providers/nextSteps'

const EMPTY: Infra = { clusters: [], nodes: [], storage: [], networks: [], guests: [], connected: false, missing: true }
const infra = useLoad(loadInfra, 30000)
const checks = useLoad(() => get<Check[]>('checks'), 15000)
const incidents = useLoad(() => get<Incident[]>('incidents?status=active&limit=100'), 15000)
const jobs = useLoad(() => get<Job[]>('jobs'), 15000)
const plans = useLoad(() => get<Plan[]>('plans'), 15000)
const deployments = useLoad(loadDeployments, 30000)
const windows = useLoad(async () => (await tryGet<MaintenanceWindow[]>('maintenance', [])).data, 60000)
const ready = useLoad(async () => { const r = await fetch('/readyz', { credentials: 'same-origin' }); try { return (await r.json()) as Ready } catch { return null } }, 30000)

// whether 0 / 0 guests means "none exist" or "the read token only sees Office Unbound's own pool" (approved policy, GET /infra/summary)
const summary = useLoad(async () => (await tryGet<{ guest_visibility?: string; guest_visibility_limited?: { endpoint_id: string; name: string }[] } | null>('infra/summary', null)).data, 60000)
const visNote = computed(() => guestVisibilityNote(summary.data.value))

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
// a failure stays listed only until the same action succeeds again (owner 2026-11-26 overview clean-up: five long-fixed failures read as an outage)
const failedJobs = computed(() => {
  const all = jobs.data.value ?? []
  const lastOk = new Map<string, number>()
  for (const j of all) if (j.status === 'succeeded') lastOk.set(j.action, Math.max(lastOk.get(j.action) ?? 0, +new Date(j.created_at)))
  return all.filter((j) => j.status === 'failed' && now.value - +new Date(j.created_at) < 7 * 86400e3 && +new Date(j.created_at) > (lastOk.get(j.action) ?? 0)).slice(0, 5)
})
const failedDeploys = computed(() => (deployments.data.value?.data ?? []).filter((d) => d.status === 'failed'))
const recent = computed(() => (jobs.data.value ?? []).filter((j) => j.status === 'succeeded' || j.status === 'failed').slice(0, 6))
const activeWindows = computed(() => (windows.data.value ?? []).filter((w) => w.active))
const upcoming = computed(() => (windows.data.value ?? []).filter((w) => !w.active && +new Date(w.starts_at) > now.value))

const scopes = computed(() => i.value.nodes.filter((n) => n.raw.managed !== false).map((n) => ({ scope: 'node', id: n.id, name: n.name })))
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

    <section class="statgrid" aria-label="Status summary">
      <StatCard label="Infrastructure health" :value="health.text" :sub="health.sub" icon="shield" to="/monitoring/infrastructure" :tone="health.tone" :loading="!loaded" />
      <StatCard label="Clusters" :value="i.clusters.length" :sub="i.clusters.length ? i.clusters.filter((c) => isUp(c.status)).length + ' online' : 'None connected'" icon="cluster" :tone="i.clusters.some((c) => isDown(c.status)) ? 'bad' : i.clusters.length ? 'ok' : 'idle'" to="/infrastructure/clusters" :loading="!loaded" />
      <StatCard label="Nodes" :value="nodesUp" :of="i.nodes.length" :sub="!i.nodes.length ? 'None connected' : i.nodes.length - nodesUp ? i.nodes.length - nodesUp + ' not online' : 'All online'" icon="server" :tone="!i.nodes.length ? 'idle' : nodesUp < i.nodes.length ? 'bad' : 'ok'" to="/infrastructure/nodes" :loading="!loaded" />
      <StatCard label="Virtual machines" :value="runningGuests(vms).length" :of="vms.length" :sub="visNote ? 'running · Office Unbound guests only' : 'running'" icon="vm" :tone="vms.length ? 'info' : 'idle'" to="/infrastructure/vms" :loading="!loaded" />
      <StatCard label="Containers" :value="runningGuests(lxc).length" :of="lxc.length" :sub="visNote ? 'running · Office Unbound guests only' : 'running'" icon="box" :tone="lxc.length ? 'info' : 'idle'" to="/infrastructure/containers" :loading="!loaded" />
      <StatCard label="Active deployments" :value="deployments.data.value?.state === 'ok' ? activeDeploys.length : '-'" :sub="deployments.data.value?.state === 'ok' ? 'in progress' : 'None yet'" icon="rocket" :tone="activeDeploys.length ? 'info' : 'idle'" to="/deployments" :loading="!loaded" />
      <StatCard label="Pending operations" :value="pendingOps" :sub="`${pendingPlans.length} awaiting approval, ${activeJobs.length} running`" icon="list" :tone="pendingPlans.length ? 'warn' : 'idle'" to="/plans" :loading="!loaded" />
      <StatCard label="Active incidents" :value="inc.length" :sub="inc.length ? inc.filter((x) => x.severity === 'critical').length + ' critical' : 'All clear'" icon="bell" :tone="inc.some((x) => x.severity === 'critical') ? 'bad' : inc.length ? 'warn' : 'ok'" to="/incidents" :loading="!loaded" />
    </section>
    <p v-if="visNote" class="muted small vis-note" data-testid="guest-visibility-note"><Icon name="info" />{{ visNote.text }} <router-link :to="visNote.to">Manage access</router-link></p>

    <Card title="Active incidents" :hint="inc.length ? 'Most severe first. Each shows the affected resource, how long it has lasted, and what to do next.' : undefined">
      <template #actions><Button size="sm" variant="ghost" to="/incidents">All incidents</Button></template>
      <IncidentList v-if="inc.length" :incidents="inc" :now="now" :limit="5" />
      <div v-else class="allclear"><Icon name="check" />No active incidents. All monitored services are healthy.</div>
    </Card>

    <div v-if="loaded && !i.connected" class="card">
      <EmptyState icon="cluster" title="Connect your first Proxmox cluster" text="Sign in to Proxmox once, tick exactly what Office Unbound may use, and it sets up its own restricted access. You see every change before anything is saved. Afterwards this dashboard fills with live node, VM and storage status, utilization charts and a health matrix.">
        <Button variant="primary" icon="plus" to="/infrastructure/providers/proxmox/connect">Start guided setup</Button>
      </EmptyState>
      <ol class="steps3" aria-label="Getting started">
        <li><b>1. Connect</b><span>Add your Proxmox cluster with the guided setup.</span></li>
        <li><b>2. Deploy</b><span>Pick a size; ICS plans and shows every change first.</span></li>
        <li><b>3. Invite users</b><span>Add colleagues under Administration, Users and roles.</span></li>
      </ol>
    </div>
    <div v-else-if="loaded && deployments.data.value && !deployments.data.value.data.length && hasPath('/deployments/new')" class="card">
      <EmptyState icon="rocket" title="Deploy Office Unbound" text="Your cluster is connected. Pick a size and ICS plans the virtual machines, shows you exactly what it will create, and runs it after approval.">
        <Button variant="primary" icon="plus" to="/deployments/new">Start deployment wizard</Button>
      </EmptyState>
    </div>
    <AppsDashboard />

    <!-- two columns that fill independently: metrics and health on the left, the short cards stacked on the right (no stretched, half-empty cards) -->
    <div class="grid main-side ovcols">
      <div class="ovcol">
        <UtilizationPanel v-if="i.connected" :scopes="scopes" :connected="i.connected" />
        <HealthMatrix :infra="i" :checks="checks.data.value ?? []" />
      </div>
      <div class="ovcol">
      <Card v-if="i.connected" title="Distribution" hint="Where your guests live">
        <div v-if="i.guests.length" class="dist">
          <template v-for="grp in [{ t: 'By state', items: guestDist }, { t: 'By node', items: perNode }]" :key="grp.t">
            <p v-if="grp.items.length" class="subhead">{{ grp.t }}</p>
            <ul v-if="grp.items.length" class="bars">
              <li v-for="x in grp.items" :key="x.label"><span class="bl">{{ x.label }}</span>
                <span class="bt"><span class="bf" :style="{ width: Math.max(4, Math.round(100 * x.value / i.guests.length)) + '%' }" /></span><b>{{ x.value }}</b></li>
            </ul>
          </template>
        </div>
        <EmptyState v-else compact icon="vm" title="No guests yet" text="Virtual machines and containers show up here once discovered or deployed." />
      </Card>
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
  </div>
</template>
<style scoped>
.ovcols { align-items: start; }
.ovcol { display: flex; flex-direction: column; gap: 18px; min-width: 0; }
.bars { list-style: none; margin: 0 0 6px; padding: 0; display: grid; gap: 8px; }
.bars li { display: grid; grid-template-columns: minmax(64px, 30%) 1fr auto; gap: 10px; align-items: center; font-size: 13px; }
.bars .bl { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); }
.bars .bt { height: 8px; border-radius: 4px; background: var(--surface2); overflow: hidden; }
.bars .bf { display: block; height: 100%; border-radius: 4px; background: var(--teal); }
.bars b { font-variant-numeric: tabular-nums; min-width: 2ch; text-align: right; }
.vis-note { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: -4px 0 0; }
.vis-note svg { width: 16px; height: 16px; flex: none; }
</style>
