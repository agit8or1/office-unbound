<script setup lang="ts">
// Consolidated read-only view of every connected cluster (multi-cluster): quorum, nodes, guests, HA, backups, storage with a capacity
// projection, data freshness and the alert rules configured. Values that were not collected are shown as unknown, never estimated.
import { reactive } from 'vue'
import { get, post, type PlanCreated } from '../../api'
import { fmtBytes, hasRole, useLoad } from '../../store'
import PageHeader from '../../ui/PageHeader.vue'
import Card from '../../ui/Card.vue'
import EmptyState from '../../ui/EmptyState.vue'
import Button from '../../ui/Button.vue'
import ProgressBar from '../../ui/ProgressBar.vue'
import ErrorBox from '../../components/ErrorBox.vue'
import { STANDARD_RULES, planParams } from './standardAlerts'

interface Proj { days_to_full: number | null; note: string; growth_bytes_per_day?: number; basis?: string }
interface Sto { name: string; node: string; shared: boolean; active: boolean | null; used: number | null; total: number | null; pct: number | null; projection: Proj }
interface Cl {
  endpoint_id: string; name: string; cluster: string | null; version: string | null; quorate: boolean | null
  freshness: { last_discovery_at: string | null; age_seconds: number | null; stale: boolean; ok: boolean | null; error: string | null }
  nodes: { total: number; online: number; monitored: number }; guests: { total: number; running: number; managed: number }
  ha: { services: number; problems: number } | null
  backups: { guests: number; backed_up_recently: number; never: number; window_hours: number; failed_tasks: number | null } | null
  storage: Sto[]; alerts: { rules: number; critical: number; warning: number }; visibility: string[]
}
const data = useLoad(() => get<{ clusters: Cl[]; stale_after_seconds: number }>('infra/overview'), 60000)
const canAdd = hasRole('operator')

type RowState = { open: boolean; busy: boolean; results: { rule: string; text: string; tone: 'ok' | 'warn' | 'bad'; plan?: string }[] }
const st = reactive<Record<string, RowState>>({})
const row = (id: string) => (st[id] ??= { open: false, busy: false, results: [] })

async function addStandard(c: Cl) {
  const r = row(c.endpoint_id)
  r.busy = true; r.results = []
  for (const rule of STANDARD_RULES) {
    const { action, params } = planParams(c.endpoint_id, c.name, rule)
    try {
      const p = await post<PlanCreated>('plans', { action, params })
      if (p.status === 'approved' || p.status === 'executing') { r.results.push({ rule: rule.label, text: 'Created', tone: 'ok', plan: p.plan_id }); continue }
      if (p.self_approval) {
        const a = await post<{ status: string }>(`plans/${p.plan_id}/approve`)
        r.results.push({ rule: rule.label, text: a.status === 'approved' ? 'Created' : a.status, tone: 'ok', plan: p.plan_id })
      } else r.results.push({ rule: rule.label, text: 'Waiting for approval', tone: 'warn', plan: p.plan_id })
    } catch (e) {
      const m = (e as Error).message
      r.results.push({ rule: rule.label, text: /already exists/.test(m) ? 'Already set up' : m, tone: /already exists/.test(m) ? 'ok' : 'bad' })
    }
  }
  r.busy = false; r.open = false
  data.reload()
}
const ago = (s: number | null) => (s == null ? 'never' : s < 120 ? `${Math.round(s)} s ago` : s < 7200 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`)
const projText = (p: Proj) => (p.days_to_full == null ? p.note : p.days_to_full > 3650 ? 'over 10 years at the current rate' : `full in about ${p.days_to_full} days`)
const projTone = (p: Proj) => (p.days_to_full == null ? 'muted' : p.days_to_full < 14 ? 'bad' : p.days_to_full < 60 ? 'warn' : 'muted')
</script>

<template>
  <div class="page ih">
    <PageHeader title="Infrastructure health" sub="Every connected cluster at a glance: availability, HA, backups and capacity."
      help="Read-only. Figures come from what Office Unbound's read token collected; anything it cannot see is marked unknown, and old data is marked stale." />
    <ErrorBox :error="data.error.value" />
    <Card v-if="!data.data.value"><EmptyState compact title="Loading…" /></Card>
    <Card v-else-if="!data.data.value.clusters.length"><EmptyState icon="cluster" title="No cluster connected" text="Connect a Proxmox cluster to monitor it here."><Button variant="primary" to="/infrastructure/providers/proxmox/connect">Connect a cluster</Button></EmptyState></Card>
    <Card v-for="c in data.data.value?.clusters ?? []" :key="c.endpoint_id" :title="c.name" :hint="(c.cluster ? 'Cluster ' + c.cluster : 'Standalone') + (c.version ? ' · Proxmox VE ' + c.version : '')">
      <template #actions><router-link class="small" :to="`/infrastructure/providers/${c.endpoint_id}`">Open</router-link></template>
      <p v-if="c.freshness.stale" class="ih-stale" role="status"><span class="badge warn">Stale</span> Last data {{ ago(c.freshness.age_seconds) }}<template v-if="c.freshness.error">: {{ c.freshness.error }}</template>. Figures below may be out of date.</p>
      <dl class="ih-facts">
        <div><dt>Quorum</dt><dd><span class="badge" :class="c.quorate === false ? 'bad' : c.quorate ? 'ok' : 'idle'">{{ c.quorate === false ? 'Lost' : c.quorate ? 'OK' : 'Unknown' }}</span></dd></div>
        <div><dt>Nodes online</dt><dd>{{ c.nodes.online }} / {{ c.nodes.total }}<span class="muted small"> · {{ c.nodes.monitored }} monitored</span></dd></div>
        <div><dt>Guests running</dt><dd>{{ c.guests.running }} / {{ c.guests.total }}<span class="muted small"> · {{ c.guests.managed }} managed by Office Unbound</span></dd></div>
        <div><dt>High availability</dt><dd v-if="c.ha">{{ c.ha.services ? c.ha.services + ' services' : 'Not configured' }}<span v-if="c.ha.problems" class="badge bad">{{ c.ha.problems }} in error</span></dd><dd v-else class="muted">Not visible (enable whole-cluster read-only monitoring)</dd></div>
        <div><dt>Backups</dt><dd v-if="c.backups">{{ c.backups.backed_up_recently }} / {{ c.backups.guests }} guests in the last {{ c.backups.window_hours }} h<span v-if="c.backups.never" class="badge warn">{{ c.backups.never }} with none</span><span v-if="c.backups.failed_tasks" class="badge bad">{{ c.backups.failed_tasks }} failed</span></dd><dd v-else class="muted">Not visible (needs read access to the backup storage)</dd></div>
        <div><dt>Alert rules</dt><dd>{{ c.alerts.rules }}<span v-if="c.alerts.critical" class="badge bad">{{ c.alerts.critical }} critical</span><span v-if="c.alerts.warning" class="badge warn">{{ c.alerts.warning }} warning</span></dd></div>
      </dl>
      <div class="tablewrap"><table><caption class="sr-only">Storage of {{ c.name }}</caption><thead><tr><th>Storage</th><th>Used</th><th>Size</th><th>Capacity outlook</th></tr></thead><tbody>
        <tr v-for="s in c.storage" :key="s.name + s.node"><td>{{ s.name }}<span v-if="s.node" class="muted small"> on {{ s.node }}</span><span v-if="s.active === false" class="badge bad">inactive</span></td>
          <td><ProgressBar :pct="s.pct" :label="s.name + ' used'" /></td><td class="num">{{ s.total ? fmtBytes(s.total) : 'unknown' }}</td>
          <td :class="projTone(s.projection)" :title="s.projection.basis">{{ projText(s.projection) }}<span v-if="s.projection.growth_bytes_per_day" class="muted small"> (+{{ fmtBytes(s.projection.growth_bytes_per_day) }}/day)</span></td></tr>
        <tr v-if="!c.storage.length"><td colspan="4" class="muted">No storage visible.</td></tr>
      </tbody></table></div>
      <div v-if="canAdd" class="ih-std">
        <Button v-if="!row(c.endpoint_id).open" size="sm" @click="row(c.endpoint_id).open = true">Add standard alerts…</Button>
        <div v-else class="card ih-confirm">
          <p><b>These alert rules will be created for {{ c.name }}:</b></p>
          <ul><li v-for="r in STANDARD_RULES" :key="r.rule">{{ r.label }}</li></ul>
          <p class="muted small">They only read data Office Unbound already collects: nothing is installed or run on the cluster or in guests. Notifications follow your existing alert channels. Each rule is a separate plan in Approvals; as the only administrator you approve them with this button.</p>
          <div class="row"><Button variant="primary" size="sm" :loading="row(c.endpoint_id).busy" @click="addStandard(c)">Create and approve</Button><Button size="sm" variant="ghost" @click="row(c.endpoint_id).open = false">Cancel</Button></div>
        </div>
        <ul v-if="row(c.endpoint_id).results.length" class="ih-res" aria-live="polite"><li v-for="x in row(c.endpoint_id).results" :key="x.rule"><span class="badge" :class="x.tone">{{ x.text }}</span> {{ x.rule }}</li></ul>
      </div>
    </Card>
  </div>
</template>

<style scoped>
.ih-facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 10px 18px; margin: 0 0 12px; }
.ih-facts dt { font-size: .8rem; color: var(--muted); }
.ih-facts dd { margin: 2px 0 0; display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.ih-stale { margin: 0 0 10px; }
.ih-std { margin-top: 12px; display: grid; gap: 8px; }
.ih-confirm ul, .ih-res { margin: 4px 0; padding-left: 18px; }
.ih-res { list-style: none; padding: 0; display: grid; gap: 4px; }
td.bad { color: var(--bad); } td.warn { color: var(--warn); }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
</style>
