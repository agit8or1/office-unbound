<script setup lang="ts">
// One deployment (owner 2026-11-26: "cleanup the pages/cards layout. needs to look better"): a summary row, then tabs instead of one
// long column of panels. The tab lives in the URL (?tab=), so links and reloads keep it; ?section=people (older links) opens People.
import { computed, watchEffect } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useLoad, hasRole } from '../store'
import { ago, crumbLabel } from '../format'
import { asList, normDeployment, tryGet } from '../infra'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import Tabs from '../ui/Tabs.vue'
import Segmented from '../ui/Segmented.vue'
import StatCard from '../ui/StatCard.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import EmptyState from '../ui/EmptyState.vue'
import Button from '../ui/Button.vue'
import Skeleton from '../ui/Skeleton.vue'
import ErrorBox from '../components/ErrorBox.vue'
import BootstrapPanel from '../components/BootstrapPanel.vue'
import AppsPanel from '../components/AppsPanel.vue'
import PeoplePanel from '../components/PeoplePanel.vue'
import DiagnosticsPanel from '../components/DiagnosticsPanel.vue'
import ResizePanel from '../wizards/deploy/ResizePanel.vue'
import DnsCheck from './tenants/DnsCheck.vue'

type Row = Record<string, unknown>
const props = defineProps<{ id: string }>()
const enc = encodeURIComponent(props.id)
const dep = useLoad(async () => { const r = await tryGet<Row | null>(`deployments/${enc}`, null); return r.data ? { n: normDeployment(r.data), raw: r.data } : null }, 10000)
const resources = useLoad(async () => asList((await tryGet<unknown>(`deployments/${enc}/resources`, [])).data) as Row[], 10000)
const events = useLoad(async () => asList((await tryGet<unknown>(`deployments/${enc}/events`, [])).data) as Row[], 10000)
watchEffect(() => { crumbLabel.value = dep.data.value?.n.name ?? '' })

const route = useRoute()
const router = useRouter()
const TABS = computed(() => [
  { id: 'overview', label: 'Overview' },
  ...(hasRole('admin') ? [{ id: 'people', label: 'People' }] : []),
  { id: 'dns', label: 'DNS records' },
  { id: 'activity', label: 'Activity' },
  { id: 'resources', label: 'Resources' },
  ...(hasRole('admin') ? [{ id: 'diagnostics', label: 'Diagnostics' }] : []),
  ...(hasRole('operator') ? [{ id: 'sizing', label: 'Sizing' }] : []),
])
const tab = computed({
  get: () => {
    const want = String(route.query.tab ?? (route.query.section === 'people' ? 'people' : 'overview'))
    return TABS.value.some((t) => t.id === want) ? want : 'overview'
  },
  set: (v: string) => { void router.replace({ query: { ...route.query, section: undefined, tab: v === 'overview' ? undefined : v } }) },
})

const s = (v: unknown) => (v === undefined || v === null || v === '' ? '-' : String(v))
const stateOf = (r: Row) => { const a = r.actual as Row | null; return s((a && typeof a === 'object' && a.state) || r.state || r.status) }
const detailOf = (r: Row) => { const a = r.actual as Row | null; return a && typeof a === 'object' && typeof a.message === 'string' ? a.message : '' }
const GOOD = new Set(['ok', 'present', 'running', 'active', 'healthy', 'applied', 'ready'])
const byKind = (k: string) => (resources.data.value ?? []).filter((r) => r.kind === k)
const checks = computed(() => byKind('check'))
const checksOk = computed(() => checks.value.filter((r) => GOOD.has(stateOf(r))).length)
const domain = computed(() => { const d = dep.data.value?.raw.desired_spec as Row | undefined; const v = d?.domain ?? (d?.input as Row | undefined)?.domain; return typeof v === 'string' ? v : null })
const revision = computed(() => { const r = asList(dep.data.value?.raw.revisions) as Row[]; return r.length ? r[r.length - 1] : null })
const lastEvent = computed(() => (events.data.value ?? [])[0] ?? null)

// resources: one table per kind, the most useful kinds first; a filter instead of 90 rows in one list
const KIND_LABEL: Record<string, string> = { vm: 'Virtual machines', service: 'Services', container: 'Containers', check: 'Health checks', dns: 'DNS names', volume: 'Volumes' }
const ORDER = ['vm', 'service', 'container', 'check', 'dns', 'volume']
const kinds = computed(() => {
  const ks = [...new Set((resources.data.value ?? []).map((r) => String(r.kind)))]
  return ks.sort((a, b) => (ORDER.indexOf(a) + 1 || 99) - (ORDER.indexOf(b) + 1 || 99))
})
const kindFilter = computed({
  get: () => { const k = String(route.query.kind ?? ''); return kinds.value.includes(k) ? k : 'all' },
  set: (v: string) => { void router.replace({ query: { ...route.query, kind: v === 'all' ? undefined : v } }) },
})
const kindOptions = computed(() => [{ value: 'all', label: `All (${resources.data.value?.length ?? 0})` },
  ...kinds.value.map((k) => ({ value: k, label: `${KIND_LABEL[k] ?? k} (${byKind(k).length})` }))])
const shownKinds = computed(() => (kindFilter.value === 'all' ? kinds.value : [kindFilter.value]))
const shortName = (r: Row) => { const n = s(r.logical_name ?? r.name); return n.startsWith(props.id + '-') ? n.slice(props.id.length + 1) : n }
</script>
<template>
  <div class="page">
    <ErrorBox :error="dep.error.value" />
    <Skeleton v-if="!dep.data.value && !dep.error.value && dep.loading.value" />
    <EmptyState v-else-if="!dep.data.value" icon="rocket" title="Deployment not found" text="It may have been removed, or deployments are not available yet."><Button to="/deployments">All deployments</Button></EmptyState>
    <template v-else>
      <PageHeader :title="dep.data.value.n.name" :sub="[domain, dep.data.value.n.profile ? 'Profile: ' + dep.data.value.n.profile : null].filter(Boolean).join(' · ') || undefined">
        <template #actions><StatusBadge :s="dep.data.value.n.status" /></template>
      </PageHeader>

      <section class="statgrid" aria-label="Deployment summary">
        <StatCard label="Virtual machines" :to="`/deployments/${enc}?tab=resources&kind=vm`" :value="byKind('vm').length" :sub="byKind('vm').length ? 'in this deployment' : 'none yet'" icon="vm" tone="info" :loading="!resources.data.value" />
        <StatCard label="Services" :to="`/deployments/${enc}?tab=resources&kind=service`" :value="byKind('service').length + byKind('container').length" :sub="`${byKind('service').length} packages · ${byKind('container').length} containers`" icon="box" tone="info" :loading="!resources.data.value" />
        <StatCard label="Health checks" :to="`/deployments/${enc}?tab=resources&kind=check`" :value="checksOk" :of="checks.length" :sub="!checks.length ? 'none yet' : checksOk === checks.length ? 'all passing' : `${checks.length - checksOk} need attention`"
                  icon="shield" :tone="!checks.length ? 'idle' : checksOk === checks.length ? 'ok' : 'warn'" :loading="!resources.data.value" />
        <StatCard label="Last change" :to="`/deployments/${enc}?tab=activity`" :value="revision ? 'Revision ' + s(revision.revision) : '-'" :sub="lastEvent ? s(lastEvent.message ?? lastEvent.event) + ' · ' + ago((lastEvent.at ?? lastEvent.created_at) as string) : 'no changes yet'"
                  icon="clock" tone="idle" :loading="!events.data.value" />
      </section>

      <Tabs v-model="tab" :tabs="TABS" />

      <div v-if="tab === 'overview'" class="stack">
        <AppsPanel v-if="hasRole('admin')" :slug="props.id" />
        <BootstrapPanel :slug="props.id" />
      </div>

      <PeoplePanel v-else-if="tab === 'people'" :slug="props.id" />

      <Card v-else-if="tab === 'dns'" title="DNS records" hint="What this deployment's domain needs at its DNS provider, including the DKIM key that signs its mail, compared with public DNS now." data-testid="deployment-dns">
        <DnsCheck :deployment="props.id" :domain="domain" />
      </Card>

      <Card v-else-if="tab === 'activity'" title="Activity" hint="Changes, jobs and events of this deployment, newest first." flush>
        <EmptyState v-if="!events.data.value?.length" compact title="No events yet" />
        <ul v-else class="feed feedpad">
          <li v-for="(e, i) in events.data.value" :key="i"><span class="t">{{ s(e.message ?? e.event ?? e.type) }}</span><span class="w">{{ ago((e.at ?? e.created_at) as string) }}</span></li>
        </ul>
      </Card>

      <template v-else-if="tab === 'resources'">
        <Segmented v-if="kinds.length > 1" v-model="kindFilter" :options="kindOptions" label="Resource kind" class="kindfilter" />
        <EmptyState v-if="!resources.data.value?.length" compact title="No resources recorded" />
        <Card v-for="k in shownKinds" :key="k" :title="`${KIND_LABEL[k] ?? k} (${byKind(k).length})`" flush>
          <div class="tablewrap">
            <table class="dense restable">
              <colgroup><col class="c-name"><col class="c-state"><col></colgroup>
              <thead><tr><th>Name</th><th>State</th><th>Detail</th></tr></thead>
              <tbody><tr v-for="(r, i) in byKind(k)" :key="i"><td class="mono nm" :title="s(r.logical_name ?? r.name)">{{ shortName(r) }}</td><td><StatusBadge :s="stateOf(r)" /></td><td class="muted small">{{ detailOf(r) }}</td></tr></tbody>
            </table>
          </div>
        </Card>
      </template>

      <DiagnosticsPanel v-else-if="tab === 'diagnostics'" :slug="props.id" />
      <ResizePanel v-else-if="tab === 'sizing'" :slug="props.id" />
    </template>
  </div>
</template>
<style scoped>
.statgrid { margin-bottom: 18px; }
.stack { display: flex; flex-direction: column; gap: 18px; }
.kindfilter { margin-bottom: 14px; flex-wrap: wrap; }
.tablewrap { overflow-x: auto; }
/* the same columns in every kind's table, so they line up down the page */
table.restable { width: 100%; table-layout: fixed; min-width: 560px; }
.restable col.c-name { width: 42%; } .restable col.c-state { width: 120px; }
td.nm { overflow-wrap: anywhere; }
</style>
