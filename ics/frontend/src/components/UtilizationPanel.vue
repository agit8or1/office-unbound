<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { loadMetric, type MetricName, type MetricSeries, type Res } from '../infra'
import { RANGES } from '../charts/geometry'
import { fmtRate } from '../format'
import LineChart from '../charts/LineChart.vue'
import Card from '../ui/Card.vue'
import Segmented from '../ui/Segmented.vue'
import EmptyState from '../ui/EmptyState.vue'
import Button from '../ui/Button.vue'

// CPU / memory / storage / network over time for one cluster or node (real samples from /infra/metrics).
const props = defineProps<{ scopes: { scope: string; id: string; name: string }[]; title?: string; connected: boolean }>()
const range = ref('24h')
const sel = ref('')
const metrics: { key: MetricName; label: string; unit: 'pct' | 'rate' }[] = [
  { key: 'cpu', label: 'CPU', unit: 'pct' }, { key: 'memory', label: 'Memory', unit: 'pct' },
  { key: 'storage', label: 'Storage', unit: 'pct' }, { key: 'network', label: 'Network', unit: 'rate' },
]
const data = ref<Partial<Record<MetricName, MetricSeries>>>({})
const loading = ref(false), failed = ref(false)
const rangeMs = computed(() => RANGES.find((r) => r.value === range.value)?.ms ?? 86400e3)
const current = computed(() => props.scopes.find((s) => `${s.scope}:${s.id}` === sel.value) ?? props.scopes[0])
// the scope picker shows the scope the charts are drawn for (it was blank until the operator picked one)
watch(() => props.scopes.map((s) => s.scope + ':' + s.id).join(), () => { if (!props.scopes.some((s) => `${s.scope}:${s.id}` === sel.value) && props.scopes[0]) sel.value = `${props.scopes[0].scope}:${props.scopes[0].id}` }, { immediate: true })

async function load() {
  const s = current.value
  if (!s) return
  loading.value = true; failed.value = false
  try {
    const rs = await Promise.all(metrics.map((m) => loadMetric(s.scope, s.id, m.key, range.value)))
    data.value = Object.fromEntries(metrics.map((m, i) => [m.key, rs[i]]))
  } catch { failed.value = true } finally { loading.value = false }
}
watch([() => props.scopes.map((s) => s.id).join(), range, sel], load, { immediate: true })
const anyData = computed(() => metrics.some((m) => (data.value[m.key]?.points.length ?? 0) > 0))
const last = (k: MetricName) => { const p = data.value[k]?.points; return p?.length ? p[p.length - 1]!.v : null }
// phones: four stacked charts at full height filled two screens; a shorter plot keeps the four together
const narrow = window.matchMedia?.('(max-width: 600px)')
const compact = ref(!!narrow?.matches)
const onNarrow = () => { compact.value = !!narrow?.matches }
onMounted(() => narrow?.addEventListener?.('change', onNarrow))
onUnmounted(() => narrow?.removeEventListener?.('change', onNarrow))
const fmt = (u: 'pct' | 'rate') => (v: number) => (u === 'pct' ? `${Math.round(v)}%` : fmtRate(v))
</script>
<template>
  <Card :title="title ?? 'Utilization'" hint="Averages from collected metric samples">
    <template #actions>
      <select v-if="scopes.length > 1" v-model="sel" aria-label="Scope" class="scope-select">
        <option v-for="s in scopes" :key="s.scope + s.id" :value="s.scope + ':' + s.id">{{ s.name }}</option>
      </select>
      <Segmented v-model="range" :options="RANGES.map((r) => ({ value: r.value, label: r.label }))" label="Time range" />
    </template>
    <div v-if="!connected || !scopes.length"><EmptyState compact icon="activity" title="No utilization data yet" text="Charts appear once a Proxmox cluster is connected and metrics are collected."><Button size="sm" to="/endpoints">Connect a cluster</Button></EmptyState></div>
    <div v-else-if="failed"><EmptyState compact icon="alert" title="Metrics are unavailable" text="We could not load utilization right now. Try again in a moment."><Button size="sm" @click="load">Retry</Button></EmptyState></div>
    <div v-else-if="!loading && !anyData"><EmptyState compact icon="activity" title="Collecting samples" text="No utilization samples exist for this range yet. Charts fill in as metrics are collected." /></div>
    <div v-else class="charts">
      <div v-for="m in metrics" :key="m.key" class="chartbox">
        <div class="ct"><span>{{ m.label }}</span><b>{{ last(m.key) === null ? '-' : fmt(m.unit)(last(m.key)!) }}</b></div>
        <LineChart :series="[{ name: m.label, points: data[m.key]?.points ?? [] }]" :range-ms="rangeMs" :fmt="fmt(m.unit)" :y-max="m.unit === 'pct' ? 100 : undefined" :height="compact ? 130 : 210" />
      </div>
    </div>
  </Card>
</template>
