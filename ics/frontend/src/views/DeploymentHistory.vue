<script setup lang="ts">
import { fmtTime, useLoad } from '../store'
import { ago } from '../format'
import { asList, loadDeployments, tryGet } from '../infra'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import DataTable from '../ui/DataTable.vue'
import EmptyState from '../ui/EmptyState.vue'
import Skeleton from '../ui/Skeleton.vue'
import Button from '../ui/Button.vue'
import ErrorBox from '../components/ErrorBox.vue'

interface Row { key: string; deployment: string; at: string; kind: string; message: string; job: string | null }
// Change history across every environment: each deployment keeps its own event log; this page merges them, newest first.
const hist = useLoad(async (): Promise<Row[]> => {
  const deps = (await loadDeployments()).data
  const rows: Row[] = []
  await Promise.all(deps.slice(0, 50).map(async (d) => {
    const ev = asList((await tryGet<unknown>(`deployments/${encodeURIComponent(d.id)}/events?limit=50`, [])).data)
    for (const e of ev) {
      const o = e as Record<string, unknown>
      rows.push({ key: `${d.id}:${o.id ?? rows.length}`, deployment: d.name, at: String(o.at ?? ''), kind: String(o.kind ?? 'event').replace(/_/g, ' '), message: String(o.message ?? ''), job: o.job_id ? String(o.job_id) : null })
    }
  }))
  return rows.sort((a, b) => +new Date(b.at) - +new Date(a.at)).slice(0, 200)
}, 20000)
const cols = [{ key: 'at', label: 'When' }, { key: 'deployment', label: 'Environment' }, { key: 'kind', label: 'Event' }, { key: 'message', label: 'Details' }, { key: 'job', label: 'Job' }]
</script>
<template>
  <div class="page">
    <PageHeader title="Deployment history" sub="What changed in your environments and when, newest first." help="Every deployment records its events: planning, applying, changes and failures. Open a job for step-by-step results.">
      <template #actions><Button size="sm" icon="refresh" :loading="hist.loading.value" @click="hist.reload()">Refresh</Button></template>
    </PageHeader>
    <ErrorBox :error="hist.error.value" />
    <Skeleton v-if="!hist.data.value && !hist.error.value" />
    <Card v-else-if="hist.data.value" flush>
      <EmptyState v-if="!hist.data.value.length" icon="clock" title="No deployment history yet" text="Events appear here once an environment is created or changed." />
      <DataTable v-else :cols="cols" :rows="hist.data.value" :row-key="(r: Row) => r.key">
        <template #cell-at="{ row }"><span :title="fmtTime(row.at)">{{ ago(row.at) }}</span></template>
        <template #cell-job="{ row }"><a v-if="row.job" :href="'#/jobs/' + row.job" class="mono">{{ row.job.slice(0, 8) }}</a><span v-else class="muted">-</span></template>
      </DataTable>
    </Card>
  </div>
</template>
