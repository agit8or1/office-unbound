<script setup lang="ts">
import { computed } from 'vue'
import { get, type Job } from '../api'
import { fmtTime, go, route, short, useLoad } from '../store'
import ErrorBox from '../components/ErrorBox.vue'
import Status from '../components/Status.vue'
import Pre from '../components/Pre.vue'
import PageHeader from '../ui/PageHeader.vue'
import EmptyState from '../ui/EmptyState.vue'
import Skeleton from '../ui/Skeleton.vue'
import Segmented from '../ui/Segmented.vue'
import Button from '../ui/Button.vue'

const jobs = useLoad(() => get<Job[]>('jobs'), 5000)
const selId = computed(() => route.value.arg)
const sel = useLoad(async () => (selId.value ? get<Job>(`jobs/${selId.value}`) : null), 5000)
</script>
<template>
  <div class="page">
    <PageHeader title="Jobs" sub="Approved changes as they run: queued, running, succeeded or failed." help="A job is created when a plan is approved. Each runs once and records its result.">
      <template #actions><Button size="sm" icon="refresh" :loading="jobs.loading.value" @click="jobs.reload()">Refresh</Button></template>
    </PageHeader>
    <Skeleton v-if="!jobs.data.value && !jobs.error.value" />
    <ErrorBox :error="jobs.error.value" />
    <div class="split">
      <section class="card flush">
        <div class="scroll" tabindex="0" role="region" aria-label="Scrollable table">
          <table v-if="jobs.data.value?.length">
            <thead><tr><th>Job</th><th>Action</th><th>Status</th><th>Created</th><th>Finished</th></tr></thead>
            <tbody>
              <tr v-for="j in jobs.data.value" :key="j.id" :class="{ sel: j.id === selId }">
                <td><a :href="'#/jobs/' + j.id" class="mono">{{ short(j.id) }}</a></td><td class="mono">{{ j.action }}</td>
                <td><Status :s="j.status" /></td><td>{{ fmtTime(j.created_at) }}</td><td>{{ fmtTime(j.finished_at) }}</td>
              </tr>
            </tbody>
          </table>
          <EmptyState v-else-if="jobs.data.value" icon="list" title="No jobs yet" text="Jobs appear here once a plan is approved and starts running." />
        </div>
      </section>
      <section v-if="selId" class="card detail" aria-label="Job details">
        <div class="head"><h2>Job {{ short(selId) }}</h2><Button size="sm" variant="ghost" icon="x" @click="go('jobs')">Close</Button></div>
        <ErrorBox :error="sel.error.value" />
        <template v-if="sel.data.value">
          <dl class="kv">
            <dt>Status</dt><dd><Status :s="sel.data.value.status" /></dd>
            <dt>Action</dt><dd class="mono">{{ sel.data.value.action }}</dd>
            <dt>Plan</dt><dd><a :href="'#/plans/' + sel.data.value.plan_id" class="mono">{{ sel.data.value.plan_id }}</a></dd>
            <dt>Created</dt><dd>{{ fmtTime(sel.data.value.created_at) }}</dd>
            <dt>Started</dt><dd>{{ fmtTime(sel.data.value.started_at) }}</dd>
            <dt>Finished</dt><dd>{{ fmtTime(sel.data.value.finished_at) }}</dd>
          </dl>
          <h3>Result</h3><Pre v-if="sel.data.value.result" :v="sel.data.value.result" /><p v-else class="muted">None.</p>
          <h3>Error</h3><Pre v-if="sel.data.value.error" :v="sel.data.value.error" /><p v-else class="muted">None.</p>
        </template>
      </section>
    </div>
  </div>
</template>
