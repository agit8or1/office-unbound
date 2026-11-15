<script setup lang="ts">
import { computed } from 'vue'
import { get, type Job } from '../api'
import { fmtTime, go, route, short, useLoad } from '../store'
import ErrorBox from '../components/ErrorBox.vue'
import Status from '../components/Status.vue'
import Pre from '../components/Pre.vue'

const jobs = useLoad(() => get<Job[]>('jobs'), 5000)
const selId = computed(() => route.value.arg)
const sel = useLoad(async () => (selId.value ? get<Job>(`jobs/${selId.value}`) : null), 5000)
</script>
<template>
  <div class="page">
    <div class="head"><h1>Jobs</h1><button class="ghost" @click="jobs.reload()" :disabled="jobs.loading.value">Refresh</button></div>
    <ErrorBox :error="jobs.error.value" />
    <div class="split">
      <section class="panel fill">
        <div class="scroll">
          <table v-if="jobs.data.value?.length">
            <thead><tr><th>Job</th><th>Action</th><th>Status</th><th>Created</th><th>Finished</th></tr></thead>
            <tbody>
              <tr v-for="j in jobs.data.value" :key="j.id" :class="{ sel: j.id === selId }">
                <td><a :href="'#/jobs/' + j.id" class="mono">{{ short(j.id) }}</a></td><td class="mono">{{ j.action }}</td>
                <td><Status :s="j.status" /></td><td>{{ fmtTime(j.created_at) }}</td><td>{{ fmtTime(j.finished_at) }}</td>
              </tr>
            </tbody>
          </table>
          <p v-else-if="jobs.data.value" class="empty">No jobs yet. Jobs are created when a plan is approved.</p>
        </div>
      </section>
      <section v-if="selId" class="panel detail" aria-label="Job details">
        <div class="head"><h2>Job {{ short(selId) }}</h2><button class="ghost" @click="go('jobs')">Close</button></div>
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
