<script setup lang="ts">
// Step progress for a durable job (GET /jobs/{id}/steps), polled until every step is terminal.
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { api, load } from '../api'
import type { JobStep, Loaded } from '../api'
import Unavailable from './Unavailable.vue'
import Banner from './Banner.vue'
const props = defineProps<{ jobId: string }>()
const steps = ref<Loaded<JobStep[]> | null>(null)
let timer: ReturnType<typeof setTimeout> | undefined
const done = (s: JobStep[]) => s.length > 0 && s.every((x) => ['succeeded', 'failed', 'skipped'].includes(x.status)) || s.some((x) => x.status === 'failed')
async function poll() {
  steps.value = await load(() => api.jobSteps(props.jobId))
  if (steps.value.state === 'ok' && !done(steps.value.data)) timer = setTimeout(poll, 3000)
}
onMounted(poll)
onBeforeUnmount(() => clearTimeout(timer))
const chip = (s: JobStep['status']) => ({ succeeded: 'ok', running: 'info', failed: 'bad', pending: 'info', skipped: 'warn' })[s]
</script>

<template>
  <div>
    <Unavailable v-if="steps?.state === 'unavailable'" what="Job step progress" endpoint="GET /api/v1/jobs/{id}/steps" :status="steps.status" />
    <Banner v-else-if="steps?.state === 'error'" kind="bad">{{ steps.message }}</Banner>
    <p v-else-if="steps && !steps.data.length" class="muted">The job has no steps yet.</p>
    <div v-else-if="steps" class="wz-table-wrap">
      <table>
        <thead><tr><th class="num">#</th><th>Step</th><th>Status</th><th>Progress</th><th class="num">Attempts</th></tr></thead>
        <tbody>
          <tr v-for="s in steps.data" :key="s.index">
            <td class="num">{{ s.index + 1 }}</td>
            <td>{{ s.name }}<div v-if="s.log_excerpt" class="mono muted">{{ s.log_excerpt }}</div></td>
            <td><span class="wz-chip" :class="chip(s.status)">{{ s.status }}</span></td>
            <td><div class="wz-bar" role="progressbar" :aria-valuenow="s.progress ?? 0" aria-valuemin="0" aria-valuemax="100"><span class="added" :style="{ width: (s.progress ?? (s.status === 'succeeded' ? 100 : 0)) + '%' }"></span></div></td>
            <td class="num">{{ s.attempts ?? 0 }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
