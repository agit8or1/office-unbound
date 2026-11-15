<script setup lang="ts">
import { computed } from 'vue'
import { get, type AuditEvent, type Endpoint, type Job, type Plan, type Ready } from '../api'
import { fmtTime, hasRole, useLoad } from '../store'
import ErrorBox from '../components/ErrorBox.vue'
import Status from '../components/Status.vue'

async function ready(): Promise<Ready | null> {
  // /readyz answers 503 with a body when not ready; fetch directly so that is still shown
  const r = await fetch('/readyz', { credentials: 'same-origin' })
  try { return (await r.json()) as Ready } catch { return null }
}
const rd = useLoad(ready, 15000)
const eps = useLoad(() => get<Endpoint[]>('endpoints'), 15000)
const plans = useLoad(() => get<Plan[]>('plans'), 15000)
const jobs = useLoad(() => get<Job[]>('jobs'), 15000)
const audit = useLoad(async () => (hasRole('approver') ? get<AuditEvent[]>('audit?limit=12') : null), 15000)

const pending = computed(() => plans.data.value?.filter((p) => p.status === 'pending_approval').length)
const running = computed(() => jobs.data.value?.filter((j) => j.status === 'running' || j.status === 'queued').length)
const failed = computed(() => jobs.data.value?.filter((j) => j.status === 'failed').length)
const label: Record<string, string> = { database: 'Database', worker: 'Job worker heartbeat', audit_chain: 'Audit chain (last 200)' }
const err = computed(() => eps.error.value ?? plans.error.value ?? jobs.error.value)
</script>
<template>
  <div class="page">
    <h1>Overview</h1>
    <ErrorBox :error="err" />
    <dl class="stats">
      <div><dt>Endpoints</dt><dd>{{ eps.data.value?.length ?? '-' }}</dd></div>
      <div><dt>Plans pending</dt><dd><a href="#/plans">{{ pending ?? '-' }}</a></dd></div>
      <div><dt>Jobs running / queued</dt><dd><a href="#/jobs">{{ running ?? '-' }}</a></dd></div>
      <div><dt>Jobs failed</dt><dd :class="{ bad: failed }"><a href="#/jobs">{{ failed ?? '-' }}</a></dd></div>
    </dl>
    <div class="cols">
      <section class="panel" aria-labelledby="rd">
        <h2 id="rd">Readiness</h2>
        <p v-if="!rd.data.value" class="muted">{{ rd.error.value ? 'Readiness unavailable.' : 'Loading…' }}</p>
        <ul v-else class="plain checks">
          <li v-for="(c, k) in rd.data.value.checks" :key="k"><Status :s="c.ok ? 'ok' : 'failed'" /> {{ label[k] ?? k }}</li>
          <li><strong>{{ rd.data.value.ready ? 'Ready' : 'Not ready' }}</strong></li>
        </ul>
        <p class="muted small">Endpoints on this ICS: {{ eps.data.value?.map((e) => e.name).join(', ') || 'none registered' }}</p>
      </section>
      <section class="panel grow" aria-labelledby="au">
        <h2 id="au">Latest audit entries</h2>
        <p v-if="!hasRole('approver')" class="muted">Audit is visible to approvers and admins.</p>
        <ErrorBox :error="audit.error.value" />
        <div v-if="audit.data.value" class="scroll">
          <table>
            <thead><tr><th>Seq</th><th>Time</th><th>Action</th><th>Actor</th></tr></thead>
            <tbody>
              <tr v-for="a in audit.data.value" :key="a.seq">
                <td class="num">{{ a.seq }}</td><td>{{ fmtTime(a.at) }}</td><td class="mono">{{ a.action }}</td><td>{{ a.actor_name ?? '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </div>
</template>
