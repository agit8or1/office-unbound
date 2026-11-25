<script setup lang="ts">
import { computed, ref } from 'vue'
import { ApiError, get, post, type IncidentDetail, type Incident, type PlanCreated } from '../api'
import { fmtTime, go, hasRole, route, short, useLoad } from '../store'
import ErrorBox from '../components/ErrorBox.vue'
import Status from '../components/Status.vue'
import PageHeader from '../ui/PageHeader.vue'
import EmptyState from '../ui/EmptyState.vue'
import Skeleton from '../ui/Skeleton.vue'
import Segmented from '../ui/Segmented.vue'
import Button from '../ui/Button.vue'
import TechText from '../ui/TechText.vue'
import { nextAction } from '../incidents'

const filter = ref<'active' | 'recovered' | ''>('active')
const list = useLoad(() => get<Incident[]>('incidents' + (filter.value ? `?status=${filter.value}` : '')), 5000)
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const selId = computed(() => (route.value.page === 'incidents' ? route.value.arg : ''))
// a malformed link (owner report 2026-11-20: "path.incident_id: Input should be a valid UUID") shows "not found" instead of an API error
const badId = computed(() => !!selId.value && !UUID_RE.test(selId.value))
const sel = useLoad(async () => (selId.value && !badId.value ? get<IncidentDetail>(`incidents/${selId.value}`) : null), 5000)
function setFilter(f: 'active' | 'recovered' | '') { filter.value = f; void list.reload() }

const err = ref<ApiError | null>(null), ok = ref(''), busy = ref(false), note = ref('')
async function ack() {
  if (!selId.value) return
  busy.value = true; err.value = null; ok.value = ''
  try {
    const r = await post<PlanCreated>('plans', { action: 'incident.ack', params: { incident_id: selId.value, note: note.value } })
    ok.value = `Acknowledge plan ${short(r.plan_id)} auto-approved (low risk); job ${short(r.job_id)} queued.`
    note.value = ''
    setTimeout(() => { void sel.reload(); void list.reload() }, 2500)
  } catch (e) { err.value = e as ApiError } finally { busy.value = false }
}
const secs = (a: string, b: string | null) => (b ? Math.round((+new Date(b) - +new Date(a)) / 1000) + ' s' : '-')
</script>
<template>
  <div class="page">
    <PageHeader title="Incidents" sub="Problems detected by health checks, with severity, duration and the recommended next step." help="An incident opens when a check fails repeatedly and closes automatically when it recovers.">
      <template #actions><Segmented :model-value="filter" :options="[{ value: 'active', label: 'Active' }, { value: 'recovered', label: 'Recovered' }, { value: '', label: 'All' }]" label="Filter" @update:model-value="setFilter($event as 'active' | 'recovered' | '')" /></template>
    </PageHeader>
    <Skeleton v-if="!list.data.value && !list.error.value" />
    <ErrorBox :error="list.error.value" />
    <div class="split">
      <section class="card flush">
        <div class="scroll" tabindex="0" role="region" aria-label="Scrollable table">
          <table v-if="list.data.value?.length">
            <thead><tr><th>Check</th><th>Severity</th><th>Status</th><th>Opened</th><th>Recovered</th></tr></thead>
            <tbody><tr v-for="i in list.data.value" :key="i.id" :class="{ sel: i.id === selId }">
              <td class="ident"><a :href="'#/incidents/' + i.id">{{ i.check_name }}</a><span v-if="i.escalated_at" class="chip bad"> escalated</span></td>
              <td><Status :s="i.severity" /></td><td><Status :s="i.status" /></td><td>{{ fmtTime(i.opened_at) }}</td><td>{{ fmtTime(i.recovered_at) }}</td>
            </tr></tbody>
          </table>
          <EmptyState v-else-if="list.data.value" icon="check" :title="filter === 'active' ? 'No active incidents' : 'No incidents'" text="Everything monitored is healthy." />
        </div>
      </section>
      <section v-if="badId" class="card detail" aria-label="Incident details" data-testid="incident-bad-id">
        <div class="head"><h2>Incident not found</h2><Button size="sm" variant="ghost" icon="x" @click="go('incidents')">Close</Button></div>
        <p class="muted">This link does not name an incident. Pick one from the list.</p>
      </section>
      <section v-else-if="selId" class="card detail" aria-label="Incident details">
        <div class="head"><h2>Incident {{ short(selId) }}</h2><Button size="sm" variant="ghost" icon="x" @click="go('incidents')">Close</Button></div>
        <ErrorBox :error="sel.error.value" />
        <template v-if="sel.data.value">
          <dl class="kv">
            <dt>Check</dt><dd><a :href="'#/checks/' + sel.data.value.check_id">{{ sel.data.value.check_name }}</a></dd>
            <dt>Status</dt><dd><Status :s="sel.data.value.status" /> <Status :s="sel.data.value.severity" /></dd>
            <dt>Opened</dt><dd>{{ fmtTime(sel.data.value.opened_at) }}</dd>
            <dt v-if="sel.data.value.acked_at">Acknowledged</dt><dd v-if="sel.data.value.acked_at">{{ fmtTime(sel.data.value.acked_at) }}</dd>
            <dt v-if="sel.data.value.recovered_at">Recovered</dt><dd v-if="sel.data.value.recovered_at">{{ fmtTime(sel.data.value.recovered_at) }} (after {{ secs(sel.data.value.opened_at, sel.data.value.recovered_at) }})</dd>
            <dt v-if="sel.data.value.escalated_at">Escalated</dt><dd v-if="sel.data.value.escalated_at">{{ fmtTime(sel.data.value.escalated_at) }}: automatic remediation exhausted</dd>
            <dt>First message</dt><dd class="wrap"><TechText :text="sel.data.value.message" /></dd>
          </dl>
          <div class="alert info"><span><b>Next step:</b> {{ nextAction(sel.data.value) }}</span></div>
          <template v-if="sel.data.value.status === 'open' && hasRole('operator')">
            <h3>Acknowledge</h3>
            <div v-if="ok" class="alert ok" role="status">{{ ok }}</div>
            <ErrorBox :error="err" />
            <div class="row"><label class="sr" for="ack-note">Note</label><input id="ack-note" v-model="note" maxlength="200" placeholder="note (optional)" />
              <button class="primary" :disabled="busy" @click="ack">Acknowledge</button></div>
          </template>
          <h3>Notifications</h3>
          <table v-if="sel.data.value.notifications.length">
            <thead><tr><th>Event</th><th>Channel</th><th>Status</th><th>Sent</th></tr></thead>
            <tbody><tr v-for="n in sel.data.value.notifications" :key="n.id">
              <td>{{ n.event }}</td><td>{{ n.channel }} <span class="muted small">({{ n.channel_kind }})</span></td>
              <td><Status :s="n.status === 'sent' ? 'ok' : n.status === 'failed' ? 'failed' : 'queued'" /> <span v-if="n.detail || n.last_error" class="muted small"><TechText :text="n.detail ?? n.last_error" /></span></td>
              <td>{{ fmtTime(n.sent_at) }}</td>
            </tr></tbody>
          </table>
          <p v-else class="muted">None (no enabled channel).</p>
          <h3>Remediation</h3>
          <table v-if="sel.data.value.remediation.length">
            <thead><tr><th>#</th><th>Runbook</th><th>Status</th><th>Verified</th><th>Job</th></tr></thead>
            <tbody><tr v-for="a in sel.data.value.remediation" :key="a.id">
              <td>{{ a.attempt_no }}</td><td class="mono">{{ a.runbook }}</td><td><Status :s="a.status" /></td>
              <td>{{ a.verified === null ? '-' : a.verified ? 'recovered' : 'not recovered' }}</td>
              <td><a v-if="a.job_id" :href="'#/jobs/' + a.job_id" class="mono">{{ short(a.job_id) }}</a><span v-else class="muted">-</span></td>
            </tr></tbody>
          </table>
          <p v-else class="muted">No automatic remediation attempted.</p>
        </template>
      </section>
    </div>
  </div>
</template>
