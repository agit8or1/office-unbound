<script setup lang="ts">
import { computed, ref } from 'vue'
import { ApiError, get, post, type AuditEvent, type Plan } from '../api'
import { fmtTime, hasRole, pretty, route, session, short, useLoad, go } from '../store'
import ErrorBox from '../components/ErrorBox.vue'
import Status from '../components/Status.vue'

const plans = useLoad(() => get<Plan[]>('plans'), 10000)
// params_hash and the requester name are only in the audit log (approver+), so look them up best-effort
const audit = useLoad(async () => (hasRole('approver') ? get<AuditEvent[]>('audit?limit=500') : []))
const filter = ref<'pending' | 'all'>('pending')
const rows = computed(() => (plans.data.value ?? []).filter((p) => filter.value === 'all' || p.status === 'pending_approval'))
const selId = computed(() => route.value.arg)
const sel = computed(() => plans.data.value?.find((p) => p.id === selId.value) ?? null)
const created = computed(() => audit.data.value?.find((a) => a.action === 'plan.create' && a.resource_id === selId.value))
const requester = computed(() => created.value?.actor_name ?? null)
const mine = computed(() => !!requester.value && requester.value === session.user?.username)
const hash = computed(() => (created.value?.details?.params_hash as string | undefined) ?? null)
const resolved = computed(() => (created.value?.details?.resolved_ips as string[] | undefined) ?? null)

const err = ref<ApiError | null>(null), ok = ref(''), busy = ref(false)
async function decide(kind: 'approve' | 'reject') {
  if (!sel.value) return
  busy.value = true; err.value = null; ok.value = ''
  try {
    const r = await post<{ status: string; job_id: string | null }>(`plans/${sel.value.id}/${kind}`)
    ok.value = kind === 'reject' ? 'Plan rejected.' : r.job_id ? `Approved; job ${r.job_id} queued.` : `Approval recorded (status: ${r.status.replace('_', ' ')}); another approver is still required.`
    await plans.reload()
  } catch (e) { err.value = e as ApiError } finally { busy.value = false }
}
</script>
<template>
  <div class="page">
    <div class="head"><h1>Plans</h1>
      <div class="seg" role="group" aria-label="Filter">
        <button :aria-pressed="filter === 'pending'" @click="filter = 'pending'">Pending</button>
        <button :aria-pressed="filter === 'all'" @click="filter = 'all'">All</button>
      </div>
    </div>
    <ErrorBox :error="plans.error.value" />
    <div class="split">
      <section class="panel fill">
        <div class="scroll">
          <table v-if="rows.length">
            <thead><tr><th>Action</th><th>Target</th><th>Risk</th><th>Status</th><th>Created</th></tr></thead>
            <tbody>
              <tr v-for="p in rows" :key="p.id" :class="{ sel: p.id === selId }">
                <td><a :href="'#/plans/' + p.id" class="mono">{{ p.action }}</a></td>
                <td>{{ p.params.name ?? p.params.username ?? short(String(p.params.endpoint_id ?? ''), 8) }}</td>
                <td><Status :s="p.risk" /></td><td><Status :s="p.status" /></td><td>{{ fmtTime(p.created_at) }}</td>
              </tr>
            </tbody>
          </table>
          <p v-else-if="plans.data.value" class="empty">{{ filter === 'pending' ? 'No plans are waiting for approval.' : 'No plans yet.' }}</p>
        </div>
      </section>
      <section v-if="selId" class="panel detail" aria-label="Plan details">
        <div class="head"><h2>Plan {{ short(selId) }}</h2><button class="ghost" @click="go('plans')">Close</button></div>
        <p v-if="!sel && plans.data.value" class="muted">Plan not found.</p>
        <template v-if="sel">
          <dl class="kv">
            <dt>Action</dt><dd class="mono">{{ sel.action }}</dd>
            <dt>Risk</dt><dd><Status :s="sel.risk" /> <span class="muted small">{{ sel.risk === 'high' ? 'needs 2 distinct approvers' : 'auto-approved' }}</span></dd>
            <dt>Status</dt><dd><Status :s="sel.status" /></dd>
            <dt>Requested by</dt><dd>{{ requester ?? 'id ' + short(sel.requested_by) }}<span v-if="mine"> (you)</span></dd>
            <dt>Created</dt><dd>{{ fmtTime(sel.created_at) }}</dd>
            <dt v-if="sel.decided_at">Decided</dt><dd v-if="sel.decided_at">{{ fmtTime(sel.decided_at) }}</dd>
            <dt>Params hash</dt><dd class="mono wrap">{{ hash ?? 'not available to your role (audit access needed)' }}</dd>
            <dt v-if="resolved">Resolved IPs</dt><dd v-if="resolved" class="mono">{{ resolved.join(', ') }}</dd>
          </dl>
          <h3>Parameters</h3>
          <pre class="code" tabindex="0">{{ pretty(sel.params) }}</pre>
          <p class="muted small">Secrets are never returned by the API.</p>
          <template v-if="sel.status === 'pending_approval'">
            <div v-if="!hasRole('approver')" class="alert info">Only approvers can decide plans.</div>
            <div v-else-if="mine" class="alert warn">You requested this plan; the server will refuse your approval or rejection.</div>
            <div v-if="ok" class="alert ok" role="status">{{ ok }}</div>
            <ErrorBox :error="err" />
            <div v-if="hasRole('approver')" class="row">
              <button class="primary" :disabled="busy" @click="decide('approve')">Approve</button>
              <button class="danger" :disabled="busy" @click="decide('reject')">Reject</button>
            </div>
            <p v-if="hasRole('approver')" class="muted small">
              The server also blocks approvers created or elevated by the requester, role changes for yourself, double approvals and expired plans, and shows its reason here.
            </p>
          </template>
        </template>
      </section>
    </div>
  </div>
</template>
