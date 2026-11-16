<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ApiError, get, post, type AuditEvent, type Plan } from '../api'
import { fmtTime, hasRole, pretty, route, session, short, useLoad, go } from '../store'
import ErrorBox from '../components/ErrorBox.vue'
import Status from '../components/Status.vue'
import PageHeader from '../ui/PageHeader.vue'
import EmptyState from '../ui/EmptyState.vue'
import Skeleton from '../ui/Skeleton.vue'
import Segmented from '../ui/Segmented.vue'
import Button from '../ui/Button.vue'
import { asPromoteParams, isReleasePlan, releaseDiff, shortHash } from '../releases'
import type { Releases } from '../api'

const plans = useLoad(() => get<Plan[]>('plans'), 10000)
// params_hash and the requester name are only in the audit log (approver+), so look them up best-effort
const audit = useLoad(async () => (hasRole('approver') ? get<AuditEvent[]>('audit?limit=500') : []))
const rel = useLoad(async () => { try { return await get<Releases>('releases') } catch { return null } })
const promo = computed(() => (sel.value && isReleasePlan(sel.value.action) ? asPromoteParams(sel.value.params) : null))
const diff = computed(() => (promo.value ? releaseDiff(promo.value, rel.data.value?.channels ?? []) : []))
const KIND = { new: 'New in the channel', replaces: 'Replaces an older version', unchanged: 'Already there, identical' } as const
const filter = ref<'pending' | 'all'>('pending')
const rows = computed(() => (plans.data.value ?? []).filter((p) => filter.value === 'all' || p.status === 'pending_approval'))
const selId = computed(() => route.value.arg)
const sel = computed(() => plans.data.value?.find((p) => p.id === selId.value) ?? null)
const created = computed(() => audit.data.value?.find((a) => a.action === 'plan.create' && a.resource_id === selId.value))
const requester = computed(() => created.value?.actor_name ?? null)
const mine = computed(() => !!requester.value && requester.value === session.user?.username)
const hash = computed(() => (created.value?.details?.params_hash as string | undefined) ?? null)
const resolved = computed(() => (created.value?.details?.resolved_ips as string[] | undefined) ?? null)

const err = ref<ApiError | null>(null), ok = ref(''), okFor = ref(''), busy = ref(false)
watch(selId, () => { ok.value = ''; err.value = null })
async function decide(kind: 'approve' | 'reject') {
  if (!sel.value) return
  busy.value = true; err.value = null; ok.value = ''
  try {
    const r = await post<{ status: string; job_id: string | null }>(`plans/${sel.value.id}/${kind}`)
    ok.value = kind === 'reject' ? 'Plan rejected.' : r.job_id ? `Approved; job ${r.job_id} queued.` : `Approval recorded (status: ${r.status.replace('_', ' ')}); another approver is still required.`
    okFor.value = sel.value.id
    await plans.reload()
  } catch (e) { err.value = e as ApiError } finally { busy.value = false }
}
</script>
<template>
  <div class="page">
    <PageHeader title="Approvals" sub="Proposed changes waiting for review. High-risk plans need two distinct approvers." help="Every change is a plan first. Approvers review the parameters and decide; approved plans become jobs.">
      <template #actions><Segmented v-model="filter" :options="[{ value: 'pending', label: 'Pending' }, { value: 'all', label: 'All plans' }]" label="Filter" /></template>
    </PageHeader>
    <Skeleton v-if="!plans.data.value && !plans.error.value" />
    <ErrorBox :error="plans.error.value" />
    <div class="split">
      <section class="card flush">
        <div class="scroll" tabindex="0" role="region" aria-label="Scrollable table">
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
          <EmptyState v-else-if="plans.data.value" icon="shield" :title="filter === 'pending' ? 'Nothing waiting for approval' : 'No plans yet'" text="Proposed changes show up here for review." />
        </div>
      </section>
      <section v-if="selId" class="card detail" aria-label="Plan details">
        <div class="head"><h2>Plan {{ short(selId) }}</h2><Button size="sm" variant="ghost" icon="x" @click="go('plans')">Close</Button></div>
        <p v-if="!sel && plans.data.value" class="muted">Plan not found.</p>
        <template v-if="sel">
          <dl class="kv">
            <dt>Action</dt><dd class="mono">{{ sel.action }}</dd>
            <dt>Risk</dt><dd><Status :s="sel.risk" /> <span class="muted small">{{ sel.approvals_required && sel.approvals_required > 1 ? 'needs ' + sel.approvals_required + ' distinct approvers' : sel.risk === 'high' ? 'needs distinct approvers' : 'one approver' }}</span></dd>
            <dt>Status</dt><dd><Status :s="sel.status" /></dd>
            <dt>Requested by</dt><dd>{{ requester ?? 'id ' + short(sel.requested_by) }}<span v-if="mine"> (you)</span></dd>
            <dt>Created</dt><dd>{{ fmtTime(sel.created_at) }}</dd>
            <dt v-if="sel.decided_at">Decided</dt><dd v-if="sel.decided_at">{{ fmtTime(sel.decided_at) }}</dd>
            <dt>Params hash</dt><dd class="mono wrap">{{ hash ?? 'not available to your role (audit access needed)' }}</dd>
            <dt v-if="resolved">Resolved IPs</dt><dd v-if="resolved" class="mono">{{ resolved.join(', ') }}</dd>
          </dl>
          <template v-if="promo">
            <h3>What will change</h3>
            <p class="small">Moves <b>{{ promo.component }}</b> from <b>{{ promo.from_channel }}</b> to <b>{{ promo.to_channel }}</b>. Check each file and its hash; the signer refuses anything that differs from this list.<template v-if="promo.reason"> Reason given: {{ promo.reason }}</template></p>
            <div class="tablewrap"><table class="dense" data-testid="release-diff" aria-label="Release diff">
              <thead><tr><th>Package</th><th>Change</th><th>SHA-256</th><th>Test record</th></tr></thead>
              <tbody><tr v-for="r in diff" :key="r.file" :data-kind="r.kind">
                <td class="mono">{{ r.name }}</td><td>{{ KIND[r.kind] }}<span v-if="r.was"> (was {{ r.was }})</span></td>
                <td class="mono small" :title="r.sha256">{{ shortHash(r.sha256, 16) }}...</td><td class="mono small">{{ r.evidence ? shortHash(r.evidence, 12) + '...' : 'none (source file)' }}</td></tr></tbody>
            </table></div>
          </template>
          <h3>{{ promo ? 'Raw parameters' : 'Parameters' }}</h3>
          <pre class="code" tabindex="0">{{ pretty(sel.params) }}</pre>
          <p class="muted small">Secrets are never returned by the API.</p>
          <div v-if="ok && okFor === sel.id" class="alert ok" role="status"><span class="grow">{{ ok }}</span>
            <button type="button" class="ghost sm" @click="ok = ''">Dismiss</button></div>
          <template v-if="sel.status === 'pending_approval'">
            <div v-if="!hasRole('approver')" class="alert info">Only approvers can decide plans.</div>
            <div v-else-if="mine" class="alert warn">You requested this plan; the server will refuse your approval or rejection.</div>
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
