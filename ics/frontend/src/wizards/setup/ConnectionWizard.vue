<script setup lang="ts">
// /setup/connection[?endpoint=<id>]: just the connection step. With an id it edits that endpoint (plan = endpoint.update);
// without one it adds an endpoint (plan = endpoint.register, connection only).
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { api, load } from '../api'
import type { Loaded, PlanCreated } from '../api'
import { Banner, Unavailable, WizardShell, useWizard } from '../kit'
import ConnectionStep from './ConnectionStep.vue'
import { assertConnectionSubmittable, buildAddParams, buildUpdateParams, connectionKey, connectionSteps, newSetupModel, prefillFromEndpoint } from './state'

const props = defineProps<{ endpointId?: string }>()
function queryEndpoint(): string | null {
  const h = typeof location !== 'undefined' ? location.hash : ''
  const q = h.includes('?') ? h.slice(h.indexOf('?') + 1) : (typeof location !== 'undefined' ? location.search.slice(1) : '')
  return new URLSearchParams(q).get('endpoint')
}
const eid = props.endpointId ?? queryEndpoint()

const m = reactive(newSetupModel())
const wz = useWizard(connectionSteps, m)
const loadErr = ref<Loaded<unknown> | null>(null)
const notFound = ref(false)
const created = ref<PlanCreated | null>(null)
const submitting = ref(false)
const submitError = ref('')
const editing = !!eid
const onReview = computed(() => wz.current.value.id === 'review')

onMounted(async () => {
  if (!eid) return
  const r = await load(() => api.endpoints())
  if (r.state !== 'ok') { loadErr.value = r; return }
  const e = r.data.find((x) => x.id === eid)
  if (!e) { notFound.value = true; return }
  prefillFromEndpoint(m, e)
})
watch(() => connectionKey(m), () => { m.confirmed = false; wz.truncateReached(0) })

const params = computed(() => (editing ? buildUpdateParams(m) : buildAddParams(m)))
const masked = computed(() => JSON.stringify({ action: editing ? 'endpoint.update' : 'endpoint.register', params: { ...params.value, token_secret: '•••••••• (entered, never shown again)' } }, null, 2))
const canSubmit = computed(() => { try { assertConnectionSubmittable({ ...m, endpointId: editing ? m.endpointId : 'new' }, onReview.value); return true } catch { return false } })

async function submit() {
  submitError.value = ''
  submitting.value = true
  try {
    created.value = await api.submitPlan(editing ? 'endpoint.update' : 'endpoint.register', params.value)
    m.tokenSecret = ''; m.probe = null; m.probedKey = null; m.tlsCheck = null
  } catch (e) { submitError.value = e instanceof Error ? e.message : String(e) } finally { submitting.value = false }
}
</script>

<template>
  <WizardShell
    :title="editing ? 'Edit endpoint connection' : 'Add infrastructure endpoint'"
    :subtitle="editing ? 'Verify the server, re-enter the token, and submit the change as a plan. Existing defaults and policy stay as they are.' : 'Verify the server and token, then submit the endpoint for approval.'"
    :steps="connectionSteps" :index="wz.m.index" :reached="wz.m.reached" :hide-nav="onReview" :hide-next="onReview" :busy="submitting"
    @next="wz.next()" @back="wz.back()" @goto="wz.goto($event)"
  >
    <Unavailable v-if="loadErr?.state === 'unavailable'" what="Endpoints" endpoint="GET /api/v1/endpoints" :status="loadErr.status" />
    <Banner v-else-if="loadErr?.state === 'error'" kind="bad">{{ loadErr.message }}</Banner>
    <Banner v-if="notFound" kind="bad" title="Endpoint not found">No endpoint with that id exists.</Banner>
    <div v-show="wz.current.value.id === 'connection'"><ConnectionStep :m="m" :errors="wz.m.errors" :editing="editing" @errors="wz.m.errors = $event" /></div>
    <div v-show="wz.current.value.id === 'review'">
      <div v-if="created" class="wz-card"><Banner kind="ok" title="Plan submitted">Plan <span class="mono">{{ created.plan_id }}</span> is {{ created.status.replace('_', ' ') }} (risk {{ created.risk }}, {{ created.approvals_required }} approval(s) required). Nothing changes until it is approved.</Banner><p><a href="#/plans">Open Plans</a></p></div>
      <template v-else>
        <div class="wz-card">
          <h2>Review</h2>
          <dl class="wz-dl">
            <dt>Action</dt><dd class="mono">{{ editing ? 'endpoint.update' : 'endpoint.register' }} (high risk, needs approval)</dd>
            <dt>Endpoint</dt><dd>{{ m.name }} &middot; https://{{ m.host }}:{{ m.port }}</dd>
            <dt>Server identity</dt><dd>{{ m.trust === 'ca' ? 'CA bundle' : 'Pinned fingerprint' }} (verified before the token was sent)</dd>
            <dt>Token</dt><dd class="mono">{{ m.tokenId }} (secret entered)</dd>
            <dt>Credential roles</dt><dd>{{ (params.credential_roles as string[]).join(', ') }}</dd>
          </dl>
          <p v-if="!editing" class="small muted">Provisioning scopes (pool, storage, networks) are empty until they are set in first-run setup.</p>
        </div>
        <details class="wz-help"><summary>Exact request body</summary><pre class="mono wz-code">{{ masked }}</pre></details>
        <Banner v-if="submitError" kind="bad" title="Not submitted">{{ submitError }}</Banner>
        <label class="wz-choice"><input v-model="m.confirmed" type="checkbox" /> I have reviewed this change and want to submit it for approval.</label>
        <div class="wz-footer"><button type="button" class="wz-btn" @click="wz.back()">Back</button><span class="spacer"></span>
          <button type="button" class="wz-btn primary" :disabled="!canSubmit || submitting" @click="submit">{{ submitting ? 'Submitting…' : 'Submit plan for approval' }}</button></div>
      </template>
    </div>
  </WizardShell>
</template>
