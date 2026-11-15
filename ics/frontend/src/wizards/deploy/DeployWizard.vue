<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { api, load } from '../api'
import type { Component, DiscNetwork, DiscStorage, Endpoint, Loaded, PlanCreated, Profile } from '../api'
import { Banner, Field, HelpNote, Unavailable, WizardShell, fmtGb, useWizard } from '../kit'
import JobSteps from '../kit/JobSteps.vue'
import PlanReview from './PlanReview.vue'
import { PROFILE_ORDER, assertSubmittable, buildCreateParams, buildRequest, deploySteps, newDeployModel, planBlocked, requestKey } from './state'

const m = reactive(newDeployModel())
const wz = useWizard(deploySteps, m)
const profiles = ref<Loaded<Profile[]> | null>(null)
const components = ref<Loaded<Component[]> | null>(null)
const endpoints = ref<Loaded<Endpoint[]> | null>(null)
const storage = ref<Loaded<DiscStorage[]> | null>(null)
const networks = ref<Loaded<DiscNetwork[]> | null>(null)
const planning = ref(false)
const planError = ref('')
const submitting = ref(false)
const submitError = ref('')
const created = ref<PlanCreated | null>(null)
const err = (k: string) => wz.m.errors[k]

onMounted(async () => {
  ;[profiles.value, components.value, endpoints.value, storage.value, networks.value] = await Promise.all([
    load(() => api.profiles()), load(() => api.components()), load(() => api.endpoints()),
    load(() => api.infra<DiscStorage>('storage')), load(() => api.infra<DiscNetwork>('networks')),
  ])
})

const sortedProfiles = computed(() => {
  if (profiles.value?.state !== 'ok') return []
  const rank = (id: string) => { const i = PROFILE_ORDER.indexOf(id); return i < 0 ? 99 : i }
  return [...profiles.value.data].sort((a, b) => rank(a.id) - rank(b.id))
})
const optionalComponents = computed(() => (components.value?.state === 'ok' ? components.value.data.filter((c) => c.optional) : []))
const diskStorage = computed(() => (storage.value?.state === 'ok' ? storage.value.data.filter((s) => s.content.includes('images')) : []))
const backupStorage = computed(() => (storage.value?.state === 'ok' ? storage.value.data.filter((s) => s.content.includes('backup')) : []))
const selected = computed(() => sortedProfiles.value.find((p) => p.id === m.profile))
const onPlan = computed(() => wz.current.value.id === 'plan')

function pick(p: Profile) {
  m.profile = p.id
  m.availability = p.ha ? 'ha' : 'single'
  if (p.multi_tenant && m.tenants < 2) m.tenants = 2
  m.optional = (components.value?.state === 'ok' ? components.value.data : []).filter((c) => c.optional && c.default_on && p.components.includes(c.id)).map((c) => c.id)
}

async function replan() {
  planError.value = ''; m.confirmed = false
  const key = requestKey(m)
  planning.value = true
  try { m.plan = await api.planDeployment(buildRequest(m)); m.planKey = key }
  catch (e) { m.plan = null; m.planKey = null; planError.value = e instanceof Error ? e.message : String(e) }
  finally { planning.value = false }
}
watch(() => wz.m.index, (i) => { if (deploySteps[i].id === 'plan' && !created.value) void replan() })
// any edit invalidates a previously reviewed plan
watch(() => requestKey(m), () => { m.confirmed = false })

const stale = computed(() => !!m.plan && m.planKey !== requestKey(m))
const canSubmit = computed(() => { try { assertSubmittable(m, onPlan.value); return true } catch { return false } })
async function submit() {
  submitError.value = ''
  try { assertSubmittable(m, onPlan.value) } catch (e) { submitError.value = (e as Error).message; return }
  submitting.value = true
  try { created.value = await api.submitPlan('deployment.create', buildCreateParams(m)) }
  catch (e) { submitError.value = e instanceof Error ? e.message : String(e) }
  finally { submitting.value = false }
}
function adjust(id: string) { const i = deploySteps.findIndex((s) => s.id === id); wz.goto(i) }
</script>

<template>
  <WizardShell
    title="New deployment" subtitle="Pick a profile, describe the environment, and review the generated plan. Nothing is created until the plan is approved."
    :steps="deploySteps" :index="wz.m.index" :reached="wz.m.reached" :hide-nav="onPlan" :hide-next="onPlan" :busy="planning || submitting"
    @next="wz.next()" @back="wz.back()" @goto="wz.goto($event)"
  >
    <!-- profile -->
    <div v-show="wz.current.value.id === 'profile'">
      <Unavailable v-if="profiles?.state === 'unavailable'" what="The deployment catalog" endpoint="GET /api/v1/catalog/profiles" :status="profiles.status" />
      <Banner v-else-if="profiles?.state === 'error'" kind="bad">{{ profiles.message }}</Banner>
      <p v-if="err('profile')" class="bad-text" role="alert">{{ err('profile') }}</p>
      <div class="wz-cards" role="group" aria-label="Deployment profiles">
        <button v-for="p in sortedProfiles" :key="p.id" type="button" class="wz-pick" :aria-pressed="m.profile === p.id" @click="pick(p)">
          <b>{{ p.label }}</b>
          <span class="muted">{{ p.description }}</span>
          <span class="small">
            <span v-if="p.users_min !== undefined">{{ p.users_min }}{{ p.users_max ? '-' + p.users_max : '+' }} users &middot; </span>
            <span v-if="p.vm_count">{{ p.vm_count }} VM{{ p.vm_count > 1 ? 's' : '' }}</span>
            <span v-if="p.ha" class="wz-chip info"> HA</span><span v-if="p.multi_tenant" class="wz-chip info"> multi-tenant</span>
          </span>
        </button>
      </div>
    </div>

    <!-- sizing -->
    <div v-show="wz.current.value.id === 'sizing'" class="wz-card">
      <h2>Size and availability</h2>
      <p class="muted">Profile: <b>{{ selected?.label ?? m.profile }}</b>. Resources are computed from these numbers, not guessed.</p>
      <div class="wz-grid">
        <Field label="Environment name" :error="err('name')" hint="Used in VM names and tags." v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.name" type="text" autocomplete="off" :aria-invalid="invalid" /></Field>
        <Field label="Users" :error="err('users')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.users" type="number" min="1" :aria-invalid="invalid" /></Field>
        <Field label="Tenants" :error="err('tenants')" hint="Customers isolated from each other." v-slot="{ id, invalid }"><input :id="id" v-model.number="m.tenants" type="number" min="1" :aria-invalid="invalid" /></Field>
        <Field label="Availability" v-slot="{ id }"><select :id="id" v-model="m.availability"><option value="single">Single instance</option><option value="ha">High availability (replicated)</option></select></Field>
      </div>
      <HelpNote title="What does availability change?">Single instance runs one copy of each component. High availability adds replicas on separate nodes where the cluster has them; the plan review warns if it cannot.</HelpNote>
    </div>

    <!-- placement -->
    <div v-show="wz.current.value.id === 'placement'" class="wz-card">
      <h2>Placement</h2>
      <Unavailable v-if="endpoints?.state === 'unavailable'" what="Endpoints" endpoint="GET /api/v1/endpoints" :status="endpoints.status" />
      <Banner v-else-if="endpoints?.state === 'ok' && !endpoints.data.length" kind="warn" title="No infrastructure endpoint">Run <a href="#/setup">First-run setup</a> to connect one.</Banner>
      <Unavailable v-if="storage?.state === 'unavailable'" what="Storage inventory" endpoint="GET /api/v1/infra/storage" :status="storage.status" />
      <Unavailable v-if="networks?.state === 'unavailable'" what="Network inventory" endpoint="GET /api/v1/infra/networks" :status="networks.status" />
      <div class="wz-grid">
        <Field label="Infrastructure endpoint" :error="err('endpointId')" v-slot="{ id, invalid }">
          <select :id="id" v-model="m.endpointId" :aria-invalid="invalid"><option value="">Select…</option><option v-for="e in endpoints?.state === 'ok' ? endpoints.data : []" :key="e.id" :value="e.id">{{ e.name }} ({{ e.base_url }})</option></select>
        </Field>
        <Field label="VM disk storage" :error="err('storage')" v-slot="{ id, invalid }">
          <select :id="id" v-model="m.storage" :aria-invalid="invalid"><option value="">Select…</option><option v-for="s in diskStorage" :key="s.id + s.node" :value="s.id">{{ s.id }} ({{ fmtGb(s.total_gb - s.used_gb) }} free)</option></select>
        </Field>
        <Field label="Bridge" :error="err('bridge')" v-slot="{ id, invalid }">
          <select :id="id" v-model="m.bridge" :aria-invalid="invalid"><option value="">Select…</option><option v-for="n in networks?.state === 'ok' ? networks.data : []" :key="n.name + n.node" :value="n.name">{{ n.name }}</option></select>
        </Field>
        <Field label="VLAN tag" optional :error="err('vlan')" v-slot="{ id, invalid }"><input :id="id" v-model="m.vlan" type="text" inputmode="numeric" :aria-invalid="invalid" /></Field>
      </div>
      <p class="small muted">Only storage, bridges and pools the endpoint is allowed to use are accepted when the plan runs.</p>
    </div>

    <!-- options -->
    <div v-show="wz.current.value.id === 'options'" class="wz-card">
      <h2>Backups and optional components</h2>
      <label class="wz-choice"><input v-model="m.backupEnabled" type="checkbox" /> Back up this environment</label>
      <div v-if="m.backupEnabled" class="wz-grid mt">
        <Field label="Backup destination" :error="err('backupStorage')" v-slot="{ id, invalid }">
          <select :id="id" v-model="m.backupStorage" :aria-invalid="invalid"><option value="">Select…</option><option v-for="s in backupStorage" :key="s.id + s.node" :value="s.id">{{ s.id }} ({{ fmtGb(s.total_gb - s.used_gb) }} free)</option></select>
        </Field>
        <Field label="Retention (days)" :error="err('retentionDays')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.retentionDays" type="number" min="1" :aria-invalid="invalid" /></Field>
      </div>
      <h3>Optional components</h3>
      <p v-if="components?.state === 'unavailable'"><Unavailable what="The component catalog" endpoint="GET /api/v1/catalog/components" :status="components.status" /></p>
      <p v-else-if="!optionalComponents.length" class="muted">This catalog has no optional components.</p>
      <label v-for="c in optionalComponents" :key="c.id" class="wz-choice"><input v-model="m.optional" type="checkbox" :value="c.id" /> <span><b>{{ c.label }}</b><span v-if="c.description" class="muted"> &mdash; {{ c.description }}</span></span></label>
    </div>

    <!-- plan -->
    <div v-show="wz.current.value.id === 'plan'">
      <template v-if="created">
        <Banner kind="ok" title="Deployment plan submitted">Plan <span class="mono">{{ created.plan_id }}</span> is {{ created.status.replace('_', ' ') }} (risk {{ created.risk }}, {{ created.approvals_required }} approval(s) required).</Banner>
        <div class="wz-card">
          <h2>Progress</h2>
          <template v-if="created.job_id">
            <p>Job <a :href="'#/jobs/' + created.job_id" class="mono">{{ created.job_id }}</a></p>
            <JobSteps :job-id="created.job_id" />
          </template>
          <p v-else class="muted">The job is created when the plan is approved. Follow it under <a href="#/plans">Plans</a>, then <a href="#/jobs">Jobs</a>.</p>
        </div>
      </template>
      <template v-else>
        <p v-if="planning" role="status" class="muted">Generating plan…</p>
        <Banner v-if="planError" kind="bad" title="Could not generate a plan">{{ planError }}</Banner>
        <Unavailable v-if="planError.startsWith('404')" what="Deployment planning" endpoint="POST /api/v1/deployments/plan" :status="404" />
        <Banner v-if="stale" kind="warn" title="Inputs changed">The plan below no longer matches your inputs. Re-plan before submitting.</Banner>
        <PlanReview v-if="m.plan" :plan="m.plan" />
        <div class="wz-card">
          <h2>Adjust and re-plan</h2>
          <div class="wz-row">
            <button type="button" class="wz-btn" @click="adjust('sizing')">Change size</button>
            <button type="button" class="wz-btn" @click="adjust('placement')">Change placement</button>
            <button type="button" class="wz-btn" @click="adjust('options')">Change backup / options</button>
            <button type="button" class="wz-btn" :disabled="planning" @click="replan">Re-plan</button>
          </div>
          <p class="small muted">Plan hash <span class="mono">{{ m.plan?.plan_hash ?? 'none' }}</span>: the same inputs always produce the same plan.</p>
        </div>
        <Banner v-if="submitError" kind="bad" title="Not submitted">{{ submitError }}</Banner>
        <label class="wz-choice"><input v-model="m.confirmed" type="checkbox" :disabled="!m.plan || stale || planBlocked(m.plan)" /> I have reviewed this plan, including warnings and capacity, and want to submit it for approval.</label>
        <div class="wz-footer"><button type="button" class="wz-btn" @click="wz.back()">Back</button><span class="spacer"></span>
          <button type="button" class="wz-btn primary" :disabled="!canSubmit || submitting" @click="submit">{{ submitting ? 'Submitting…' : 'Submit deployment plan' }}</button></div>
      </template>
    </div>
  </WizardShell>
</template>
