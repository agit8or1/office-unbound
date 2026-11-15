<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { api, load } from '../api'
import type { Component, DiscNetwork, DiscStorage, Endpoint, Loaded, OsImage, PlanCreated, Profile } from '../api'
import { Banner, Field, HelpNote, Unavailable, WizardShell, fmtGb, useWizard } from '../kit'
import JobSteps from '../kit/JobSteps.vue'
import PlanReview from './PlanReview.vue'
import { PROFILE_ORDER, assertSubmittable, buildCreateParams, buildRequest, deploySteps, newDeployModel, optionalHelp, planBlocked, requestKey } from './state'

const m = reactive(newDeployModel())
const wz = useWizard(deploySteps, m)
const profiles = ref<Loaded<Profile[]> | null>(null)
const components = ref<Loaded<Component[]> | null>(null)
const osImages = ref<Loaded<OsImage[]> | null>(null)
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
  ;[profiles.value, components.value, osImages.value, endpoints.value] = await Promise.all([
    load(() => api.profiles()), load(() => api.components()), load(() => api.osImages()), load(() => api.endpoints()),
  ])
  // express path: "small" is the recommended starting profile; a single deployable endpoint is chosen for the user
  if (profiles.value.state === 'ok') { const small = profiles.value.data.find((p) => p.id === 'small'); if (small) pick(small) }
  if (endpoints.value.state === 'ok') {
    const usable = endpoints.value.data.filter((e) => e.credentials.provision.present && e.enabled !== false)
    if (usable.length === 1) m.endpoint = usable[0]!.name
  }
})

const endpoint = computed(() => (endpoints.value?.state === 'ok' ? endpoints.value.data.find((e) => e.name === m.endpoint) : undefined))
// storage and bridges come from the chosen endpoint's own discovered inventory
watch(() => endpoint.value?.id, async (id) => {
  m.pool = ''; m.storage = ''; m.bridge = ''
  storage.value = networks.value = null
  if (!id) return
  ;[storage.value, networks.value] = await Promise.all([
    load(() => api.infra('storage', id) as Promise<DiscStorage[]>), load(() => api.infra('networks', id) as Promise<DiscNetwork[]>),
  ])
  // express path: pre-fill whatever the endpoint's own scope and saved defaults make unambiguous
  const ep = endpoint.value
  const pools = ep?.scope.allowed_pools ?? []
  if (pools.length === 1) m.pool = pools[0]!
  const okStorage = diskStorage.value.filter((s) => !ep || ep.scope.allowed_storage.includes(s.id))
  const wantedStorage = ep?.defaults?.storage
  if (wantedStorage && okStorage.some((s) => s.id === wantedStorage)) m.storage = wantedStorage
  else if (new Set(okStorage.map((s) => s.id)).size === 1) m.storage = okStorage[0]!.id
  const wantedBridge = ep?.defaults?.bridge
  if (wantedBridge && bridges.value.some((b) => b.name === wantedBridge)) m.bridge = wantedBridge
  else if (bridges.value.length === 1) m.bridge = bridges.value[0]!.name
  if (ep?.defaults?.vlan) m.vlan = String(ep.defaults.vlan)
})

const label = (id: string) => (components.value?.state === 'ok' ? components.value.data.find((c) => c.id === id)?.label : undefined) ?? id
const describe = (id: string) => optionalHelp(id, components.value?.state === 'ok' ? components.value.data.find((c) => c.id === id)?.description : undefined)
const sortedProfiles = computed(() => {
  if (profiles.value?.state !== 'ok') return []
  const rank = (id: string) => { const i = PROFILE_ORDER.indexOf(id); return i < 0 ? 99 : i }
  return [...profiles.value.data].sort((a, b) => rank(a.id) - rank(b.id))
})
const diskStorage = computed(() => (storage.value?.state === 'ok' ? storage.value.data.filter((s) => s.content.includes('images')) : []))
const bridges = computed(() => (networks.value?.state === 'ok' ? [...new Map(networks.value.data.filter((n) => n.kind === 'bridge').map((n) => [n.name, n])).values()] : []))
const selected = computed(() => sortedProfiles.value.find((p) => p.id === m.profile))
const onPlan = computed(() => wz.current.value.id === 'plan')

function pick(p: Profile) {
  m.profile = p.id
  if (p.multi_tenant && m.tenants < 2) m.tenants = 2
  m.optionalAvailable = [...p.optional_components]
  m.optional = [...p.default_optional]
  m.federation = false
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
            <span v-if="p.users_max !== undefined">up to {{ p.users_max }} users &middot; </span>
            <span v-if="p.vm_count">{{ p.vm_count }} VM{{ p.vm_count > 1 ? 's' : '' }}</span>
            <span v-if="p.ha" class="wz-chip info"> HA</span><span v-if="p.multi_tenant" class="wz-chip info"> multi-tenant</span>
            <span v-if="p.maturity === 'experimental'" class="wz-chip warn"> experimental</span>
          </span>
        </button>
      </div>
    </div>

    <!-- sizing -->
    <div v-show="wz.current.value.id === 'sizing'" class="wz-card">
      <h2>Who is this for?</h2>
      <p class="muted">Profile: <b>{{ selected?.label ?? m.profile }}</b>. Resources are computed from these numbers, not guessed.</p>
      <div class="wz-grid">
        <Field label="Customer" :error="err('customerId')" hint="Short identifier of the customer this environment belongs to." v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.customerId" type="text" autocomplete="off" :aria-invalid="invalid" /></Field>
        <Field label="Environment name" :error="err('name')" hint="Used in VM names and the ownership tag; cannot be changed later." v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.name" type="text" autocomplete="off" :aria-invalid="invalid" /></Field>
        <Field label="Customer domain" :error="err('domain')" hint="Used for service host names and DNS records." v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.domain" type="text" placeholder="your-company.tld" autocomplete="off" :aria-invalid="invalid" /></Field>
        <Field label="Users (per tenant)" :error="err('users')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.users" type="number" min="1" :aria-invalid="invalid" /></Field>
        <Field label="Tenants" :error="err('tenants')" hint="Customers isolated from each other." v-slot="{ id, invalid }"><input :id="id" v-model.number="m.tenants" type="number" min="1" :aria-invalid="invalid" /></Field>
      </div>
      <HelpNote title="High availability">Availability is a property of the profile: choose the HA profile to get replicas on separate nodes. The plan review warns when the cluster cannot place them.</HelpNote>
    </div>

    <!-- placement -->
    <div v-show="wz.current.value.id === 'placement'" class="wz-card">
      <h2>Where should it run?</h2>
      <Unavailable v-if="endpoints?.state === 'unavailable'" what="Endpoints" endpoint="GET /api/v1/endpoints" :status="endpoints.status" />
      <Banner v-else-if="endpoints?.state === 'ok' && !endpoints.data.length" kind="warn" title="No cluster connected yet"><a href="#/setup">Connect Proxmox</a> first, then come back.</Banner>
      <Banner v-else-if="endpoints?.state === 'ok' && !endpoints.data.some((e) => e.credentials.provision.present)" kind="warn" title="Read-only connection">None of your connected clusters has a provisioning token, so ICS cannot create machines yet. <a href="#/setup/connection">Add one</a>.</Banner>
      <Unavailable v-if="storage?.state === 'unavailable'" what="Storage inventory" endpoint="GET /api/v1/infra/storage" :status="storage.status" />
      <Unavailable v-if="networks?.state === 'unavailable'" what="Network inventory" endpoint="GET /api/v1/infra/networks" :status="networks.status" />
      <p v-if="m.endpoint && m.pool && m.storage && m.bridge" class="muted">We will use <b>{{ m.endpoint }}</b>, pool <b>{{ m.pool }}</b>, storage <b>{{ m.storage }}</b> and network <b>{{ m.bridge }}</b>. Change this under Customize if needed.</p>
      <details class="wz-help" :open="!(m.endpoint && m.pool && m.storage && m.bridge) || Object.keys(wz.m.errors).length > 0"><summary>Customize</summary>
      <div class="wz-grid">
        <Field label="Infrastructure endpoint" :error="err('endpoint')" v-slot="{ id, invalid }">
          <select :id="id" v-model="m.endpoint" :aria-invalid="invalid"><option value="">Select…</option><option v-for="e in endpoints?.state === 'ok' ? endpoints.data : []" :key="e.id" :value="e.name" :disabled="!e.credentials.provision.present">{{ e.name }} ({{ e.base_url }}){{ e.credentials.provision.present ? '' : ' - inventory only, cannot deploy' }}</option></select>
        </Field>
        <Field label="Resource pool" :error="err('pool')" hint="Only pools the endpoint allows are listed." v-slot="{ id, invalid }">
          <select :id="id" v-model="m.pool" :aria-invalid="invalid"><option value="">Select…</option><option v-for="p in endpoint?.scope.allowed_pools ?? []" :key="p" :value="p">{{ p }}</option></select>
        </Field>
        <Field label="VM disk storage" :error="err('storage')" v-slot="{ id, invalid }">
          <select :id="id" v-model="m.storage" :aria-invalid="invalid"><option value="">Select…</option><option v-for="s in diskStorage" :key="s.id + s.node" :value="s.id" :disabled="!!endpoint && !endpoint.scope.allowed_storage.includes(s.id)">{{ s.id }} ({{ fmtGb(s.total_gb - s.used_gb) }} free)</option></select>
        </Field>
        <Field label="Bridge" :error="err('bridge')" v-slot="{ id, invalid }">
          <select :id="id" v-model="m.bridge" :aria-invalid="invalid"><option value="">Select…</option><option v-for="n in bridges" :key="n.name" :value="n.name">{{ n.name }}</option></select>
        </Field>
        <Field label="VLAN tag" optional :error="err('vlan')" v-slot="{ id, invalid }"><input :id="id" v-model="m.vlan" type="text" inputmode="numeric" :aria-invalid="invalid" /></Field>
        <Field v-if="osImages?.state === 'ok'" label="OS image" optional hint="Empty = the catalog default." v-slot="{ id }">
          <select :id="id" v-model="m.osImage"><option value="">Catalog default</option><option v-for="o in osImages.data" :key="o.id" :value="o.id">{{ o.title }}</option></select>
        </Field>
      </div>
      </details>
      <p class="small muted">Storage, bridges and pools outside the endpoint's allowed lists are refused again when the plan runs.</p>
    </div>

    <!-- options -->
    <div v-show="wz.current.value.id === 'options'" class="wz-card">
      <h2>Backups and extras</h2>
      <p class="muted">Backups follow the profile's schedule. You can usually leave everything here as it is.</p>
      <details class="wz-help"><summary>Customize backups</summary>
      <div class="wz-grid mt">
        <Field label="Backup retention (days)" optional :error="err('retentionDays')" hint="Empty = profile default." v-slot="{ id, invalid }"><input :id="id" v-model="m.retentionDays" type="text" inputmode="numeric" :aria-invalid="invalid" /></Field>
      </div>
      </details>
      <h3>Optional components</h3>
      <p v-if="components?.state === 'unavailable'"><Unavailable what="The component catalog" endpoint="GET /api/v1/catalog/components" :status="components.status" /></p>
      <p v-else-if="!m.optionalAvailable.length" class="muted">This profile has no optional components.</p>
      <label v-for="c in m.optionalAvailable" :key="c" class="wz-choice"><input v-model="m.optional" type="checkbox" :value="c" /> <span><b>{{ label(c) }}</b><span v-if="describe(c)" class="muted"> &mdash; {{ describe(c) }}</span></span></label>
      <label v-if="m.optional.includes('chat')" class="wz-choice"><input v-model="m.federation" type="checkbox" /> <span><b>Chat federation</b><span class="muted"> &mdash; let people on other Matrix servers talk to your users (opens port 8448). Off by default.</span></span></label>
    </div>

    <!-- plan -->
    <div v-show="wz.current.value.id === 'plan'">
      <template v-if="created">
        <Banner kind="ok" title="Sent for approval">Request <span class="mono">{{ created.plan_id }}</span> is {{ created.status.replace('_', ' ') }} (risk {{ created.risk }}, {{ created.approvals_required }} approval(s) needed). <a :href="'#/plans/' + created.plan_id">Open the approval</a>: another approver must approve it before anything is created.</Banner>
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
          <button type="button" class="wz-btn primary" :disabled="!canSubmit || submitting" @click="submit">{{ submitting ? 'Submitting…' : 'Submit for approval' }}</button></div>
      </template>
    </div>
  </WizardShell>
</template>
