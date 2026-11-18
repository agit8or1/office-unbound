<script setup lang="ts">
// New deployment: 5-step wizard on the sizing engine (docs/status/sizing-api.md). Every size call is a dry run; the only mutation is
// deployment.create through POST /plans, which waits for an explicit approval (RunPanel / useRun).
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { api, load, mapPlan } from '../api'
import type { DeploymentPlan, Endpoint, Loaded } from '../api'
import { Banner, Field, Unavailable, WizardShell, fmtGb, fmtMem, useWizard } from '../kit'
import PlanReview from './PlanReview.vue'
import SizeSummary from './SizeSummary.vue'
import SizeReview from './SizeReview.vue'
import RunPanel from '../../views/providers/RunPanel.vue'
import '../../views/providers/providers.css'
import { useRun } from '../../views/providers/run'
import {
  DEPLOYMENT_TYPES, KNOWN_SERVICES, SERVICE_INFO, applyType, architectureCards, backupMessages, buildSizeRequest, createParams, createSizer, identityValid,
  newModel, nodeRows, recommendationText, requestKey, serviceLabel, sizable, sizingApi, summarize, wizardSteps, type Arch, type SizeResponse,
} from './sizing'

const m = reactive(newModel())
const resp = ref<SizeResponse | null>(null)
const respKey = ref('')
const sizeError = ref('')
const sizing = ref(false)
const steps = wizardSteps(() => resp.value)
const wz = useWizard(steps, m)
const err = (k: string) => wz.m.errors[k]
const stepId = computed(() => wz.current.value.id)

const endpoints = ref<Loaded<Endpoint[]> | null>(null)
const usable = (e: Endpoint) => e.credentials.provision.present && e.enabled !== false && e.scope.allowed_pools.length > 0
onMounted(async () => {
  endpoints.value = await load(() => api.endpoints())
  if (endpoints.value.state === 'ok' && !m.endpoint) { const u = endpoints.value.data.find(usable); if (u) m.endpoint = u.name }
})
const endpoint = computed(() => (endpoints.value?.state === 'ok' ? endpoints.value.data.find((e) => e.name === m.endpoint) : undefined))
watch(() => m.endpoint, () => { m.allowedNodes = []; m.storage = ''; m.bridge = ''; m.vlan = ''; m.pool = ''; m.backupDestination = '' })

// ---- live sizing (debounced dry runs)
// the service catalog comes from the API; remembered across failed calls so the request does not flap
const catalog = ref<string[] | null>(null)
watch(resp, (r) => { if (r?.service_catalog?.length) catalog.value = r.service_catalog.map((s) => s.id) })
const serviceIds = computed(() => catalog.value ?? KNOWN_SERVICES)
const request = computed(() => buildSizeRequest(m, catalog.value, true))
const key = computed(() => (sizable(m) ? requestKey(request.value) : ''))
const sizer = createSizer((r, e, k) => { sizing.value = false; resp.value = r; sizeError.value = e; respKey.value = k })
watch(key, (k) => { if (k) { sizing.value = true; sizer.schedule(request.value) } }, { immediate: true })
async function regenerate() { if (!key.value) return; sizing.value = true; await sizer.regenerate(request.value) }
const fresh = computed(() => !!resp.value && respKey.value === key.value)

const summary = computed(() => summarize(resp.value))
const recText = computed(() => recommendationText(resp.value))
const archCards = computed(() => architectureCards(resp.value))
const nodes = computed(() => nodeRows(resp.value))
const approvedNodes = computed(() => { const s = endpoint.value?.scope.allowed_nodes ?? []; return s.length ? s : nodes.value.map((n) => n.name) })
const backupMsgs = computed(() => backupMessages(resp.value))
const summaryHint = computed(() => (!m.endpoint ? 'Choose a cluster (step 3) to see an estimate.' : !m.services.length ? 'Choose at least one service.' : 'Enter valid numbers to see an estimate.'))

function pickArch(id: Arch, available: boolean) { if (available) m.architecture = id }
function toggleNode(n: string, on: boolean) {
  const cur = m.allowedNodes.length ? m.allowedNodes : [...approvedNodes.value]
  const next = on ? [...new Set([...cur, n])] : cur.filter((x) => x !== n)
  m.allowedNodes = next.length === approvedNodes.value.length ? [] : next
}
const nodeOn = (n: string) => !m.allowedNodes.length || m.allowedNodes.includes(n)

// ---- plan + submit (deployment.create through the normal approval flow)
const generated = ref<DeploymentPlan | null>(null)
const generatedKey = ref('')
const planning = ref(false)
const planError = ref('')
const confirmed = ref(false)
const run = useRun()
watch(key, () => { confirmed.value = false })
watch(stepId, (id) => { if (id === 'review') void regenerate() })
const canPlan = computed(() => fresh.value && identityValid(m) && !!resp.value?.selected && !!resp.value.plan_input && !(resp.value.plan_blocking ?? []).length && resp.value.fits === true)
async function createPlan() {
  if (!canPlan.value || !resp.value?.plan_input) return
  planError.value = ''; planning.value = true; confirmed.value = false
  const k = key.value
  try { generated.value = mapPlan(await sizingApi.plan(resp.value.plan_input)); generatedKey.value = k }
  catch (e) { generated.value = null; planError.value = e instanceof Error ? e.message : String(e) }
  finally { planning.value = false }
}
const planCurrent = computed(() => !!generated.value && generatedKey.value === key.value)
const canSubmit = computed(() => planCurrent.value && confirmed.value && !!generated.value && !generated.value.errors.length && !run.busy.value && !run.created.value)
function submit() {
  if (!canSubmit.value || !resp.value?.plan_input || !generated.value) return
  void run.start('deployment.create', createParams(resp.value.plan_input, generated.value.plan_hash))
}
</script>

<template>
  <WizardShell
    title="New deployment" subtitle="Describe what you need; Office Unbound sizes it against your approved infrastructure. Nothing is created until you approve the plan."
    :steps="steps" :index="wz.m.index" :reached="wz.m.reached" :hide-next="stepId === 'review'" :busy="planning"
    @next="wz.next()" @back="wz.back()" @goto="wz.goto($event)"
  >
    <div class="dw-layout">
      <div class="dw-main">
        <!-- 1 type -->
        <div v-show="stepId === 'type'">
          <div class="wz-card">
            <h2>What kind of deployment is this?</h2>
            <p v-if="err('type')" class="dw-bad" role="alert">{{ err('type') }}</p>
            <div class="wz-cards" role="group" aria-label="Deployment type">
              <button v-for="t in DEPLOYMENT_TYPES" :key="t.id" type="button" class="wz-pick" :aria-pressed="m.type === t.id" @click="applyType(m, t.id)">
                <b>{{ t.title }}</b><span class="muted">{{ t.blurb }}</span>
              </button>
            </div>
          </div>
          <div class="wz-card">
            <h2>Who is it for?</h2>
            <div class="wz-grid">
              <Field label="Customer" :error="err('customerId')" hint="Short identifier, for example acme." v-slot="{ id, invalid, describedBy }"><input :id="id" v-model.trim="m.customerId" type="text" autocomplete="off" :aria-invalid="invalid" :aria-describedby="describedBy" /></Field>
              <Field label="Environment name" :error="err('name')" hint="Used in VM names; cannot be changed later." v-slot="{ id, invalid, describedBy }"><input :id="id" v-model.trim="m.name" type="text" autocomplete="off" :aria-invalid="invalid" :aria-describedby="describedBy" /></Field>
              <Field label="Customer domain" :error="err('domain')" hint="Used for service addresses and DNS records." v-slot="{ id, invalid, describedBy }"><input :id="id" v-model.trim="m.domain" type="text" placeholder="your-company.tld" autocomplete="off" :aria-invalid="invalid" :aria-describedby="describedBy" /></Field>
            </div>
          </div>
        </div>

        <!-- 2 workload -->
        <div v-show="stepId === 'workload'">
          <div class="wz-card">
            <h2>How many people, and how busy?</h2>
            <div class="wz-grid">
              <Field :label="m.type === 'msp' ? 'Users per customer' : 'Total users'" :error="err('users')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.users" type="number" min="1" :aria-invalid="invalid" /></Field>
              <Field v-if="m.type === 'msp'" label="Customers" :error="err('tenants')" hint="Each customer is kept separate." v-slot="{ id, invalid }"><input :id="id" v-model.number="m.tenants" type="number" min="1" max="50" :aria-invalid="invalid" /></Field>
              <Field label="Active at the same time" optional :error="err('concurrentUsers')" :hint="`Empty = ${m.concurrentPct}% of users.`" v-slot="{ id, invalid }"><input :id="id" v-model="m.concurrentUsers" type="number" min="0" :placeholder="String(Math.round(m.users * m.concurrentPct / 100))" :aria-invalid="invalid" /></Field>
              <Field label="Mailbox size per user (GB)" :error="err('mailboxGb')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.mailboxGb" type="number" min="0" step="0.5" :aria-invalid="invalid" /></Field>
              <Field label="File storage per user (GB)" :error="err('fileGb')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.fileGb" type="number" min="0" step="0.5" :aria-invalid="invalid" /></Field>
              <Field label="Expected growth (%)" :error="err('growthPct')" hint="Sized for today plus this growth." v-slot="{ id, invalid }"><input :id="id" v-model.number="m.growthPct" type="number" min="0" max="500" :aria-invalid="invalid" /></Field>
            </div>
          </div>
          <div class="wz-card">
            <h2>Services</h2>
            <p v-if="err('services')" class="dw-bad" role="alert">{{ err('services') }}</p>
            <fieldset class="dw-fs"><legend class="dw-sr">Services to deploy</legend>
              <div class="dw-services">
                <label v-for="s in serviceIds" :key="s" class="wz-choice"><input v-model="m.services" type="checkbox" :value="s" /> <span><b>{{ serviceLabel(s) }}</b><span v-if="SERVICE_INFO[s]" class="muted small"> &mdash; {{ SERVICE_INFO[s].blurb }}</span></span></label>
              </div>
            </fieldset>
            <p class="small muted">Sign-in (identity) and the secure entry point are always included. Services another service needs are added automatically.</p>
          </div>
          <details class="wz-help">
            <summary>Advanced parameters</summary>
            <div class="wz-grid mt">
              <Field label="Active users if not given (% of users)" :error="err('concurrentPct')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.concurrentPct" type="number" min="1" max="100" :aria-invalid="invalid" /></Field>
              <Field label="Editing documents (% of active)" :error="err('officeEditorPct')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.officeEditorPct" type="number" min="0" max="100" :aria-invalid="invalid" /></Field>
              <Field label="In meetings (% of active)" :error="err('meetingPct')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.meetingPct" type="number" min="0" max="100" :aria-invalid="invalid" /></Field>
              <Field label="On calls (% of active)" :error="err('callPct')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.callPct" type="number" min="0" max="100" :aria-invalid="invalid" /></Field>
              <Field label="Safety margin on estimates (%)" optional :error="err('marginPct')" hint="Empty = catalog default." v-slot="{ id, invalid }"><input :id="id" v-model="m.marginPct" type="number" min="0" max="200" :aria-invalid="invalid" /></Field>
              <Field label="Minimum sizes" hint="Default depends on the deployment type." v-slot="{ id }"><select :id="id" v-model="m.tier"><option value="">Default</option><option value="minimum">Minimum (smallest that runs)</option><option value="recommended">Recommended</option></select></Field>
            </div>
          </details>
        </div>

        <!-- 3 placement -->
        <div v-show="stepId === 'placement'">
          <div class="wz-card">
            <h2>Where should it run?</h2>
            <Unavailable v-if="endpoints?.state === 'unavailable'" what="Clusters" endpoint="GET /api/v1/endpoints" :status="endpoints.status" />
            <Banner v-else-if="endpoints?.state === 'error'" kind="bad">{{ endpoints.message }}</Banner>
            <Banner v-else-if="endpoints?.state === 'ok' && !endpoints.data.some(usable)" kind="warn" title="No cluster can deploy yet">Connect a cluster and grant it the Deployment access level first. <router-link to="/infrastructure/providers/proxmox/connect">Connect Proxmox</router-link></Banner>
            <div class="wz-grid">
              <Field label="Cluster" :error="err('endpoint')" v-slot="{ id, invalid }">
                <select :id="id" v-model="m.endpoint" :aria-invalid="invalid"><option value="">Select…</option>
                  <option v-for="e in endpoints?.state === 'ok' ? endpoints.data : []" :key="e.id" :value="e.name" :disabled="!usable(e)">{{ e.display_name || e.name }}{{ usable(e) ? '' : ' (cannot deploy: no deployment access)' }}</option></select>
              </Field>
            </div>
            <template v-if="nodes.length">
              <h3>Approved nodes</h3>
              <fieldset class="dw-fs"><legend class="dw-sr">Nodes this deployment may use</legend>
                <div class="wz-table-wrap"><table>
                  <thead><tr><th>Use</th><th>Node</th><th class="num">Free vCPU</th><th class="num">Free memory</th><th class="num">VMs placed</th></tr></thead>
                  <tbody><tr v-for="n in approvedNodes" :key="n">
                    <td><input type="checkbox" :checked="nodeOn(n)" :aria-label="`Use node ${n}`" @change="toggleNode(n, ($event.target as HTMLInputElement).checked)" /></td>
                    <td class="mono">{{ n }}</td>
                    <td class="num">{{ nodes.find((x) => x.name === n)?.vcpu ?? '-' }}</td>
                    <td class="num">{{ nodes.find((x) => x.name === n) ? fmtMem(nodes.find((x) => x.name === n)!.memoryMb) : '-' }}</td>
                    <td class="num">{{ nodes.find((x) => x.name === n)?.vmsHere ?? 0 }}</td>
                  </tr></tbody>
                </table></div>
              </fieldset>
              <p v-if="summary.available" class="small muted">Available in total: {{ summary.available.vcpu }} vCPU, {{ fmtMem(summary.available.memoryMb) }} memory, {{ fmtGb(summary.available.storageGb) }} storage.</p>
              <ul v-if="resp?.capacity?.storage?.length" class="dw-list small"><li v-for="st in resp.capacity.storage" :key="st.key ?? st.name"><b>{{ st.name }}</b>: {{ fmtGb(st.available_gb) }} free{{ st.shared ? ', shared' : ', local to ' + (st.nodes ?? []).join(', ') }}</li></ul>
            </template>
          </div>
          <div class="wz-card">
            <h2>Architecture</h2>
            <p class="muted">How the services are spread over virtual machines. Options this cluster cannot support are shown with the reason.</p>
            <p v-if="err('architecture')" class="dw-bad" role="alert">{{ err('architecture') }}</p>
            <div class="wz-cards" role="group" aria-label="Architecture">
              <button v-for="a in archCards" :key="a.id" type="button" class="wz-pick dw-arch" :aria-pressed="m.architecture ? m.architecture === a.id : a.recommended" :disabled="!a.available" :aria-disabled="!a.available" @click="pickArch(a.id, a.available)">
                <b>{{ a.title }} <span v-if="a.recommended" class="wz-chip ok">Recommended</span></b>
                <span class="muted">{{ a.blurb }}</span>
                <span v-if="a.available && a.vms !== null" class="small">{{ a.vms }} VM{{ a.vms === 1 ? '' : 's' }}</span>
                <span v-if="a.fitNote" class="small dw-bad">{{ a.fitNote }}</span>
                <span v-if="!a.available" class="small dw-why">Not available: {{ a.whyNot }}</span>
              </button>
            </div>
            <p class="small mt"><button v-if="m.architecture" type="button" class="wz-btn" @click="m.architecture = null">Use the recommendation</button></p>
          </div>
          <details v-if="endpoint" class="wz-help">
            <summary>Storage and network (optional)</summary>
            <div class="wz-grid mt">
              <Field label="VM disk storage" hint="Default: the approved storage with the most free space." v-slot="{ id }"><select :id="id" v-model="m.storage"><option value="">Automatic</option><option v-for="s in endpoint.scope.allowed_storage" :key="s" :value="s">{{ s }}</option></select></Field>
              <Field label="Network bridge" v-slot="{ id }"><select :id="id" v-model="m.bridge"><option value="">Automatic</option><option v-for="b in [...new Set(endpoint.scope.allowed_networks.map((x) => x.split('/')[0]))]" :key="b" :value="b">{{ b }}</option></select></Field>
              <Field label="VLAN tag" optional :error="err('vlan')" v-slot="{ id, invalid }"><input :id="id" v-model="m.vlan" type="text" inputmode="numeric" :aria-invalid="invalid" /></Field>
              <Field label="Resource pool" v-slot="{ id }"><select :id="id" v-model="m.pool"><option value="">Automatic</option><option v-for="p in endpoint.scope.allowed_pools" :key="p" :value="p">{{ p }}</option></select></Field>
            </div>
          </details>
        </div>

        <!-- 4 backup -->
        <div v-show="stepId === 'backup'">
          <div class="wz-card">
            <h2>Backups</h2>
            <div class="wz-grid">
              <Field label="Backup destination" hint="Backup-capable storage on this cluster." v-slot="{ id }">
                <select :id="id" v-model="m.backupDestination"><option value="">Automatic</option><option v-for="d in resp?.backup_destinations ?? []" :key="d.name" :value="d.name">{{ d.name }} ({{ fmtGb(d.avail_gb) }} free)</option></select>
              </Field>
              <Field label="Keep backups for (days)" :error="err('retentionDays')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.retentionDays" type="number" min="1" max="3650" :aria-invalid="invalid" /></Field>
              <Field label="Most data you can afford to lose (hours)" :error="err('rpoHours')" hint="Recovery point objective." v-slot="{ id, invalid }"><input :id="id" v-model.number="m.rpoHours" type="number" min="1" max="720" :aria-invalid="invalid" /></Field>
              <Field label="Back online within (hours)" optional :error="err('rtoHours')" hint="Recovery time objective; not verified automatically." v-slot="{ id, invalid }"><input :id="id" v-model="m.rtoHours" type="number" min="1" max="720" :aria-invalid="invalid" /></Field>
            </div>
            <label class="wz-choice mt"><input v-model="m.offsite" type="checkbox" /> <span>I need an off-site copy</span></label>
            <p v-if="resp?.backup?.estimated_backup_gb" class="small muted">About {{ fmtGb(resp.backup.estimated_backup_gb) }} of backup space needed <span class="wz-chip warn">estimate</span></p>
            <Banner v-for="(b, i) in backupMsgs" :key="i" :kind="b.kind">{{ b.text }}</Banner>
          </div>
          <div class="wz-card">
            <h2>Updates</h2>
            <fieldset class="dw-fs"><legend class="dw-sr">Update preference</legend>
              <label class="wz-choice"><input v-model="m.updatesMode" type="radio" value="manual" /> <span>Manual: I start every update myself</span></label>
              <label class="wz-choice"><input v-model="m.updatesMode" type="radio" value="maintenance_window" /> <span>In a maintenance window</span></label>
            </fieldset>
            <Field v-if="m.updatesMode === 'maintenance_window'" label="Window" :error="err('updatesWindow')" hint='For example "sun 02:00-04:00".' v-slot="{ id, invalid }"><input :id="id" v-model="m.updatesWindow" type="text" :aria-invalid="invalid" /></Field>
            <p class="small muted">{{ resp?.updates?.note ?? 'Updates always run as approved changes; nothing is applied automatically.' }}</p>
          </div>
          <Banner v-for="(e, i) in resp?.errors ?? []" :key="i" :kind="e.severity === 'error' ? 'bad' : 'warn'">{{ e.message }}</Banner>
        </div>

        <!-- 5 review -->
        <div v-show="stepId === 'review'">
          <p v-if="sizing && !resp" class="muted" role="status">Calculating…</p>
          <Banner v-if="sizeError" kind="bad" title="Could not size this deployment">{{ sizeError }}</Banner>
          <Banner v-if="resp && !fresh && !sizing" kind="warn" title="Inputs changed">The plan below is out of date. <button type="button" class="wz-btn" @click="regenerate">Regenerate</button></Banner>
          <SizeReview v-if="resp" :r="resp" :m="m" :busy="sizing" @regenerate="regenerate" />

          <div v-if="resp" class="wz-card">
            <h2>Create the deployment plan</h2>
            <p class="small">This computes the final plan and its fingerprint. It still creates nothing; you approve it in the next step.</p>
            <Banner v-if="planError" kind="bad" title="Could not create the plan">{{ planError }}</Banner>
            <div class="wz-row">
              <button type="button" class="wz-btn primary" :disabled="!canPlan || planning || !!run.created.value" @click="createPlan">{{ planning ? 'Creating plan…' : 'Create deployment plan' }}</button>
              <span v-if="!canPlan && fresh" class="small muted">{{ resp.fits === false ? 'The layout does not fit the approved capacity.' : (resp.plan_blocking ?? []).length ? 'Resolve the blocking issues above first.' : '' }}</span>
            </div>
            <template v-if="generated">
              <Banner v-if="!planCurrent" kind="warn" title="Inputs changed">Create the plan again to review the current inputs.</Banner>
              <p class="small">Plan fingerprint <span class="mono">{{ generated.plan_hash.slice(0, 16) }}</span><span v-if="generated.plan_hash === resp.plan_hash" class="wz-chip ok">matches the sizing result</span><span v-else class="wz-chip warn">differs from the sizing result: inventory changed</span>. {{ generated.vms.length }} VMs.</p>
              <Banner v-for="(e, i) in generated.errors" :key="i" kind="bad" title="Blocking error">{{ e.message }}</Banner>
              <details class="wz-help"><summary>Full plan details (firewall, DNS, steps)</summary><PlanReview :plan="generated" /></details>
              <label class="wz-choice mt"><input v-model="confirmed" type="checkbox" :disabled="!planCurrent || !!generated.errors.length || !!run.created.value" /> <span>I reviewed this plan, including risks and capacity, and want to submit it for approval.</span></label>
              <div class="wz-row mt"><button type="button" class="wz-btn primary" :disabled="!canSubmit" @click="submit">Submit for approval</button></div>
              <RunPanel v-if="run.created.value || run.error.value" :run="run" what="New deployment" />
            </template>
          </div>
        </div>
      </div>
      <SizeSummary :summary="summary" :recommendation="recText" :busy="sizing" :error="stepId === 'review' ? '' : sizeError" :hint="summaryHint" />
    </div>
  </WizardShell>
</template>

<style>
.dw-layout { display: grid; grid-template-columns: minmax(0, 1fr) 260px; gap: 16px; align-items: start; }
.dw-main { min-width: 0; }
.dw-summary { position: sticky; top: 12px; }
@media (max-width: 900px) { .dw-layout { grid-template-columns: minmax(0, 1fr); } .dw-summary { position: static; } }
.dw-stats { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 8px 0; }
.dw-stats div { border: 1px solid var(--line); border-radius: var(--radius); padding: 6px 8px; }
.dw-stats dt { color: var(--muted); font-size: 11px; } .dw-stats dd { margin: 0; font-size: 16px; font-weight: 600; }
.dw-head, .dw-list { margin: 4px 0; padding-left: 18px; }
.dw-bad { color: var(--bad); } .dw-ok { color: var(--ok); } .dw-why { color: var(--warn); }
.dw-rec { color: var(--accent); font-weight: 600; } .dw-rec-big { color: var(--accent); font-size: 15px; font-weight: 600; margin: 0 0 4px; }
.dw-services { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 240px), 1fr)); gap: 6px 16px; }
.dw-fs { border: 0; margin: 0; padding: 0; min-width: 0; }
.dw-sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.wz-pick.dw-arch:disabled { cursor: not-allowed; opacity: .75; border-style: dashed; }
.dw-num { width: 7em; max-width: 100%; }
.wz .mt { margin-top: 10px; }
</style>
