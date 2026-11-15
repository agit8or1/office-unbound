<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { api, load } from '../api'
import type { Loaded, PlanCreated, SetupState } from '../api'
import { Banner, CapacityBar, Field, HelpNote, Unavailable, WizardShell, fmtGb, useWizard } from '../kit'
import ConnectionStep from './ConnectionStep.vue'
import {
  OS_IMAGES, POLICIES, assertSubmittable, buildRegisterParams, connectionKey, discovery, hasProvision, isReady, newSetupModel, readiness, setupSteps, storageFor,
} from './state'

const m = reactive(newSetupModel())
const wz = useWizard(setupSteps, m)
const setupState = ref<Loaded<SetupState> | null>(null)
const submitting = ref(false)
const submitError = ref('')
const created = ref<PlanCreated | null>(null)
const fieldErr = (k: string) => wz.m.errors[k]

onMounted(async () => { setupState.value = await load(() => api.setupState()) })

// any change to connection details invalidates the probe (and everything derived from it)
watch(() => connectionKey(m), () => { if (m.probe && m.probedKey !== connectionKey(m)) { wz.truncateReached(0) } })
watch(() => m.defaults, () => { m.confirmed = false }, { deep: true })

const checks = computed(() => readiness(m))
const disc = computed(() => discovery(m))
const params = computed(() => buildRegisterParams(m))
const masked = computed(() => JSON.stringify({
  ...params.value, token_secret: '•••••••• (entered, never shown again)', ...(params.value.provision_token_secret ? { provision_token_secret: '••••••••' } : {}),
}, null, 2))
const onReview = computed(() => wz.current.value.id === 'review')
const canSubmit = computed(() => { try { assertSubmittable(m, onReview.value); return true } catch { return false } })
const managedNodes = computed(() => (disc.value?.nodes ?? []).filter((n) => n.managed !== false))
const unmanaged = computed(() => (disc.value?.nodes ?? []).filter((n) => n.managed === false))
const bridges = computed(() => [...new Set((disc.value?.networks ?? []).filter((n) => n.kind === 'bridge').map((n) => n.name))])

async function submit() {
  submitError.value = ''
  try { assertSubmittable(m, onReview.value) } catch (e) { submitError.value = (e as Error).message; return }
  submitting.value = true
  try {
    created.value = await api.submitPlan('endpoint.register', buildRegisterParams(m))
    m.tokenSecret = ''; m.provTokenSecret = ''; m.probe = null; m.probedKey = null; m.tlsCheck = null // secrets leave the browser state once submitted
  } catch (e) { submitError.value = e instanceof Error ? e.message : String(e) } finally { submitting.value = false }
}
const nodeCores = (n: { cpu_total: number | null; cpu_used: number | null }) => ({ total: n.cpu_total ?? 0, used: n.cpu_used ?? 0 })
function skip() { try { sessionStorage.setItem('ics-setup-skipped', '1') } catch { /* storage may be blocked */ } }
</script>

<template>
  <WizardShell
    title="Connect your infrastructure" subtitle="Four short steps: connect your Proxmox cluster, check what we found, confirm the settings, and send it for approval. Nothing changes until it is approved."
    :steps="setupSteps" :index="wz.m.index" :reached="wz.m.reached" :hide-nav="onReview" :hide-next="onReview" :busy="submitting"
    @next="wz.next()" @back="wz.back()" @goto="wz.goto($event)"
  >
    <Banner v-if="setupState?.state === 'ok' && setupState.data.has_endpoint" kind="info" title="A cluster is already connected">You can connect another one here; existing connections are not changed.</Banner>
    <Unavailable v-if="setupState?.state === 'unavailable'" what="Setup status" endpoint="GET /api/v1/setup/state" :status="setupState.status" />
    <p class="small muted"><a href="#/overview" @click="skip">Skip for now</a>: you can come back from the Overview at any time.</p>

    <!-- 1 connection -->
    <div v-show="wz.current.value.id === 'connection'"><ConnectionStep :m="m" :errors="wz.m.errors" @errors="wz.m.errors = $event" /></div>

    <!-- 2 discovery -->
    <div v-show="wz.current.value.id === 'discovery'">
      <div class="wz-card">
        <h2>What we found</h2>
        <Banner v-if="!disc" kind="warn" title="Nothing to show">Run a connection test first.</Banner>
        <template v-else>
          <p>Connected. We found <b>{{ disc.nodes.length }}</b> server(s), <b>{{ disc.storage.length }}</b> storage location(s), <b>{{ disc.guests.filter((g) => !g.template).length }}</b> existing machine(s) and <b>{{ disc.guests.filter((g) => g.template).length }}</b> template(s). Existing machines are never touched: ICS only manages machines it creates itself.</p>
          <Banner v-for="w in disc.warnings ?? []" :key="w" kind="warn">{{ w }}</Banner>
          <Banner v-if="unmanaged.length" kind="warn" title="Some servers are not visible to this token">{{ unmanaged.map((n) => n.name).join(', ') }}: their capacity is unknown and is not counted.</Banner>
          <details class="wz-help"><summary>Show details</summary>
            <h3>Servers and capacity</h3>
            <div v-for="n in managedNodes" :key="n.name">
              <CapacityBar :label="`${n.name} CPU (${n.status})`" :total="nodeCores(n).total" :used="nodeCores(n).used" unit="cores" />
              <CapacityBar :label="`${n.name} memory`" :total="n.mem_total_gb ?? 0" :used="n.mem_used_gb ?? 0" unit="GiB" />
            </div>
            <h3>Storage</h3>
            <div class="wz-table-wrap"><table>
              <thead><tr><th>Storage</th><th>Server</th><th>Type</th><th>Holds</th><th class="num">Free</th><th class="num">Total</th></tr></thead>
              <tbody><tr v-for="s in disc.storage" :key="s.id + s.node"><td class="mono">{{ s.id }}</td><td>{{ s.node ?? 'shared' }}</td><td>{{ s.type }}</td><td>{{ s.content.join(', ') }}</td><td class="num">{{ fmtGb(s.total_gb - s.used_gb) }}</td><td class="num">{{ fmtGb(s.total_gb) }}</td></tr></tbody>
            </table></div>
            <h3>Networks</h3>
            <div class="wz-table-wrap"><table>
              <thead><tr><th>Name</th><th>Server</th><th>Kind</th></tr></thead>
              <tbody><tr v-for="n in disc.networks" :key="n.name + n.node"><td class="mono">{{ n.name }}</td><td>{{ n.node ?? 'cluster' }}</td><td>{{ n.kind }}</td></tr></tbody>
            </table></div>
            <h3>Existing machines</h3>
            <div class="wz-table-wrap"><table>
              <thead><tr><th>ID</th><th>Name</th><th>Kind</th><th>Server</th><th>Status</th></tr></thead>
              <tbody>
                <tr v-for="g in disc.guests" :key="g.vmid"><td class="mono">{{ g.vmid }}</td><td>{{ g.name }}<span v-if="g.template" class="wz-chip info"> template</span></td><td>{{ g.kind }}</td><td>{{ g.node }}</td><td>{{ g.status }}</td></tr>
                <tr v-if="!disc.guests.length"><td colspan="5" class="muted">No machines found.</td></tr>
              </tbody>
            </table></div>
          </details>
        </template>
      </div>
    </div>

    <!-- 3 settings -->
    <div v-show="wz.current.value.id === 'defaults'">
      <div class="wz-card">
        <h2>Settings for new environments</h2>
        <Banner v-if="!hasProvision(m)" kind="info" title="Read-only connection">You did not add a provisioning token, so ICS will monitor this cluster but not create machines. You can add one later.</Banner>
        <template v-else>
          <p class="muted">We filled in what the cluster made obvious. Check the summary, change anything under <b>Customize</b>.</p>
          <dl class="wz-dl">
            <dt>Machines may be created on</dt><dd>{{ m.defaults.nodes.join(', ') || 'choose below' }}</dd>
            <dt>Disks are stored on</dt><dd>{{ m.defaults.storage || 'choose below' }}</dd>
            <dt>Network</dt><dd>{{ m.defaults.bridge || 'choose below' }}{{ m.defaults.vlan ? ' (VLAN ' + m.defaults.vlan + ')' : '' }}, addresses by DHCP</dd>
            <dt>Resource pool</dt><dd>{{ m.defaults.pool || 'choose below' }}</dd>
          </dl>
        </template>
        <details class="wz-help" :open="Object.keys(wz.m.errors).length > 0">
          <summary>Customize</summary>
          <div class="wz-grid">
            <Field v-if="hasProvision(m)" label="Resource pool" :error="fieldErr('pool')" hint="All machines ICS creates live here. It must be the pool the provisioning token can use." v-slot="{ id, invalid }">
              <select v-if="disc?.pools?.length" :id="id" v-model="m.defaults.pool" :aria-invalid="invalid"><option value="">Select…</option><option v-for="p in disc.pools" :key="p" :value="p">{{ p }}</option></select>
              <input v-else :id="id" v-model.trim="m.defaults.pool" type="text" :aria-invalid="invalid" />
            </Field>
            <fieldset v-if="hasProvision(m)" class="wz-fieldset"><legend>Servers ICS may use</legend>
              <p v-if="fieldErr('nodes')" class="bad-text" role="alert">{{ fieldErr('nodes') }}</p>
              <label v-for="n in managedNodes" :key="n.name" class="wz-choice"><input v-model="m.defaults.nodes" type="checkbox" :value="n.name" /> {{ n.name }} ({{ n.status }})</label>
              <p class="small muted">ICS never creates, changes or moves machines on a server that is not ticked here.</p>
            </fieldset>
            <Field v-if="hasProvision(m)" label="Disk storage" :error="fieldErr('storage')" v-slot="{ id, invalid }">
              <select :id="id" v-model="m.defaults.storage" :aria-invalid="invalid"><option value="">Select…</option><option v-for="s in storageFor(m, 'images')" :key="s.id + s.node" :value="s.id">{{ s.id }} ({{ fmtGb(s.total_gb - s.used_gb) }} free)</option></select>
            </Field>
            <Field v-if="hasProvision(m)" label="Network" :error="fieldErr('bridge')" v-slot="{ id, invalid }">
              <select :id="id" v-model="m.defaults.bridge" :aria-invalid="invalid"><option value="">Select…</option><option v-for="b in bridges" :key="b" :value="b">{{ b }}</option></select>
            </Field>
            <Field label="VLAN tag" :error="fieldErr('vlan')" optional hint="Empty = untagged." v-slot="{ id, invalid }"><input :id="id" v-model="m.defaults.vlan" type="text" inputmode="numeric" :aria-invalid="invalid" /></Field>
            <Field label="Search domain" optional :error="fieldErr('searchDomain')" v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.defaults.searchDomain" type="text" placeholder="your-company.tld" :aria-invalid="invalid" /></Field>
            <Field label="DNS servers" optional :error="fieldErr('dnsServers')" hint="Comma-separated." v-slot="{ id, invalid }"><input :id="id" v-model="m.defaults.dnsServers" type="text" :aria-invalid="invalid" /></Field>
            <Field label="Backup storage" optional hint="Storage that accepts backups." v-slot="{ id }">
              <select :id="id" v-model="m.defaults.backupStorage"><option value="">None (set per deployment)</option><option v-for="s in storageFor(m, 'backup')" :key="s.id + s.node" :value="s.id">{{ s.id }} ({{ fmtGb(s.total_gb - s.used_gb) }} free)</option></select>
            </Field>
            <Field label="How tightly to pack machines" v-slot="{ id }"><select :id="id" v-model="m.defaults.resourcePolicy"><option v-for="p in POLICIES" :key="p.id" :value="p.id">{{ p.label }}</option></select></Field>
          </div>
          <h3>Approved operating system images</h3>
          <p v-if="fieldErr('images')" class="bad-text" role="alert">{{ fieldErr('images') }}</p>
          <label v-for="o in OS_IMAGES" :key="o.id" class="wz-choice"><input v-model="m.defaults.images" type="checkbox" :value="o.id" /> {{ o.label }}</label>
          <p class="small muted">Only images from the approved catalog can be used; arbitrary images are not accepted.</p>
        </details>
      </div>
    </div>

    <!-- 4 review -->
    <div v-show="wz.current.value.id === 'review'">
      <div v-if="created" class="wz-card">
        <Banner kind="ok" title="Sent for approval">Request <span class="mono">{{ created.plan_id }}</span> is {{ created.status.replace('_', ' ') }} (risk {{ created.risk }}, {{ created.approvals_required }} approval(s) needed). Nothing is stored or contacted until it is approved.</Banner>
        <p><a :href="'#/plans/' + created.plan_id" class="wz-btn primary">Open the approval</a> <span class="muted small">You cannot approve your own request: another approver must.</span></p>
      </div>
      <template v-else>
        <div class="wz-card">
          <h2>Review</h2>
          <ul class="wz-checks"><li v-for="c in checks" :key="c.id"><span><span class="wz-chip" :class="c.level">{{ c.level === 'ok' ? 'Ready' : c.level === 'warn' ? 'Note' : c.blocks ? 'Blocks deploying' : 'Blocked' }}</span></span><span>{{ c.text }}</span></li></ul>
          <dl class="wz-dl">
            <dt>Cluster</dt><dd>{{ m.name }} &middot; {{ params.base_url }}</dd>
            <dt>Access</dt><dd>{{ hasProvision(m) ? 'read and create machines, in pool ' + (params.allowed_pools as string[]).join(', ') + ' on ' + (params.allowed_nodes as string[]).join(', ') : 'read-only' }}</dd>
          </dl>
          <HelpNote title="Technical details (exact request)"><pre class="mono wz-code">{{ masked }}</pre></HelpNote>
        </div>
        <Banner v-if="submitError" kind="bad" title="Not submitted">{{ submitError }}</Banner>
        <label class="wz-choice"><input v-model="m.confirmed" type="checkbox" :disabled="!isReady(m)" /> I have reviewed this and want to send it for approval.</label>
        <div class="wz-footer"><button type="button" class="wz-btn" @click="wz.back()">Back</button><span class="spacer"></span>
          <button type="button" class="wz-btn primary" :disabled="!canSubmit || submitting" @click="submit">{{ submitting ? 'Submitting…' : 'Submit for approval' }}</button></div>
      </template>
    </div>
  </WizardShell>
</template>
