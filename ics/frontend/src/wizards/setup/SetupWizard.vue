<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { api, load } from '../api'
import type { Loaded, PlanCreated, SetupState } from '../api'
import { Banner, CapacityBar, Field, HelpNote, Unavailable, WizardShell, fmtGb, useWizard } from '../kit'
import ConnectionStep from './ConnectionStep.vue'
import {
  OS_IMAGES, assertSubmittable, buildRegisterParams, connectionKey, discovery, isReady, newSetupModel, readiness, setupSteps, storageFor,
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
watch(() => m.security, () => { m.confirmed = false }, { deep: true })

const checks = computed(() => readiness(m))
const disc = computed(() => discovery(m))
const params = computed(() => buildRegisterParams(m))
const masked = computed(() => JSON.stringify({ ...params.value, token_secret: '•••••••• (entered, never shown again)' }, null, 2))
const onReview = computed(() => wz.current.value.id === 'review')
const canSubmit = computed(() => { try { assertSubmittable(m, onReview.value); return true } catch { return false } })

async function submit() {
  submitError.value = ''
  try { assertSubmittable(m, onReview.value) } catch (e) { submitError.value = (e as Error).message; return }
  submitting.value = true
  try {
    created.value = await api.submitPlan('endpoint.register', buildRegisterParams(m))
    m.tokenSecret = ''; m.probe = null; m.probedKey = null; m.tlsCheck = null // the secret leaves the browser state once submitted
  } catch (e) { submitError.value = e instanceof Error ? e.message : String(e) } finally { submitting.value = false }
}
const nodeCores = (n: { cpu_total: number; cpu_used: number }) => ({ total: n.cpu_total, used: n.cpu_used })
</script>

<template>
  <WizardShell
    title="First-run setup" subtitle="Connect the infrastructure provider, review what was discovered, and set safe defaults. Nothing is changed until you submit the plan at the end."
    :steps="setupSteps" :index="wz.m.index" :reached="wz.m.reached" :hide-nav="onReview" :hide-next="onReview" :busy="submitting"
    @next="wz.next()" @back="wz.back()" @goto="wz.goto($event)"
  >
    <Banner v-if="setupState?.state === 'ok' && setupState.data.has_endpoint" kind="info" title="An endpoint is already registered">You can register another provider endpoint here; existing endpoints are not changed.</Banner>
    <Unavailable v-if="setupState?.state === 'unavailable'" what="Setup status" endpoint="GET /api/v1/setup/state" :status="setupState.status" />

    <!-- 1 connection -->
    <div v-show="wz.current.value.id === 'connection'"><ConnectionStep :m="m" :errors="wz.m.errors" @errors="wz.m.errors = $event" /></div>

    <!-- 2 discovery -->
    <div v-show="wz.current.value.id === 'discovery'">
      <div class="wz-card">
        <h2>What was discovered</h2>
        <Banner v-if="!disc" kind="warn" title="Nothing to show">Run a connection test first.</Banner>
        <template v-else>
          <p class="muted">{{ disc.nodes.length }} node(s), {{ disc.storage.length }} storage, {{ disc.networks.length }} network(s), {{ disc.guests.filter((g) => !g.template).length }} guest(s), {{ disc.guests.filter((g) => g.template).length }} template(s).</p>
          <h3>Nodes and capacity</h3>
          <div v-for="n in disc.nodes" :key="n.name">
            <CapacityBar :label="`${n.name} CPU (${n.status})`" :total="nodeCores(n).total" :used="nodeCores(n).used" unit="cores" />
            <CapacityBar :label="`${n.name} memory`" :total="n.mem_total_gb" :used="n.mem_used_gb" unit="GiB" />
          </div>
          <h3>Storage</h3>
          <div class="wz-table-wrap"><table>
            <thead><tr><th>Storage</th><th>Node</th><th>Type</th><th>Content</th><th class="num">Free</th><th class="num">Total</th></tr></thead>
            <tbody><tr v-for="s in disc.storage" :key="s.id + s.node"><td class="mono">{{ s.id }}</td><td>{{ s.node ?? 'shared' }}</td><td>{{ s.type }}</td><td>{{ s.content.join(', ') }}</td><td class="num">{{ fmtGb(s.total_gb - s.used_gb) }}</td><td class="num">{{ fmtGb(s.total_gb) }}</td></tr></tbody>
          </table></div>
          <h3>Bridges and VLANs</h3>
          <div class="wz-table-wrap"><table>
            <thead><tr><th>Name</th><th>Node</th><th>Kind</th><th>VLAN</th></tr></thead>
            <tbody><tr v-for="n in disc.networks" :key="n.name + n.node"><td class="mono">{{ n.name }}</td><td>{{ n.node ?? 'cluster' }}</td><td>{{ n.kind }}</td><td>{{ n.vlan ?? '-' }}</td></tr></tbody>
          </table></div>
          <h3>Existing guests</h3>
          <div class="wz-table-wrap"><table>
            <thead><tr><th>VMID</th><th>Name</th><th>Kind</th><th>Node</th><th>Status</th></tr></thead>
            <tbody>
              <tr v-for="g in disc.guests" :key="g.vmid"><td class="mono">{{ g.vmid }}</td><td>{{ g.name }}<span v-if="g.template" class="wz-chip info"> template</span></td><td>{{ g.kind }}</td><td>{{ g.node }}</td><td>{{ g.status }}</td></tr>
              <tr v-if="!disc.guests.length"><td colspan="5" class="muted">No guests found.</td></tr>
            </tbody>
          </table></div>
          <p class="small muted">Existing guests are never modified: the ICS only manages guests it created and tagged itself.</p>
        </template>
      </div>
    </div>

    <!-- 3 defaults -->
    <div v-show="wz.current.value.id === 'defaults'">
      <div class="wz-card">
        <h2>Deployment defaults</h2>
        <p class="muted">Used as the starting point for new deployments. Each deployment can still be adjusted in its own wizard, within these limits.</p>
        <div class="wz-grid">
          <Field label="Resource pool" :error="fieldErr('pool')" hint="All ICS-created guests live here. Must match the pool granted to the provision token." v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.defaults.pool" type="text" :aria-invalid="invalid" /></Field>
          <Field label="VM disk storage" :error="fieldErr('storage')" v-slot="{ id, invalid }">
            <select :id="id" v-model="m.defaults.storage" :aria-invalid="invalid"><option value="">Select…</option><option v-for="s in storageFor(m, 'images')" :key="s.id" :value="s.id">{{ s.id }} ({{ fmtGb(s.total_gb - s.used_gb) }} free)</option></select>
          </Field>
          <Field label="Bridge" :error="fieldErr('bridge')" v-slot="{ id, invalid }">
            <select :id="id" v-model="m.defaults.bridge" :aria-invalid="invalid"><option value="">Select…</option><option v-for="n in disc?.networks ?? []" :key="n.name + n.node" :value="n.name">{{ n.name }}</option></select>
          </Field>
          <Field label="VLAN tag" :error="fieldErr('vlan')" optional hint="Empty = untagged." v-slot="{ id, invalid }"><input :id="id" v-model="m.defaults.vlan" type="text" inputmode="numeric" :aria-invalid="invalid" /></Field>
        </div>

        <h3>IP addressing</h3>
        <div class="wz-row">
          <label class="wz-choice"><input v-model="m.defaults.ipMode" type="radio" value="dhcp" /> DHCP</label>
          <label class="wz-choice"><input v-model="m.defaults.ipMode" type="radio" value="static" /> Static pool</label>
        </div>
        <div v-if="m.defaults.ipMode === 'static'" class="wz-grid">
          <Field label="Pool start" :error="fieldErr('ipStart')" v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.defaults.ipStart" type="text" :aria-invalid="invalid" /></Field>
          <Field label="Pool end" :error="fieldErr('ipEnd')" v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.defaults.ipEnd" type="text" :aria-invalid="invalid" /></Field>
          <Field label="Gateway" :error="fieldErr('gateway')" v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.defaults.gateway" type="text" :aria-invalid="invalid" /></Field>
          <Field label="Prefix length" :error="fieldErr('prefix')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.defaults.prefix" type="number" :aria-invalid="invalid" /></Field>
        </div>

        <h3>DNS and backup</h3>
        <div class="wz-grid">
          <Field label="Domain" optional :error="fieldErr('domain')" v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.defaults.domain" type="text" placeholder="corp.example.com" :aria-invalid="invalid" /></Field>
          <Field label="DNS servers" optional :error="fieldErr('dnsServers')" hint="Comma-separated." v-slot="{ id, invalid }"><input :id="id" v-model="m.defaults.dnsServers" type="text" placeholder="192.168.1.1, 1.1.1.1" :aria-invalid="invalid" /></Field>
          <Field label="Backup destination" optional hint="Storage that accepts backups." v-slot="{ id }">
            <select :id="id" v-model="m.defaults.backupStorage"><option value="">None (set per deployment)</option><option v-for="s in storageFor(m, 'backup')" :key="s.id" :value="s.id">{{ s.id }} ({{ fmtGb(s.total_gb - s.used_gb) }} free)</option></select>
          </Field>
        </div>

        <h3>Approved OS images</h3>
        <p v-if="fieldErr('images')" class="bad-text" role="alert">{{ fieldErr('images') }}</p>
        <label v-for="o in OS_IMAGES" :key="o.id" class="wz-choice"><input v-model="m.defaults.images" type="checkbox" :value="o.id" /> {{ o.label }}</label>
        <p class="small muted">Only checksum-pinned images from the approved catalog can be used; arbitrary images are not accepted.</p>

        <h3>Resource policy (per deployment)</h3>
        <div class="wz-grid">
          <Field label="Max vCPU" :error="fieldErr('maxCores')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.defaults.maxCores" type="number" :aria-invalid="invalid" /></Field>
          <Field label="Max memory (GiB)" :error="fieldErr('maxMemoryGb')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.defaults.maxMemoryGb" type="number" :aria-invalid="invalid" /></Field>
          <Field label="Max disk (GiB)" :error="fieldErr('maxDiskGb')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.defaults.maxDiskGb" type="number" :aria-invalid="invalid" /></Field>
          <Field label="CPU overcommit ratio" :error="fieldErr('cpuOvercommit')" hint="vCPU : physical core." v-slot="{ id, invalid }"><input :id="id" v-model.number="m.defaults.cpuOvercommit" type="number" step="0.5" :aria-invalid="invalid" /></Field>
        </div>
      </div>
    </div>

    <!-- 4 security -->
    <div v-show="wz.current.value.id === 'security'">
      <div class="wz-card">
        <h2>Security</h2>
        <h3>Approvals required per risk level</h3>
        <div class="wz-grid">
          <Field label="Low-risk actions" v-slot="{ id }"><select :id="id" v-model.number="m.security.approvalsLow"><option :value="1">1 approver</option><option :value="2">2 approvers</option></select></Field>
          <Field label="High-risk actions" :error="fieldErr('approvalsHigh')" hint="Registering endpoints, destroying guests, production changes." v-slot="{ id, invalid }"><select :id="id" v-model.number="m.security.approvalsHigh" :aria-invalid="invalid"><option :value="1">1 approver</option><option :value="2">2 approvers</option></select></Field>
        </div>
        <p class="small muted">The requester can never approve their own plan. Approval mode never auto-executes.</p>
        <h3>Multi-factor authentication</h3>
        <Banner v-if="setupState?.state === 'ok' && setupState.data.mfa" :kind="setupState.data.mfa.enrolled_users >= setupState.data.mfa.total_users ? 'ok' : 'warn'" title="Current MFA status">
          {{ setupState.data.mfa.enrolled_users }} of {{ setupState.data.mfa.total_users }} console users have TOTP enrolled.
        </Banner>
        <Unavailable v-else-if="setupState?.state === 'unavailable'" what="MFA status" endpoint="GET /api/v1/setup/state" :status="setupState.status" />
        <label class="wz-choice"><input v-model="m.security.requireMfaForApprovers" type="checkbox" /> Require MFA-enrolled users for approvals</label>
        <h3>Alert channel</h3>
        <div class="wz-grid">
          <Field label="Send alerts via" v-slot="{ id }"><select :id="id" v-model="m.security.alertKind"><option value="none">Console only</option><option value="email">E-mail</option><option value="webhook">Webhook (https)</option></select></Field>
          <Field v-if="m.security.alertKind !== 'none'" :label="m.security.alertKind === 'email' ? 'E-mail address' : 'Webhook URL'" :error="fieldErr('alertTarget')" v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.security.alertTarget" type="text" :aria-invalid="invalid" /></Field>
        </div>
      </div>
    </div>

    <!-- 5 review -->
    <div v-show="wz.current.value.id === 'review'">
      <div v-if="created" class="wz-card">
        <Banner kind="ok" title="Plan submitted">Plan <span class="mono">{{ created.plan_id }}</span> is {{ created.status.replace('_', ' ') }} (risk {{ created.risk }}, {{ created.approvals_required }} approval(s) required). Nothing runs until it is approved.</Banner>
        <p><a :href="'#/plans'">Open Plans</a> to follow approval.</p>
      </div>
      <template v-else>
        <div class="wz-card">
          <h2>Readiness report</h2>
          <ul class="wz-checks"><li v-for="c in checks" :key="c.id"><span><span class="wz-chip" :class="c.level">{{ c.level === 'ok' ? 'Ready' : c.level === 'warn' ? 'Note' : c.blocks ? 'Blocks provisioning' : 'Blocked' }}</span></span><span>{{ c.text }}</span></li></ul>
        </div>
        <div class="wz-card">
          <h2>What will be submitted</h2>
          <p class="muted">One <span class="mono">endpoint.register</span> plan (high risk). It needs approval before anything is stored or contacted. The token secret is masked below.</p>
          <dl class="wz-dl">
            <dt>Endpoint</dt><dd>{{ m.name }} &middot; {{ params.base_url }}</dd>
            <dt>Token</dt><dd class="mono">{{ m.tokenId }} (secret entered)</dd>
            <dt>Credential roles</dt><dd>{{ (params.credential_roles as string[]).join(', ') }}</dd>
            <dt>Allowed pools / storage / networks</dt><dd>{{ (params.allowed_pools as string[]).join(', ') || 'none (inventory-only)' }} / {{ (params.allowed_storage as string[]).join(', ') || 'none' }} / {{ (params.allowed_networks as string[]).join(', ') || 'none' }}</dd>
            <dt>Approvals</dt><dd>low {{ m.security.approvalsLow }}, high {{ m.security.approvalsHigh }}; MFA for approvers {{ m.security.requireMfaForApprovers ? 'required' : 'not required' }}</dd>
          </dl>
          <HelpNote title="Exact request body"><pre class="mono wz-code">{{ masked }}</pre></HelpNote>
        </div>
        <Banner v-if="submitError" kind="bad" title="Not submitted">{{ submitError }}</Banner>
        <label class="wz-choice"><input v-model="m.confirmed" type="checkbox" :disabled="!isReady(m)" /> I have reviewed the report above and want to submit this plan for approval.</label>
        <div class="wz-footer"><button type="button" class="wz-btn" @click="wz.back()">Back</button><span class="spacer"></span>
          <button type="button" class="wz-btn primary" :disabled="!canSubmit || submitting" @click="submit">{{ submitting ? 'Submitting…' : 'Submit plan for approval' }}</button></div>
      </template>
    </div>
  </WizardShell>
</template>
