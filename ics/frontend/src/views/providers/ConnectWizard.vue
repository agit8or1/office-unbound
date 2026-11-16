<script setup lang="ts">
// Connect a Proxmox cluster: Connect > Discover > Access > Review > Apply > Verify > Done.
import { computed, onBeforeUnmount, reactive } from 'vue'
import { Banner, WizardShell, useWizard, type Errors, type StepDef } from '../../wizards/kit'
import ConnectStep from './wizard/ConnectStep.vue'
import DiscoverStep from './wizard/DiscoverStep.vue'
import ReviewStep from './wizard/ReviewStep.vue'
import ApplyStep, { type Outcome } from './wizard/ApplyStep.vue'
import VerifyStep from './wizard/VerifyStep.vue'
import ScopeEditor from './ScopeEditor.vue'
import { newModel, newSecrets, previewKeyOf, riskOf, reviewVerdict, suggestScope, validateConnect, validateScope, wipe, type WizardModel } from './model'
import { useRun } from './run'
import './providers.css'

const m = reactive(newModel()) as WizardModel
const s = newSecrets() // not reactive, never serialised: wiped after each request
const run = useRun()
const outcome = reactive<Outcome>({ verification: null, applied: [], version: null })
onBeforeUnmount(() => wipe(s))

const applyTitle = computed(() => (m.method === 'package' ? 'Package' : m.method === 'admin' ? 'Apply' : 'Register'))
const stepsOf = (): StepDef<WizardModel>[] => [
  { id: 'connect', title: 'Connect', validate: (x) => validateConnect(x, s) },
  { id: 'discover', title: 'Discover' },
  { id: 'access', title: 'Access', validate: (x) => validateScope(x) },
  { id: 'review', title: 'Review', validate: (x): Errors => {
    if (x.method !== 'token') {
      if (!x.preview || x.previewKey !== previewKeyOf(x)) return { preview: 'Preview the changes before continuing.' }
      if (!reviewVerdict(x.preview).ok) return { preview: 'The plan is blocked. Go back and change the access, or resolve the items above.' }
    }
    return riskOf(x) === 'high' && !x.riskAck ? { riskAck: 'Confirm that you have read the consequences.' } : {}
  } },
  { id: 'apply', title: applyTitle.value, validate: (x): Errors => (x.endpointId ? {} : { apply: x.method === 'package' ? 'Generate the package and import the tokens to continue.' : 'Complete this step to continue.' }) },
  { id: 'verify', title: 'Verify' },
  { id: 'done', title: 'Done' },
]
const steps = computed(() => stepsOf())
const w = useWizard(stepsOf(), m)
// titles are reactive to the chosen method
const shellSteps = computed(() => steps.value.map((x) => ({ id: x.id, title: x.title })))

function onNext() {
  const before = w.m.index
  const leaving = w.current.value.id
  if (leaving === 'discover' && !m.scopeSuggested && m.discovery) { Object.assign(m.scope, suggestScope(m.discovery, m.preset, m.scopeMode)); m.scopeSuggested = true }
  if (w.next() && before === 0 && m.discovery && !m.scopeSuggested) { Object.assign(m.scope, suggestScope(m.discovery, m.preset, m.scopeMode)); m.scopeSuggested = true }
}
function setErrors(e: Record<string, string>) { w.m.errors = e }
const errs = computed(() => w.m.errors)
const last = computed(() => w.current.value.id === 'done')
const id = computed(() => w.current.value.id)
</script>

<template>
  <div class="pv-wiz">
    <WizardShell title="Connect a Proxmox cluster" subtitle="A few minutes. You stay in control: nothing is changed in Proxmox until you have seen exactly what will happen."
      :steps="shellSteps" :index="w.m.index" :reached="w.m.reached" :next-label="id === 'review' ? (m.method === 'token' ? 'Continue' : 'Continue to ' + applyTitle.toLowerCase()) : id === 'verify' ? 'Finish' : 'Next'"
      :hide-next="last" :busy="run.busy.value" @next="onNext" @back="w.back()" @goto="w.goto($event)">
      <Banner v-if="id === 'connect'" kind="info" title="Have SSH access to a node instead of an API token?">
        <router-link to="/infrastructure/providers/proxmox/connect-ssh">Connect with SSH</router-link>: log in once, choose what Office Unbound may do, and it creates its own account, permissions and key. Your login is destroyed afterwards.
      </Banner>
      <ConnectStep v-if="id === 'connect'" :m="m" :s="s" :errors="errs" @errors="setErrors" />
      <DiscoverStep v-else-if="id === 'discover'" :m="m" :s="s" :errors="errs" @errors="setErrors" />
      <div v-else-if="id === 'access'">
        <h2>What may Office Unbound do?</h2>
        <p class="muted">Start from an access level, then choose exactly where it applies. You can change this later; widening access always needs approval.</p>
        <ScopeEditor :m="m" :errors="errs" />
      </div>
      <ReviewStep v-else-if="id === 'review'" :m="m" :s="s" :errors="errs" :run="run" @errors="setErrors" />
      <ApplyStep v-else-if="id === 'apply'" :m="m" :s="s" :errors="errs" :run="run" :outcome="outcome" @errors="setErrors" />
      <VerifyStep v-else-if="id === 'verify'" :m="m" :outcome="outcome" />
      <div v-else class="pv-done">
        <div class="pv-bigcheck" aria-hidden="true">&#10003;</div>
        <h2>{{ m.displayName || m.name }} is connected</h2>
        <p class="muted">Office Unbound is now reading the cluster. Inventory and charts fill in over the next few minutes.</p>
        <dl class="wz-dl">
          <dt>Access level</dt><dd>{{ m.preset === 'deploy' ? 'Deployment & management' : m.preset === 'monitoring' ? 'Monitoring only' : m.preset === 'full_admin' ? 'Full cluster administration' : 'Custom' }}</dd>
          <dt>Authorised</dt><dd>{{ [m.scope.pools.length && m.scope.pools.length + ' pool(s)', m.scope.storages.length && m.scope.storages.length + ' storage', m.scope.networks.length && m.scope.networks.length + ' network(s)'].filter(Boolean).join(', ') || 'see the permissions page' }}</dd>
          <dt>Credentials</dt><dd>Encrypted in the vault. The secrets you typed were wiped from this page.</dd>
        </dl>
        <div class="wz-row mt">
          <router-link v-if="m.endpointId" class="wz-btn primary" :to="`/infrastructure/providers/${m.endpointId}`">Open the cluster</router-link>
          <router-link class="wz-btn" :to="m.endpointId ? `/infrastructure/providers/${m.endpointId}/permissions` : '/infrastructure/providers'">Review permissions</router-link>
          <router-link class="wz-btn" to="/deployments/new">Plan a deployment</router-link>
        </div>
        <Banner kind="info" title="What to do if something looks wrong">Open the cluster's Permissions page to run a validation, rotate a token or revoke access at any time.</Banner>
      </div>
    </WizardShell>
  </div>
</template>
