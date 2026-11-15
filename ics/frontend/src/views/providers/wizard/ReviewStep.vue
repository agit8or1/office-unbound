<script setup lang="ts">
// Step 4: exactly what will happen. For setup by Office Unbound or a package this asks Proxmox-side facts through a read-only preview plan.
import { computed, ref } from 'vue'
import { Banner } from '../../../wizards/kit'
import type { Errors } from '../../../wizards/kit'
import CredFields from '../CredFields.vue'
import PlanView from '../PlanView.vue'
import RunPanel from '../RunPanel.vue'
import { previewOf } from '../api'
import { previewKeyOf, previewParams, riskOf, tokenPathEnforcement, validateCreds, wipeAdmin, type SecretBag, type WizardModel } from '../model'
import type { Run } from '../run'
const props = defineProps<{ m: WizardModel; s: SecretBag; errors: Errors; run: Run }>()
const emit = defineEmits<{ errors: [Errors] }>()
const risk = computed(() => riskOf(props.m))
const fresh = computed(() => !!props.m.preview && props.m.previewKey === previewKeyOf(props.m))
const localErrors = ref<Errors>({})
const online = computed(() => props.m.method === 'admin')
async function preview() {
  const e = online.value ? validateCreds(props.m, props.s) : {}
  localErrors.value = e
  if (Object.keys(e).length) return
  props.m.preview = null
  const params = previewParams(props.m, props.s)
  const job = await props.run.start('provider.provision.plan_preview', params as Record<string, unknown>)
  wipeAdmin(props.s) // temporary credentials: gone as soon as the request has been sent
  const p = job && job.status === 'succeeded' ? previewOf(job) : null
  if (p) { props.m.preview = p; props.m.previewKey = previewKeyOf(props.m); emit('errors', {}) }
}
const probePerms = computed(() => props.m.probe?.permissions)
</script>
<template>
  <div>
    <!-- Existing token: nothing is changed in Proxmox -->
    <template v-if="m.method === 'token'">
      <Banner kind="ok" title="No changes will be made in Proxmox">Office Unbound will register your token and remember the limits below. What the token can do is decided by Proxmox, not by this wizard.</Banner>
      <div class="wz-card"><h2>What will be saved</h2>
        <dl class="wz-dl">
          <dt>Cluster</dt><dd>{{ m.displayName || m.name }} <span class="mono muted">{{ m.host }}:{{ m.port }}</span></dd>
          <dt>Certificate</dt><dd>{{ m.trust === 'ca' ? 'Verified against your CA' : 'Pinned to the fingerprint you compared' }}</dd>
          <dt>Token</dt><dd class="mono">{{ m.tokenId }}<template v-if="m.provisionTokenId"> and {{ m.provisionTokenId }}</template></dd>
          <dt>Pools</dt><dd>{{ m.scope.pools.join(', ') || 'none' }}</dd><dt>Storage</dt><dd>{{ m.scope.storages.join(', ') || 'none' }}</dd>
          <dt>Networks</dt><dd>{{ m.scope.networks.join(', ') || 'none' }}</dd><dt>Templates</dt><dd>{{ m.scope.template_vmids.join(', ') || 'none' }}</dd>
        </dl></div>
      <div v-if="probePerms" class="wz-card"><h2>What the token can do today</h2>
        <p><span class="wz-chip" :class="probePerms.inventory.ok ? 'ok' : 'bad'">Read inventory: {{ probePerms.inventory.ok ? 'yes' : 'no' }}</span> <span class="wz-chip" :class="probePerms.provision.ok ? 'ok' : 'warn'">Create and change VMs: {{ probePerms.provision.ok ? 'yes' : m.provisionTokenId ? 'no' : 'not configured' }}</span></p>
        <h3>Who enforces what</h3>
        <ul class="pv-list"><li v-for="e in tokenPathEnforcement(m)" :key="e.control"><span class="wz-chip" :class="e.enforced_by === 'proxmox' ? 'ok' : e.enforced_by === 'ics' ? 'info' : 'warn'">{{ e.enforced_by === 'proxmox' ? 'Proxmox' : e.enforced_by === 'ics' ? 'Office Unbound only' : 'Not enforced yet' }}</span> <b>{{ e.control }}</b><div class="muted small">{{ e.detail }}</div></li></ul></div>
    </template>

    <template v-else>
      <div class="wz-card" v-if="!fresh">
        <h2>Preview the changes</h2>
        <p class="muted">This is read-only. It works out exactly which accounts, roles and permissions would be created, and flags anything that already exists.</p>
        <template v-if="online">
          <Banner kind="info" title="Temporary administrator login">Used once for this preview, then discarded. You will be asked again when you apply, because it is never kept.</Banner>
          <CredFields :m="m" :s="s" :errors="localErrors" />
        </template>
        <p v-else class="muted small">No login is needed: this preview is computed offline for Proxmox VE {{ m.pveMajor }}. The script re-checks everything when it runs.</p>
        <div class="wz-row mt"><button type="button" class="wz-btn primary" :disabled="run.busy.value" @click="preview">{{ run.busy.value ? 'Working out the plan...' : 'Preview changes' }}</button><span v-if="errors.preview" class="bad-text" role="alert">{{ errors.preview }}</span></div>
        <RunPanel :run="run" what="Reading your cluster and computing the plan" />
      </div>
      <template v-if="fresh && m.preview">
        <Banner kind="ok" title="Plan ready">Review it carefully. Nothing has been changed yet.</Banner>
        <PlanView :preview="m.preview" />
        <button type="button" class="wz-btn" @click="m.preview = null; m.previewKey = null">Discard and preview again</button>
      </template>
    </template>

    <div v-if="risk === 'high'" class="wz-card pv-risk">
      <Banner kind="bad" title="High-impact request">This needs two approvers and is recorded in the audit log.</Banner>
      <label class="wz-choice"><input v-model="m.riskAck" type="checkbox" /> <span>I have read the consequences above and want to submit this for approval.</span></label>
      <p v-if="errors.riskAck" class="bad-text" role="alert">{{ errors.riskAck }}</p>
    </div>
  </div>
</template>
