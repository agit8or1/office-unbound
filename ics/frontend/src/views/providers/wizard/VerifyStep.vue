<script setup lang="ts">
// Step 6: permission test results. What Proxmox actually allows now, not what we asked for.
import { computed, onMounted, ref } from 'vue'
import { Banner } from '../../../wizards/kit'
import { api, load, msg } from '../api'
import { driftItems, type DriftReport, type PermissionsView, type ProviderEndpoint, type WizardModel } from '../model'
import type { Outcome } from './ApplyStep.vue'
const props = defineProps<{ m: WizardModel; outcome: Outcome }>()
const ep = ref<ProviderEndpoint | null>(null), perms = ref<PermissionsView | null>(null)
const busy = ref(false), error = ref(''), rep = ref<DriftReport | null>(null)
const VERB: Record<string, string> = { discover: 'Read nodes, storage and guests', metrics: 'Collect performance metrics', clone_vm: 'Create VMs from templates', configure_vm: 'Configure VMs', resize_disk: 'Grow disks', power: 'Start and stop VMs', snapshot: 'Take snapshots', rollback: 'Roll back snapshots', migrate: 'Move VMs between nodes', destroy_vm: 'Delete VMs it created', clone_template: 'Clone the approved templates' }
async function reload() {
  if (!props.m.endpointId) return
  const e = await load(() => api.endpoint(props.m.endpointId!)); if (e.state === 'ok') ep.value = e.data
  const p = await load(() => api.permissions(props.m.endpointId!)); if (p.state === 'ok') perms.value = p.data
}
onMounted(reload)
async function validate() {
  busy.value = true; error.value = ''
  try { rep.value = (await api.checkPermissions(props.m.endpointId!)) as DriftReport; await reload() } catch (e) { error.value = msg(e) } finally { busy.value = false }
}
const verbs = computed(() => Object.entries(ep.value?.last_probe?.verbs ?? {}))
const verifs = computed(() => Object.entries(props.outcome.verification ?? {}).filter(([k]) => k !== 'ok') as [string, NonNullable<Outcome['verification']>[string]][])
const allOk = computed(() => verifs.value.length ? verifs.value.every(([, v]) => v.ok) : !!ep.value?.last_probe?.ok)
const items = computed(() => driftItems(rep.value ?? perms.value?.last_drift))
const disc = computed(() => ep.value?.last_discovery)
</script>
<template>
  <div>
    <Banner v-if="allOk" kind="ok" title="Everything checks out">The tokens work and their permissions match what you approved.</Banner>
    <Banner v-else kind="warn" title="Some checks need attention">Review the list below. Nothing was widened to make them pass.</Banner>

    <div class="wz-card"><h2>Connection</h2>
      <ul class="wz-checks">
        <li><span class="wz-chip ok">Pass</span><span>Server identity confirmed ({{ m.trust === 'ca' ? 'CA' : 'pinned fingerprint' }}); TLS is verified on every connection.</span></li>
        <li><span class="wz-chip" :class="ep?.last_probe?.ok === false ? 'bad' : ep?.last_probe ? 'ok' : 'info'">{{ ep?.last_probe?.ok === false ? 'Fail' : ep?.last_probe ? 'Pass' : 'Pending' }}</span><span>Token accepted by Proxmox<template v-if="ep?.last_probe?.version"> (version {{ ep.last_probe.version }})</template>.</span></li>
        <li><span class="wz-chip" :class="disc?.ok ? 'ok' : disc?.ok === false ? 'bad' : 'info'">{{ disc?.ok ? 'Pass' : disc?.ok === false ? 'Fail' : 'Pending' }}</span><span>Inventory discovery<template v-if="disc?.ok">: {{ Object.entries(disc.counts ?? {}).map(([k, v]) => v + ' ' + k).join(', ') }}</template><template v-else-if="disc?.error">: {{ disc.error }}</template><template v-else> runs within a few minutes of connecting.</template></span></li>
      </ul></div>

    <div v-if="verbs.length" class="wz-card"><h2>What Office Unbound can do right now</h2>
      <p class="muted small">Tested against the permissions Proxmox reports for the token. "Cannot" is expected for anything you did not authorise.</p>
      <ul class="wz-checks"><li v-for="[v, ok] in verbs" :key="v"><span class="wz-chip" :class="ok ? 'ok' : 'warn'">{{ ok ? 'Can' : 'Cannot' }}</span><span>{{ VERB[v] ?? v }}</span></li></ul></div>

    <div v-if="verifs.length" class="wz-card"><h2>Permission verification</h2>
      <div v-for="[k, v] in verifs" :key="k" class="pv-res">
        <div class="wz-row"><b>{{ k === 'inventory' ? 'Inventory token' : 'Provisioning token' }}</b><span class="wz-chip" :class="v.ok ? 'ok' : 'bad'">{{ v.ok ? 'Matches the plan' : 'Differs from the plan' }}</span></div>
        <ul v-if="!v.ok" class="pv-list"><li v-for="x in v.missing ?? []" :key="'m' + x.path">Missing: {{ x.privileges.join(', ') }} on <span class="mono">{{ x.path }}</span></li><li v-for="x in v.unexpected ?? []" :key="'u' + x.path">Extra: {{ x.privileges.join(', ') }} on <span class="mono">{{ x.path }}</span></li></ul>
      </div></div>

    <div v-if="perms?.managed_by_provisioning" class="wz-card"><h2>Run the permission test again</h2>
      <p class="muted small">Logs in with the integration's own tokens and compares real permissions with the approved policy. Read-only.</p>
      <button type="button" class="wz-btn" :disabled="busy" @click="validate">{{ busy ? 'Testing...' : 'Run validation' }}</button>
      <Banner v-if="error" kind="bad">{{ error }}</Banner>
      <template v-if="rep"><Banner :kind="rep.ok ? 'ok' : 'warn'" :title="rep.ok ? 'In sync' : 'Drift found'">{{ rep.error ?? (rep.ok ? 'Actual permissions match the policy.' : items.length + ' difference(s).') }}</Banner>
        <ul class="pv-list"><li v-for="(i, n) in items" :key="n"><b>{{ i.kind }}</b>: {{ i.suggestion }}</li></ul></template></div>
    <p v-else-if="m.method === 'token'" class="muted small">The token's permissions are managed by you in Proxmox. To change them, edit the token there and test again from the cluster's page.</p>
  </div>
</template>
