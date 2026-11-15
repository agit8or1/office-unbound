<script setup lang="ts">
// A permission change as a plan: configure, see the before/after, then submit. Used by the permissions page for
// change access (add/remove/modify permissions, create a role via custom grants), reconcile, rotate token and revoke.
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import Drawer from '../../ui/Drawer.vue'
import { Banner, Field } from '../../wizards/kit'
import type { Errors } from '../../wizards/kit'
import CredFields from './CredFields.vue'
import PlanView from './PlanView.vue'
import RunPanel from './RunPanel.vue'
import ScopeEditor from './ScopeEditor.vue'
import { api, previewOf } from './api'
import {
  applyParams, buildPolicy, changedOnly, diffPolicies, newModel, newSecrets, normDiscovery, policyForApi, policyFromView, previewKeyOf, reviewVerdict, riskOf, validateCreds, validateScope, wipeAdmin,
  type DiffRow, type PermissionsView, type WizardModel,
} from './model'
import { useRun } from './run'
import './providers.css'

export type FlowKind = 'change' | 'reconcile' | 'rotate' | 'revoke'
const props = defineProps<{ kind: FlowKind; endpointId: string; name: string; view: PermissionsView }>()
const emit = defineEmits<{ close: []; done: [] }>()
const TITLE: Record<FlowKind, string> = { change: 'Change access', reconcile: 'Restore approved permissions', rotate: 'Rotate tokens', revoke: 'Revoke access' }

const original = policyFromView(props.view)
const m = reactive(newModel()) as WizardModel
m.endpointId = props.endpointId; m.method = 'admin'
if (original) {
  m.preset = original.preset; m.capabilities = [...original.capabilities]; Object.assign(m.scope, JSON.parse(JSON.stringify(original.scope)))
  m.serviceUser = original.service_user; m.scopeSuggested = true; m.acknowledgeFullAdmin = original.acknowledge_full_admin
  m.scopeMode = original.scope_mode ?? (original.scope.nodes.length ? 'single_node' : 'whole_cluster'); m.riskOverrides = [...(original.scope_risk_overrides ?? [])]; m.allowMigrate = original.allow_migrate
}
const s = newSecrets()
onBeforeUnmount(() => wipeAdmin(s))
const run = useRun()
const previewRun = useRun()
const errors = ref<Errors>({})
const stage = ref<'configure' | 'review'>(props.kind === 'change' ? 'configure' : 'review')
const kinds = ref<string[]>(Object.keys(props.view.tokens ?? {}))
const confirmName = ref(''), deleteUser = ref(false), deleteRoles = ref(false)
const loadingDisc = ref(props.kind === 'change')
onMounted(async () => {
  if (props.kind !== 'change') return
  try {
    const [nodes, storage, networks, guests, templates] = await Promise.all([api.nodes(props.endpointId), api.storage(props.endpointId), api.networks(props.endpointId), api.guests(props.endpointId), api.templates(props.endpointId)])
    m.discovery = normDiscovery({ nodes, storage, networks, guests, templates })
  } catch { m.discovery = null } finally { loadingDisc.value = false }
})

// ---- before / after
const diff = computed<DiffRow[]>(() => {
  if (props.kind === 'change' && original) return diffPolicies(original, buildPolicy(m))
  if (props.kind === 'rotate') return kinds.value.map((k) => ({ field: (k === 'inventory' ? 'Inventory' : 'Provisioning') + ' token', before: `${props.view.tokens?.[k]?.id ?? k} (generation ${props.view.tokens?.[k]?.gen ?? 1})`, after: 'New secret under a new generation; the old token is deleted in Proxmox', changed: true }))
  if (props.kind === 'revoke') return [
    { field: 'API tokens', before: Object.values(props.view.tokens ?? {}).map((t) => t.id).join(', ') || '(none)', after: 'Deleted in Proxmox; stored credentials destroyed', changed: true },
    { field: 'Cluster connection', before: 'Connected', after: 'Disconnected. Office Unbound can no longer read or change this cluster.', changed: true },
    { field: 'Service account', before: props.view.service_user ?? '-', after: deleteUser.value ? 'Deleted' : 'Kept in Proxmox (disabled by losing its tokens)', changed: deleteUser.value },
    { field: 'Roles created by Office Unbound', before: (props.view.managed_objects?.roles ?? []).join(', ') || '(none)', after: deleteRoles.value ? 'Deleted' : 'Kept', changed: deleteRoles.value },
  ]
  return []
})
const diffShown = computed(() => (props.kind === 'change' ? changedOnly(diff.value) : diff.value))
const risky = computed(() => props.kind !== 'change' || riskOf(m) !== 'normal')

// ---- preview (change, reconcile)
async function preview() {
  const e: Errors = props.kind === 'change' ? validateScope(m) : {}
  Object.assign(e, validateCreds(m, s))
  errors.value = e
  if (Object.keys(e).length) return
  m.preview = null
  const params = props.kind === 'reconcile'
    ? { purpose: 'reconcile', endpoint_id: props.endpointId, admin_username: m.adminKind === 'password' ? m.adminUser.trim() : undefined, admin_password: m.adminKind === 'password' ? s.adminPassword : undefined, admin_token_id: m.adminKind === 'token' ? m.adminTokenId.trim() : undefined, admin_token_secret: m.adminKind === 'token' ? s.adminTokenSecret : undefined }
    : { purpose: 'provision', endpoint_id: props.endpointId, policy: policyForApi(buildPolicy(m)), ...creds() }
  const job = await previewRun.start('provider.provision.plan_preview', stripUndef(params))
  wipeAdmin(s)
  const p = job?.status === 'succeeded' ? previewOf(job) : null
  if (p) { m.preview = p; m.previewKey = previewKeyOf(m) }
}
const stripUndef = (o: Record<string, unknown>) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined))
const creds = () => (m.adminKind === 'password' ? { admin_username: m.adminUser.trim(), admin_password: s.adminPassword } : { admin_token_id: m.adminTokenId.trim(), admin_token_secret: s.adminTokenSecret })

// ---- submit
const ack = ref(false)
const done = ref(false)
async function submit() {
  const e = validateCreds(m, s)
  if (props.kind === 'revoke' && confirmName.value !== props.name) e.confirm = `Type the cluster ID "${props.name}" to confirm.`
  if (props.kind === 'rotate' && !kinds.value.length) e.kinds = 'Choose at least one token.'
  if (risky.value && !ack.value) e.ack = 'Confirm that you have reviewed the change.'
  errors.value = e
  if (Object.keys(e).length) return
  let action = '', params: Record<string, unknown> = {}
  if (props.kind === 'change') { action = 'provider.provision.apply'; params = applyParams(m, s) }
  else if (props.kind === 'reconcile') { action = 'provider.permissions.reconcile'; params = { endpoint_id: props.endpointId, preview_id: m.preview!.preview_id, plan_hash: m.preview!.plan_hash, ...creds() } }
  else if (props.kind === 'rotate') { action = 'provider.token.rotate'; params = { endpoint_id: props.endpointId, kinds: kinds.value, ...creds() } }
  else { action = 'provider.token.revoke'; params = { endpoint_id: props.endpointId, confirm_name: confirmName.value, delete_user: deleteUser.value, delete_roles: deleteRoles.value, ...creds() } }
  const job = await run.start(action, params)
  wipeAdmin(s)
  if (job?.status === 'succeeded') { done.value = true; emit('done') }
}
const needsPreview = computed(() => props.kind === 'change' || props.kind === 'reconcile')
const previewReady = computed(() => !!m.preview && (props.kind === 'reconcile' || m.previewKey === previewKeyOf(m)))
const blocked = computed(() => (m.preview ? !reviewVerdict(m.preview).ok : false))
function toReview() { const e = validateScope(m); errors.value = e; if (!Object.keys(e).length) { stage.value = 'review'; m.preview = null } }
</script>

<template>
  <Drawer :title="TITLE[kind] + ' - ' + name" @close="emit('close')">
    <div class="wz pv-flow">
      <Banner v-if="!original && kind === 'change'" kind="warn" title="This cluster was connected with a token you supplied">There is no stored policy to change here. Edit the token in Proxmox, or reconnect the cluster through the wizard.</Banner>
      <template v-else>
        <template v-if="kind === 'change' && stage === 'configure'">
          <p class="muted">Choose the new access. You will see exactly what changes before anything is submitted. Widening access always needs approval.</p>
          <p v-if="loadingDisc" class="muted">Loading what is in the cluster...</p>
          <ScopeEditor v-else :m="m" :errors="errors" compact-advanced scope-locked />
          <div class="wz-row mt"><button type="button" class="wz-btn primary" @click="toReview">Review the change</button><button type="button" class="wz-btn" @click="emit('close')">Cancel</button></div>
        </template>

        <template v-else>
          <p v-if="kind === 'reconcile'" class="muted">Puts Proxmox back to the approved policy. It only restores what was approved and removes what was not; it never grants more.</p>
          <p v-if="kind === 'rotate'" class="muted">Issues new secrets and deletes the old tokens. The connection keeps working throughout. Rotate if a secret may have been exposed.</p>
          <Banner v-if="kind === 'revoke'" kind="bad" title="Revoking cannot be undone">Office Unbound will lose access to this cluster. Existing VMs keep running.</Banner>

          <template v-if="kind === 'rotate'"><Field label="Tokens to rotate" :error="errors.kinds" v-slot="{ id }"><div :id="id" class="wz-row"><label v-for="k in Object.keys(view.tokens ?? {})" :key="k" class="wz-choice"><input v-model="kinds" type="checkbox" :value="k" /> {{ k === 'inventory' ? 'Inventory token' : 'Provisioning token' }} <span class="mono muted">{{ view.tokens?.[k]?.id }}</span></label></div></Field></template>
          <template v-if="kind === 'revoke'">
            <div class="wz-row"><label class="wz-choice"><input v-model="deleteUser" type="checkbox" /> Also delete the service account</label><label class="wz-choice"><input v-model="deleteRoles" type="checkbox" /> Also delete the roles Office Unbound created</label></div>
            <Field :label="`Type ${name} to confirm`" :error="errors.confirm" v-slot="{ id, invalid }"><input :id="id" v-model="confirmName" type="text" autocomplete="off" :aria-invalid="invalid" /></Field>
          </template>

          <h3>Before and after</h3>
          <div class="wz-table-wrap"><table class="pv-table"><thead><tr><th>Setting</th><th>Now</th><th>After the change</th></tr></thead>
            <tbody><tr v-for="r in diffShown" :key="r.field" :class="{ changed: r.changed }"><td>{{ r.field }}</td><td>{{ r.before }}</td><td><b>{{ r.after }}</b></td></tr>
              <tr v-if="!diffShown.length"><td colspan="3" class="muted">No difference from the current policy.</td></tr></tbody></table></div>

          <template v-if="needsPreview">
            <template v-if="!previewReady">
              <h3>Exact Proxmox changes</h3>
              <p class="muted small">A read-only check of the cluster, using a temporary administrator login that is discarded straight after.</p>
              <CredFields :m="m" :s="s" :errors="errors" />
              <div class="wz-row mt"><button type="button" class="wz-btn primary" :disabled="previewRun.busy.value || (kind === 'change' && !diffShown.length)" @click="preview">{{ previewRun.busy.value ? 'Working out the plan...' : 'Preview changes' }}</button><button v-if="kind === 'change'" type="button" class="wz-btn" @click="stage = 'configure'">Back</button></div>
              <RunPanel :run="previewRun" what="Computing the plan" />
            </template>
            <template v-else><PlanView v-if="m.preview" :preview="m.preview" /><button type="button" class="wz-btn" @click="m.preview = null">Preview again</button></template>
          </template>

          <div v-if="(!needsPreview || previewReady) && !done" class="wz-card mt">
            <h3>Submit</h3>
            <p class="muted small">Enter the administrator login again: it is never kept. This creates a plan that is approved according to its risk, then runs as a recorded job.</p>
            <CredFields :m="m" :s="s" :errors="errors" />
            <label v-if="risky" class="wz-choice mt"><input v-model="ack" type="checkbox" /> <span>I have reviewed the change and want to submit it for approval.</span></label>
            <p v-if="errors.ack" class="bad-text" role="alert">{{ errors.ack }}</p>
            <div class="wz-row mt"><button type="button" class="wz-btn primary" :disabled="run.busy.value || blocked" @click="submit">{{ run.busy.value ? 'Working...' : kind === 'revoke' ? 'Revoke access' : 'Submit' }}</button><button type="button" class="wz-btn" @click="emit('close')">Cancel</button></div>
            <RunPanel :run="run" :what="TITLE[kind]" />
          </div>
          <Banner v-if="done" kind="ok" title="Done">The change was applied and recorded in the audit log. The page will refresh its status.<div class="mt"><button type="button" class="wz-btn" @click="emit('close')">Close</button></div></Banner>
        </template>
      </template>
    </div>
  </Drawer>
</template>
