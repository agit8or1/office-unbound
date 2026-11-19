<script setup lang="ts">
// Manage access > connection maintenance, using the wizard's Proxmox sign-in: repair drifted permissions, rotate the service tokens, disconnect.
// Each is an approval-gated typed action; nothing here deletes a VM, a disk or anything Office Unbound did not create.
// "Clean up leftovers" deletes only what Office Unbound provably left behind (GET /infra/leftovers decides, the job re-checks live), using this
// sign-in for that one job: the credentials are not stored (provider.cleanup).
import { computed, ref } from 'vue'
import { get } from '../../../api'
import { Banner } from '../../../wizards/kit'
import { useRun } from '../run'
import RunPanel from '../RunPanel.vue'
import PlanView from '../PlanView.vue'
import type { PlanPreviewOut } from '../model'

const props = defineProps<{ endpointId: string; sessionId: string; endpointName: string; initial?: 'cleanup' }>()
const what = ref<'' | 'repair' | 'rotate' | 'disconnect' | 'cleanup'>('')
const run = useRun()
const preview = ref<PlanPreviewOut | null>(null)
const confirmName = ref('')
const removeAccount = ref(false)
const base = computed(() => ({ endpoint_id: props.endpointId, admin_session: props.sessionId }))

interface Leftover { vmid: number; name: string | null; node: string | null; template: boolean; removable: boolean; why: string }
const leftovers = ref<Leftover[] | null>(null)
const chosen = ref<number[]>([])
const importFiles = ref(true)
const removable = computed(() => (leftovers.value ?? []).filter(x => x.removable))
async function loadLeftovers() {
  const r = await get<{ items: Leftover[] }>(`infra/leftovers?endpoint=${encodeURIComponent(props.endpointId)}`)
  leftovers.value = r.items
  chosen.value = r.items.filter(x => x.removable).map(x => x.vmid)
}
function pick(w: typeof what.value) {
  what.value = w; preview.value = null; run.reset(); confirmName.value = ''
  if (w === 'cleanup') loadLeftovers()
}
if (props.initial) pick(props.initial)          // opened from the "Clean up leftovers" button (?task=cleanup)
const cleanup = () => run.start('provider.cleanup', { ...base.value, confirm_name: confirmName.value, vmids: chosen.value, import_files: importFiles.value })
async function repairPreview() {
  const j = await run.start('provider.provision.plan_preview', { ...base.value, purpose: 'reconcile' })
  if (j?.status === 'succeeded') preview.value = j.result as unknown as PlanPreviewOut
}
async function repairApply() {
  if (!preview.value) return
  await run.start('provider.permissions.reconcile', { ...base.value, preview_id: preview.value.preview_id, plan_hash: preview.value.plan_hash })
}
const rotate = () => run.start('provider.token.rotate', { ...base.value })
const disconnect = () => run.start('provider.token.revoke', { ...base.value, confirm_name: confirmName.value, delete_user: removeAccount.value, delete_roles: removeAccount.value })
const blocked = computed(() => preview.value?.plan.blocked ?? [])
</script>

<template>
  <details class="ax-maint" :open="!!initial" data-testid="maintenance">
    <summary>Connection maintenance: repair, rotate credentials, clean up leftovers, disconnect</summary>
    <div class="row">
      <button type="button" class="wz-btn" :class="{ primary: what === 'repair' }" @click="pick('repair')">Repair connection</button>
      <button type="button" class="wz-btn" :class="{ primary: what === 'rotate' }" @click="pick('rotate')">Rotate service credentials</button>
      <button type="button" class="wz-btn" :class="{ primary: what === 'cleanup' }" @click="pick('cleanup')">Clean up leftovers</button>
      <button type="button" class="wz-btn" :class="{ primary: what === 'disconnect' }" @click="pick('disconnect')">Disconnect cluster</button>
    </div>
    <template v-if="what === 'repair'">
      <p class="muted small">Puts back exactly the approved permissions (missing roles, ACLs or tokens) and removes extra ones Office Unbound created. It never restores something broader than what was approved, and never touches entries of other users.</p>
      <button v-if="!preview" type="button" class="wz-btn primary" :disabled="run.busy.value" @click="repairPreview">Check what needs repair</button>
      <template v-else>
        <PlanView :preview="preview" />
        <button v-if="!blocked.length" type="button" class="wz-btn primary" :disabled="run.busy.value" @click="repairApply">Request approval and repair</button>
      </template>
    </template>
    <template v-else-if="what === 'rotate'">
      <p class="muted small">Creates new tokens with the same approved rights, tests them, switches Office Unbound over and revokes the old ones. If the new tokens fail, the old ones stay in use.</p>
      <button type="button" class="wz-btn primary" :disabled="run.busy.value" @click="rotate">Request approval and rotate</button>
    </template>
    <template v-else-if="what === 'cleanup'">
      <p class="muted small">Deletes what Office Unbound left on this cluster: golden-image templates a newer import replaced, stopped VMs of destroyed deployments, and the uploaded golden-image files. Your Proxmox sign-in is used for this one job and then discarded; it is not stored. Everything is checked again against the live cluster before anything is deleted.</p>
      <p v-if="leftovers === null" class="muted small">Looking for leftovers…</p>
      <template v-else>
        <p v-if="!removable.length" class="muted small">No leftover VMs or templates found.</p>
        <label v-for="x in removable" :key="x.vmid" class="row"><input v-model="chosen" type="checkbox" :value="x.vmid" /> <b>{{ x.vmid }}</b> {{ x.name }} <span class="muted small">({{ x.template ? 'template' : 'VM' }}: {{ x.why }})</span></label>
        <label class="row"><input v-model="importFiles" type="checkbox" /> Also delete the uploaded golden-image files (<code>ou-golden-*.qcow2</code> in import storage)</label>
        <details v-if="leftovers.length > removable.length" class="small"><summary>Not removable here ({{ leftovers.length - removable.length }})</summary>
          <p v-for="x in leftovers.filter(y => !y.removable)" :key="x.vmid" class="muted small"><b>{{ x.vmid }}</b> {{ x.name }}: {{ x.why }}</p>
        </details>
        <label class="fld"><span>Type the cluster name <b>{{ endpointName }}</b> to confirm</span><input v-model="confirmName" autocomplete="off" /></label>
        <button type="button" class="wz-btn danger" :disabled="run.busy.value || confirmName !== endpointName || (!chosen.length && !importFiles)" @click="cleanup">Request approval and clean up</button>
      </template>
    </template>
    <template v-else-if="what === 'disconnect'">
      <Banner kind="warn" title="Office Unbound stops managing this cluster">Its tokens are revoked and their secrets destroyed. Your VMs, containers and disks are not touched. Other clusters are not affected.</Banner>
      <label class="row"><input v-model="removeAccount" type="checkbox" /> Also remove the Office Unbound service account and roles from Proxmox</label>
      <label class="fld"><span>Type the cluster name <b>{{ endpointName }}</b> to confirm</span><input v-model="confirmName" autocomplete="off" /></label>
      <button type="button" class="wz-btn danger" :disabled="run.busy.value || confirmName !== endpointName" @click="disconnect">Request approval and disconnect</button>
    </template>
    <RunPanel v-if="run.created.value || run.error.value" :run="run" :what="what === 'repair' ? 'Repair' : what === 'rotate' ? 'Credential rotation' : what === 'cleanup' ? 'Cleanup' : 'Disconnect'" />
    <Banner v-if="run.job.value?.status === 'succeeded'" kind="ok" title="Done">{{ what === 'disconnect' ? 'The cluster was disconnected.' : what === 'rotate' ? 'New credentials are in use; the old ones were revoked.' : what === 'cleanup' ? 'The leftovers were removed; the sign-in was discarded.' : 'The approved permissions are in place again.' }}</Banner>
  </details>
</template>

<style scoped>
.ax-maint { border: 1px solid var(--line); border-radius: 8px; padding: 10px 14px; display: grid; gap: 10px; }
.ax-maint summary { cursor: pointer; font-weight: 600; }
.row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 8px 0; }
.fld { display: grid; gap: 4px; max-width: 420px; }
</style>
