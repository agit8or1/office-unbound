<script setup lang="ts">
// Manage access > connection maintenance, using the wizard's Proxmox sign-in: repair drifted permissions, rotate the service tokens, disconnect.
// Each is an approval-gated typed action; nothing here deletes a VM, a disk or anything Office Unbound did not create.
import { computed, ref } from 'vue'
import { Banner } from '../../../wizards/kit'
import { useRun } from '../run'
import RunPanel from '../RunPanel.vue'
import PlanView from '../PlanView.vue'
import type { PlanPreviewOut } from '../model'

const props = defineProps<{ endpointId: string; sessionId: string; endpointName: string }>()
const what = ref<'' | 'repair' | 'rotate' | 'disconnect'>('')
const run = useRun()
const preview = ref<PlanPreviewOut | null>(null)
const confirmName = ref('')
const removeAccount = ref(false)
const base = computed(() => ({ endpoint_id: props.endpointId, admin_session: props.sessionId }))

function pick(w: typeof what.value) { what.value = w; preview.value = null; run.reset(); confirmName.value = '' }
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
  <details class="ax-maint">
    <summary>Connection maintenance: repair, rotate credentials, disconnect</summary>
    <div class="row">
      <button type="button" class="wz-btn" :class="{ primary: what === 'repair' }" @click="pick('repair')">Repair connection</button>
      <button type="button" class="wz-btn" :class="{ primary: what === 'rotate' }" @click="pick('rotate')">Rotate service credentials</button>
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
    <template v-else-if="what === 'disconnect'">
      <Banner kind="warn" title="Office Unbound stops managing this cluster">Its tokens are revoked and their secrets destroyed. Your VMs, containers and disks are not touched. Other clusters are not affected.</Banner>
      <label class="row"><input v-model="removeAccount" type="checkbox" /> Also remove the Office Unbound service account and roles from Proxmox</label>
      <label class="fld"><span>Type the cluster name <b>{{ endpointName }}</b> to confirm</span><input v-model="confirmName" autocomplete="off" /></label>
      <button type="button" class="wz-btn danger" :disabled="run.busy.value || confirmName !== endpointName" @click="disconnect">Request approval and disconnect</button>
    </template>
    <RunPanel v-if="run.created.value || run.error.value" :run="run" :what="what === 'repair' ? 'Repair' : what === 'rotate' ? 'Credential rotation' : 'Disconnect'" />
    <Banner v-if="run.job.value?.status === 'succeeded'" kind="ok" title="Done">{{ what === 'disconnect' ? 'The cluster was disconnected.' : what === 'rotate' ? 'New credentials are in use; the old ones were revoked.' : 'The approved permissions are in place again.' }}</Banner>
  </details>
</template>

<style scoped>
.ax-maint { border: 1px solid var(--border, #d0d5dd); border-radius: 8px; padding: 10px 14px; display: grid; gap: 10px; }
.ax-maint summary { cursor: pointer; font-weight: 600; }
.row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 8px 0; }
.fld { display: grid; gap: 4px; max-width: 420px; }
</style>
