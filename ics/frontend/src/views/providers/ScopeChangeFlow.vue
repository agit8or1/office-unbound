<script setup lang="ts">
// Change scope: one node <-> more nodes <-> whole cluster, add/remove storage. Preview first (before/after, permission diff, impact), then either
// apply it with a temporary administrator login (Mode A) or hand a script to the cluster owner (Mode B) and confirm afterwards.
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import Drawer from '../../ui/Drawer.vue'
import { Banner, Field, HelpNote } from '../../wizards/kit'
import type { Errors } from '../../wizards/kit'
import ChipList from './ChipList.vue'
import CredFields from './CredFields.vue'
import RunPanel from './RunPanel.vue'
import { api, packageUrl } from './api'
import {
  DIRECTION_TEXT, ENFORCER_LABEL, SCOPE_MODES, SCOPE_MODE_LABEL, SINGLE_NODE_NOTES, adminCreds, mergeStorage, newModel, newSecrets, scopeChangeParams, scopePackageParams, scopePreviewOf, scopePreviewParams,
  scopeTargetOf, scopeTargetValid, storageLocality, validateCreds, wipeAdmin, type PermissionsView, type ScopeMode, type ScopePreviewOut, type WizardModel, type InfraNode, type InfraStorage,
} from './model'
import { useRun } from './run'
import './providers.css'

const props = defineProps<{ endpointId: string; name: string; view: PermissionsView }>()
const emit = defineEmits<{ close: []; done: [] }>()

const cur = props.view.scope ?? {}
const startMode: ScopeMode = props.view.scope_mode === 'whole_cluster' ? 'whole_cluster' : 'single_node'
const mode = ref<ScopeMode>(startMode)
const nodesSel = ref<string[]>([...(cur.nodes ?? [])])
const storages = ref<string[]>([...(cur.storages ?? [])])
const overrides = ref<string[]>([...(props.view.scope_risk_overrides ?? [])])
const detach = ref(false)
const m = reactive(newModel()) as WizardModel
m.method = 'admin'
const s = newSecrets()
onBeforeUnmount(() => wipeAdmin(s))

const nodes = ref<InfraNode[]>([]), stor = ref<InfraStorage[]>([]), loading = ref(true)
onMounted(async () => {
  try { [nodes.value, stor.value] = await Promise.all([api.nodes(props.endpointId), api.storage(props.endpointId)]) } catch { /* the plain lists below still work */ } finally { loading.value = false }
})
const storageRows = computed(() => mergeStorage(stor.value.map((x) => ({ ...x, content: x.content ?? [] })) as never).map((r) => ({ ...r, loc: storageLocality(r, nodesSel.value) })))
function toggle(list: string[], v: string) { const i = list.indexOf(v); if (i >= 0) list.splice(i, 1); else list.push(v) }
function pickNode(n: string) { if (mode.value === 'single_node') nodesSel.value = [n] }
function setMode(x: ScopeMode) { mode.value = x; if (x === 'single_node' && !nodesSel.value.length && nodes.value.length) nodesSel.value = [nodes.value.find((n) => n.managed)?.name ?? nodes.value[0]!.name] }

const stage = ref<'target' | 'review'>('target')
const errors = ref<Errors>({})
const previewRun = useRun(), run = useRun(), pkgRun = useRun()
const preview = ref<ScopePreviewOut | null>(null)
const route = ref<'a' | 'b'>('a')
const packageId = ref<string | null>(null)
const ack = ref(false), done = ref(false)
const target = computed(() => scopeTargetOf(props.view, mode.value, nodesSel.value, storages.value, overrides.value, detach.value))
const unchanged = computed(() => JSON.stringify([mode.value, mode.value === 'single_node' ? [...nodesSel.value].sort() : [], [...storages.value].sort()]) === JSON.stringify([startMode, startMode === 'single_node' ? [...(cur.nodes ?? [])].sort() : [], [...(cur.storages ?? [])].sort()]))

async function doPreview() {
  const e: Errors = {}
  const bad = scopeTargetValid(target.value)
  if (bad) e.nodes = bad
  Object.assign(e, validateCreds(m, s))
  errors.value = e
  if (Object.keys(e).length) return
  preview.value = null
  const job = await previewRun.start('provider.provision.plan_preview', scopePreviewParams(props.endpointId, target.value, adminCreds(m, s)) as unknown as Record<string, unknown>)
  wipeAdmin(s)
  const p = job?.status === 'succeeded' ? scopePreviewOf(job) : null
  if (p) { preview.value = p; stage.value = 'review'; ack.value = false }
}
const blocked = computed(() => preview.value?.blocked ?? [])
const high = computed(() => preview.value?.risk === 'high')
const dirText = computed(() => (preview.value ? DIRECTION_TEXT[preview.value.direction] : null))
const label = (e: { enforced_by: string }) => ENFORCER_LABEL[e.enforced_by as keyof typeof ENFORCER_LABEL] ?? e.enforced_by
const caps = computed(() => preview.value?.scope.impact.capacity ?? [])

async function submitA() {
  const e = validateCreds(m, s)
  if (high.value && !ack.value) e.ack = 'Confirm that you have reviewed the change.'
  errors.value = e
  if (Object.keys(e).length || !preview.value) return
  const j = await run.start('provider.scope.change', scopeChangeParams(props.endpointId, preview.value, 'mode_a', adminCreds(m, s)) as unknown as Record<string, unknown>)
  wipeAdmin(s)
  if (j?.status === 'succeeded') { done.value = true; emit('done') }
}
async function makePackage() {
  if (!preview.value) return
  const j = await pkgRun.start('provider.scope.package', scopePackageParams(props.endpointId, preview.value) as unknown as Record<string, unknown>)
  const r = j?.status === 'succeeded' ? (j.result as { package_id?: string } | null) : null
  if (r?.package_id) packageId.value = r.package_id
}
async function confirmPackage() {
  if (!preview.value || !packageId.value) return
  const j = await run.start('provider.scope.change', scopeChangeParams(props.endpointId, preview.value, 'confirm_package', {}, packageId.value) as unknown as Record<string, unknown>)
  if (j?.status === 'succeeded') { done.value = true; emit('done') }
}
const fmtNodes = (n: string[], mode_: string) => (mode_ === 'whole_cluster' ? `all nodes (${n.length} found)` : n.join(', ') || '(none)')
</script>

<template>
  <Drawer :title="'Change scope - ' + name" @close="emit('close')">
    <div class="wz pv-flow">
      <template v-if="stage === 'target'">
        <p class="muted">Decide how much of the cluster Office Unbound may reach. You see exactly what changes in Proxmox, and what is held by Proxmox versus by Office Unbound, before anything is submitted.</p>
        <p v-if="loading" class="muted">Looking at the cluster...</p>
        <div class="wz-cards" role="radiogroup" aria-label="Scope">
          <button v-for="o in SCOPE_MODES" :key="o.id" type="button" class="wz-pick" role="radio" :aria-checked="mode === o.id" :aria-pressed="mode === o.id" @click="setMode(o.id)">
            <span class="wz-row"><b>{{ o.title }}</b><span v-if="o.id === startMode" class="wz-chip">current</span></span>
            <span class="muted small">{{ o.blurb }}</span>
          </button>
        </div>
        <div v-if="mode === 'single_node'" class="wz-card">
          <h2>Which node{{ nodesSel.length > 1 ? 's' : '' }}?</h2>
          <div v-if="nodes.length" class="pv-pick"><label v-for="n in nodes" :key="n.name" class="wz-choice pv-opt"><input :type="'radio'" name="sc-node" :checked="nodesSel.includes(n.name)" @change="pickNode(n.name)" /><span><b>{{ n.name }}</b> <span class="wz-chip" :class="n.status === 'online' ? 'ok' : 'warn'">{{ n.status }}</span></span></label></div>
          <ChipList v-else v-model="nodesSel" label="Node names" placeholder="Node name, press Enter" />
          <HelpNote title="Advanced: more than one node">
            <div v-if="nodes.length" class="pv-pick"><label v-for="n in nodes" :key="n.name" class="wz-choice pv-opt"><input type="checkbox" :checked="nodesSel.includes(n.name)" @change="toggle(nodesSel, n.name)" /><span><b>{{ n.name }}</b></span></label></div>
          </HelpNote>
          <p v-if="errors.nodes" class="bad-text" role="alert">{{ errors.nodes }}</p>
          <ul class="pv-list small"><li v-for="n in SINGLE_NODE_NOTES" :key="n">{{ n }}</li></ul>
        </div>
        <div class="wz-card">
          <h2>Storage</h2>
          <p class="muted small">Disks may only be placed here. <template v-if="mode === 'single_node'">In one-node mode a storage must exist only on the chosen node(s); shared storage is refused.</template></p>
          <div class="pv-pick"><label v-for="r in storageRows" :key="r.name" class="wz-choice pv-opt pv-wide" :class="{ 'pv-disabled': mode === 'single_node' && !r.loc.local && !storages.includes(r.name) }">
            <input type="checkbox" :checked="storages.includes(r.name)" :disabled="mode === 'single_node' && !r.loc.local" @change="toggle(storages, r.name)" />
            <span><b>{{ r.name }}</b> <span class="muted small">{{ r.type }}<template v-if="r.shared"> &middot; shared</template></span>
              <span v-if="mode === 'single_node' && !r.loc.local" class="wz-chip warn">not available in one-node mode</span><span v-if="mode === 'single_node'" class="muted small"> {{ r.loc.reason }}</span></span></label></div>
          <Field label="Add a storage by name" optional v-slot="{ id }"><ChipList :id="id" :model-value="[]" label="Storage" placeholder="Storage name, press Enter" @update:model-value="(v) => v.forEach((x) => { if (!storages.includes(x)) storages.push(x) })" /></Field>
          <HelpNote v-if="mode === 'single_node'" title="Advanced: guests that would be left outside the scope">
            <label class="wz-choice"><input v-model="detach" type="checkbox" /> If narrowing would leave Office Unbound-managed VMs on other nodes, detach them (Office Unbound stops managing them; they keep running). Needs separate approval.</label>
          </HelpNote>
        </div>
        <h3>Check the cluster now</h3>
        <p class="muted small">A read-only check with a temporary administrator login that is discarded straight after. Nothing is changed yet.</p>
        <CredFields :m="m" :s="s" :errors="errors" />
        <div class="wz-row mt"><button type="button" class="wz-btn primary" :disabled="previewRun.busy.value || unchanged" @click="doPreview">{{ previewRun.busy.value ? 'Working it out...' : 'Preview the change' }}</button><button type="button" class="wz-btn" @click="emit('close')">Cancel</button></div>
        <p v-if="unchanged" class="muted small">Nothing differs from the current scope yet.</p>
        <RunPanel :run="previewRun" what="Computing the scope change" />
      </template>

      <template v-else-if="preview">
        <Banner :kind="blocked.length ? 'bad' : high ? 'warn' : 'info'" :title="dirText?.title ?? ''">{{ dirText?.text }}</Banner>
        <Banner v-for="b in blocked" :key="b" kind="bad" title="Cannot be done as it stands">{{ b }}</Banner>

        <h3>Before and after</h3>
        <div class="wz-table-wrap"><table class="pv-table"><thead><tr><th>Setting</th><th>Now</th><th>After</th></tr></thead><tbody>
          <tr><td>Scope</td><td>{{ SCOPE_MODE_LABEL[preview.scope.old_scope.mode] ?? preview.scope.old_scope.mode }}</td><td><b>{{ SCOPE_MODE_LABEL[preview.scope.new_scope.mode] }}</b></td></tr>
          <tr><td>Nodes</td><td>{{ fmtNodes(preview.scope.old_scope.nodes, preview.scope.old_scope.mode) }}</td><td><b>{{ fmtNodes(preview.scope.new_scope.nodes, preview.scope.new_scope.mode) }}</b></td></tr>
          <tr><td>Storage</td><td>{{ preview.scope.old_scope.storages.join(', ') || '(none)' }}</td><td><b>{{ preview.scope.new_scope.storages.join(', ') || '(none)' }}</b></td></tr>
        </tbody></table></div>

        <h3>Permissions that change in Proxmox</h3>
        <div class="wz-table-wrap"><table class="pv-table"><thead><tr><th>Change</th><th>Where</th><th>Role</th><th>Held by</th><th>Enforced by</th></tr></thead><tbody>
          <tr v-for="r in preview.scope.diff.acl_add" :key="'a' + r.path + r.role"><td><span class="wz-chip warn">Add</span></td><td class="mono">{{ r.path }}<span v-if="r.propagate" class="muted small"> (and below)</span></td><td class="mono small">{{ r.role }}</td><td class="small">{{ r.subjects.join(', ') }}</td><td><span class="wz-chip ok">{{ label(r) }}</span></td></tr>
          <tr v-for="r in preview.scope.diff.acl_remove" :key="'r' + r.path + r.role"><td><span class="wz-chip info">Remove</span></td><td class="mono">{{ r.path }}</td><td class="mono small">{{ r.role }}</td><td class="small">{{ r.subjects.join(', ') }}</td><td><span class="wz-chip ok">{{ label(r) }}</span></td></tr>
          <tr v-for="r in preview.scope.diff.roles" :key="r.role"><td><span class="wz-chip warn">Role</span></td><td colspan="2" class="mono small">{{ r.role }}: {{ r.change }}<template v-if="r.added?.length"> +{{ r.added.join(', ') }}</template><template v-if="r.removed?.length"> -{{ r.removed.join(', ') }}</template></td><td></td><td><span class="wz-chip ok">Enforced by Proxmox</span></td></tr>
          <tr><td><span class="wz-chip info">Allowlist</span></td><td colspan="2" class="small">Office Unbound node allowlist: {{ preview.scope.diff.ics_allowlist.nodes.before.join(', ') || '(none)' }} &rarr; {{ preview.scope.diff.ics_allowlist.nodes.after.join(', ') }}<br />Storage allowlist: {{ preview.scope.diff.ics_allowlist.storages.before.join(', ') || '(none)' }} &rarr; {{ preview.scope.diff.ics_allowlist.storages.after.join(', ') || '(none)' }}</td><td></td><td><span class="wz-chip info">Enforced by Office Unbound</span></td></tr>
          <tr v-if="!preview.scope.diff.acl_add.length && !preview.scope.diff.acl_remove.length && !preview.scope.diff.roles.length"><td colspan="5" class="muted">No permission changes in Proxmox.</td></tr>
        </tbody></table></div>

        <h3>Impact</h3>
        <div class="wz-table-wrap"><table class="pv-table"><thead><tr><th>Node</th><th>CPU</th><th>Memory</th><th>After the change</th></tr></thead><tbody>
          <tr v-for="c in caps" :key="c.node"><td class="mono">{{ c.node }}</td><td>{{ c.cpus ?? 'unknown' }}</td><td>{{ c.mem_gib ? c.mem_gib + ' GiB' : 'unknown' }}</td>
            <td><span class="wz-chip" :class="c.change === 'added' ? 'warn' : c.change === 'removed' ? 'info' : c.change === 'kept' ? 'ok' : ''">{{ { added: 'becomes visible and usable', removed: 'no longer visible', kept: 'stays', outside: 'stays out of reach' }[c.change] }}</span></td></tr>
        </tbody></table></div>
        <template v-if="preview.scope.impact.managed_guests_outside.length">
          <Banner kind="warn" :title="preview.scope.impact.managed_guests_outside.length + ' managed VM(s) would fall outside the new scope'">
            <ul class="pv-list small"><li v-for="g in preview.scope.impact.managed_guests_outside" :key="g.vmid"><b>{{ g.vmid }} {{ g.name }}</b>: {{ g.why.join('; ') }}</li></ul>
            <p class="small">Move or remove them first, or go back and choose "detach" under Advanced (separate approval).</p>
          </Banner>
        </template>
        <ul v-if="preview.scope.impact.notes.length" class="pv-list small"><li v-for="n in preview.scope.impact.notes" :key="n">{{ n }}</li></ul>

        <h3>Who enforces what after the change</h3>
        <div class="pv-enf">
          <div class="pv-enf-col" data-who="proxmox"><h4>Enforced by Proxmox</h4><ul class="pv-list"><li v-for="e in preview.scope.enforcement_after.filter((x) => x.enforced_by === 'proxmox' || x.enforced_by === 'both')" :key="e.control"><b>{{ e.control }}</b><div class="muted small">{{ e.detail }}</div></li></ul></div>
          <div class="pv-enf-col" data-who="ics"><h4>Enforced by Office Unbound only</h4><ul class="pv-list"><li v-for="e in preview.scope.enforcement_after.filter((x) => x.enforced_by === 'ics')" :key="e.control"><b>{{ e.control }}</b><div class="muted small">{{ e.detail }}</div></li></ul></div>
        </div>

        <div v-if="!done && !blocked.length" class="wz-card mt">
          <h3>Apply it</h3>
          <div class="wz-row"><label class="wz-choice"><input v-model="route" type="radio" value="a" /> Office Unbound applies it now (temporary administrator login)</label><label class="wz-choice"><input v-model="route" type="radio" value="b" /> The cluster owner runs a script</label></div>
          <template v-if="route === 'a'">
            <CredFields :m="m" :s="s" :errors="errors" />
            <label v-if="high" class="wz-choice mt"><input v-model="ack" type="checkbox" /> <span>I have reviewed the change and want to submit it for approval.</span></label>
            <p v-if="errors.ack" class="bad-text" role="alert">{{ errors.ack }}</p>
            <div class="wz-row mt"><button type="button" class="wz-btn primary" :disabled="run.busy.value" @click="submitA">{{ run.busy.value ? 'Working...' : 'Submit' }}</button><button type="button" class="wz-btn" @click="stage = 'target'">Back</button></div>
            <RunPanel :run="run" what="Changing the scope" />
          </template>
          <template v-else>
            <p class="muted small">Creates a script that makes exactly this change. Running it twice changes nothing the second time. It contains no passwords or secrets.</p>
            <div class="wz-row"><button v-if="!packageId" type="button" class="wz-btn primary" :disabled="pkgRun.busy.value" @click="makePackage">{{ pkgRun.busy.value ? 'Preparing...' : 'Prepare the script' }}</button><button type="button" class="wz-btn" @click="stage = 'target'">Back</button></div>
            <RunPanel :run="pkgRun" what="Preparing the script" />
            <template v-if="packageId">
              <p class="small">Give these files to the cluster owner: <a :href="packageUrl(endpointId, packageId, 'zip')">scope package (zip)</a> &middot; <a :href="packageUrl(endpointId, packageId, 'report.html')" target="_blank" rel="noopener">report</a>. They run <span class="mono">provision.sh</span> as root on one node (<span class="mono">rollback.sh</span> restores the old scope).</p>
              <p class="small">When they have done it, confirm here. Office Unbound then checks what Proxmox really allows and only then updates its own limits.</p>
              <div class="wz-row"><button type="button" class="wz-btn primary" :disabled="run.busy.value" @click="confirmPackage">{{ run.busy.value ? 'Checking Proxmox...' : 'They ran it: verify and apply' }}</button></div>
              <RunPanel :run="run" what="Verifying the new scope" />
            </template>
          </template>
        </div>
        <div v-else-if="blocked.length" class="wz-row mt"><button type="button" class="wz-btn" @click="stage = 'target'">Back</button></div>
        <Banner v-if="done" kind="ok" title="Scope changed">Proxmox was verified against the new scope, then the Office Unbound limits were updated. Run a validation on the permissions page to see the result.<div class="mt"><button type="button" class="wz-btn" @click="emit('close')">Close</button></div></Banner>
      </template>
    </div>
  </Drawer>
</template>
