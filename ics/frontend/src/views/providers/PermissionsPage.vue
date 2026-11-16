<script setup lang="ts">
// Permissions: who Office Unbound is in Proxmox, what it may do, and whether reality still matches what was approved.
import { computed, ref } from 'vue'
import { useLoad, hasRole } from '../../store'
import { ago } from '../../format'
import Card from '../../ui/Card.vue'
import Button from '../../ui/Button.vue'
import EmptyState from '../../ui/EmptyState.vue'
import ErrorBox from '../../components/ErrorBox.vue'
import { Banner, HelpNote } from '../../wizards/kit'
import ClusterHeader from './ClusterHeader.vue'
import ActionFlow, { type FlowKind } from './ActionFlow.vue'
import ScopeChangeFlow from './ScopeChangeFlow.vue'
import { api, load, msg } from './api'
import { PRESETS, SCOPE_MODE_LABEL, TYPE_LABEL, driftItems, policyStatus, type DriftReport } from './model'
import './providers.css'

const props = defineProps<{ id: string }>()
const data = useLoad(async () => {
  const ep = await api.endpoint(props.id)
  const p = await load(() => api.permissions(props.id))
  return { ep, perms: p.state === 'ok' ? p.data : null, state: p.state }
}, 60000)
const d = computed(() => data.data.value)
const v = computed(() => d.value?.perms ?? null)
const status = computed(() => policyStatus(v.value))
const flow = ref<FlowKind | null>(null)
const scopeFlow = ref(false)
const scopeMode = computed(() => (v.value?.scope_mode ? SCOPE_MODE_LABEL[v.value.scope_mode] ?? v.value.scope_mode : 'Not recorded'))
const scopeNotes = computed(() => (v.value?.scope_enforcement ?? []))
const icsDrift = computed(() => (report.value?.ics_scope && !report.value.ics_scope.ok ? report.value.ics_scope : null))
const checking = ref(false), checkError = ref(''), checked = ref<DriftReport | null>(null)
const report = computed<DriftReport | null>(() => checked.value ?? v.value?.last_drift ?? null)
const items = computed(() => driftItems(report.value))
const preset = computed(() => PRESETS.find((p) => p.id === v.value?.preset))
const canOperate = computed(() => hasRole('operator'))
const canAdmin = computed(() => hasRole('admin'))
const aclRows = computed(() => Object.entries(v.value?.expected ?? {}).flatMap(([kind, paths]) => Object.entries(paths).map(([path, privs]) => ({ kind, path, privs }))).sort((a, b) => a.path.localeCompare(b.path)))
const scopeRows = computed(() => { const s = v.value?.scope ?? {}; return [['Nodes', s.nodes], ['Pools', s.pools], ['Storage', s.storages], ['Networks', s.networks], ['Templates', s.template_vmids], ['Backup storage', s.backup_storages]] as [string, (string | number)[] | undefined][] })
const icsLimits = computed(() => { const s = v.value?.scope; if (!s) return [] as string[]; return [s.vmid_ranges?.length ? `VMID ranges: ${s.vmid_ranges.map((r) => r.join('-')).join(', ')}` : '', s.max_cores ? `Max ${s.max_cores} cores per VM` : '', s.max_memory_mb ? `Max ${s.max_memory_mb} MB memory per VM` : '', s.max_disk_gb ? `Max ${s.max_disk_gb} GB disk per VM` : '', s.guest_types ? `Guest types: ${s.guest_types.join(', ')}` : ''].filter(Boolean) })
async function validate() {
  checking.value = true; checkError.value = ''
  try { checked.value = (await api.checkPermissions(props.id)) as DriftReport; await data.reload() } catch (e) { checkError.value = msg(e) } finally { checking.value = false }
}
function closeFlow() { flow.value = null; checked.value = null; void data.reload() }
const tone = (t: string) => t
</script>

<template>
  <div class="pv">
    <ClusterHeader :id="id" :ep="d?.ep ?? null" />
    <ErrorBox v-if="data.error.value" :error="data.error.value" />
    <template v-if="d">
      <EmptyState v-if="d.state === 'unavailable'" icon="shield" title="Permission management is not available on this server" text="This ICS version does not provide the provisioning API." />
      <template v-else-if="v">
        <div class="card pv-statusrow">
          <div><span class="badge" :class="tone(status.tone)">{{ status.text }}</span><p class="muted small">{{ status.detail }}</p></div>
          <div class="muted small"><div>Last verified: <b>{{ v.last_verified_at ? ago(v.last_verified_at) : 'never' }}</b></div><div>Last drift check: <b>{{ v.last_drift_at ? ago(v.last_drift_at) : 'never' }}</b></div></div>
          <div class="row">
            <Button size="sm" :loading="checking" :disabled="!canOperate || !v.managed_by_provisioning" @click="validate">Run validation</Button>
            <Button size="sm" variant="primary" :disabled="!canAdmin || !v.managed_by_provisioning" @click="scopeFlow = true">Change scope</Button>
            <Button size="sm" :disabled="!canAdmin" :to="`/infrastructure/providers/proxmox/connect-ssh?endpoint=${id}`">Change with SSH</Button>
            <Button size="sm" :disabled="!canAdmin" :to="`/infrastructure/providers/proxmox/connect-ssh?endpoint=${id}&offboard=1`">Remove SSH-created access</Button>
            <Button size="sm" :disabled="!canAdmin || !v.managed_by_provisioning" @click="flow = 'change'">Change access</Button>
            <Button size="sm" :disabled="!canAdmin || !v.managed_by_provisioning" @click="flow = 'rotate'">Rotate tokens</Button>
            <Button size="sm" variant="danger" :disabled="!canAdmin || !v.managed_by_provisioning" @click="flow = 'revoke'">Revoke</Button>
          </div>
        </div>
        <Banner v-if="checkError" kind="bad" title="Validation failed">{{ checkError }}</Banner>
        <Banner v-if="!v.managed_by_provisioning" kind="info" title="Permissions are managed outside Office Unbound">{{ v.note }} To get drift detection, reconciliation and rotation, reconnect this cluster with "Set it up for me" or a setup package.</Banner>

        <template v-if="v.managed_by_provisioning">
          <Banner v-if="icsDrift" kind="bad" title="Office Unbound's own limits differ from the approved scope">{{ icsDrift.note }} Nodes approved: {{ icsDrift.nodes.policy.join(', ') || 'none' }}; in force: {{ icsDrift.nodes.endpoint.join(', ') || 'none' }}. <span class="muted">(Enforced by Office Unbound)</span></Banner>
          <Card title="Scope" hint="How much of the cluster this integration may reach">
            <dl class="pv-dl"><dt>Scope</dt><dd><b>{{ scopeMode }}</b><span v-if="v.scope_mode === 'single_node'" class="badge ok">Recommended for security</span></dd>
              <dt>Nodes</dt><dd>{{ v.scope_mode === 'whole_cluster' ? 'All nodes (' + (v.scope?.nodes?.length ?? 0) + ' found when set)' : (v.scope?.nodes ?? []).join(', ') || 'none' }}</dd>
              <dt>Storage</dt><dd>{{ [...(v.scope?.storages ?? []), ...(v.scope?.backup_storages ?? [])].join(', ') || 'none' }}</dd></dl>
            <div class="pv-enf"><div class="pv-enf-col" data-who="proxmox"><h4>Held by Proxmox</h4><ul class="pv-list small"><li v-for="e in scopeNotes.filter((x) => x.enforced_by === 'proxmox')" :key="e.control"><b>{{ e.control }}</b><div class="muted small">{{ e.detail }}</div></li></ul></div>
              <div class="pv-enf-col" data-who="ics"><h4>Held by Office Unbound (also)</h4><ul class="pv-list small"><li v-for="e in scopeNotes.filter((x) => x.enforced_by === 'ics' || x.enforced_by === 'both')" :key="e.control"><b>{{ e.control }}</b><div class="muted small">{{ e.detail }}</div></li></ul></div></div>
            <p v-if="!scopeNotes.length" class="muted small">This integration was set up before scope modes existed. Use Change scope to choose one node or the whole cluster.</p>
          </Card>
          <Card v-if="items.length || (report && !report.ok)" title="Drift: expected versus actual" hint="Proxmox no longer matches what was approved">
            <Banner v-if="report?.error" kind="bad" :title="report.error_code === 'token_failed' ? 'The token is rejected' : 'The check could not complete'">{{ report.error }}</Banner>
            <div v-if="items.length" class="tablewrap"><table class="pv-table"><thead><tr><th>Difference</th><th>Token</th><th>Where</th><th>Privileges</th><th>Suggested correction</th></tr></thead><tbody>
              <tr v-for="(i, n) in items" :key="n"><td><span class="badge" :class="i.type === 'missing' ? 'warn' : 'bad'">{{ TYPE_LABEL[i.type] }}</span></td><td>{{ i.kind }}</td><td class="mono">{{ i.path }}</td><td class="mono">{{ i.privileges.join(', ') }}</td><td>{{ i.suggestion }}</td></tr></tbody></table></div>
            <div class="row mt"><Button variant="primary" size="sm" :disabled="!canAdmin" @click="flow = 'reconcile'">Reconcile to the approved policy</Button><span class="muted small">Shows the exact changes first. It never grants more than was approved.</span></div>
          </Card>
          <Banner v-else kind="ok" title="No drift">The permissions Proxmox reports for the tokens match the approved policy.</Banner>

          <div class="grid cols-2">
            <Card title="Service account and tokens">
              <dl class="pv-dl"><dt>Account</dt><dd class="mono">{{ v.service_user }}</dd><dt>Created by</dt><dd>{{ v.mode === 'A' ? 'Office Unbound (automatic)' : 'Customer-run script' }}</dd><dt>Access level</dt><dd>{{ preset?.title ?? v.preset }}</dd></dl>
              <div class="tablewrap"><table class="pv-table"><thead><tr><th>Token</th><th>Purpose</th><th>Generation</th><th>Status</th></tr></thead><tbody>
                <tr v-for="(t, k) in v.tokens" :key="k"><td class="mono">{{ t.id }}</td><td>{{ k === 'inventory' ? 'Read inventory' : 'Create and change VMs' }}</td><td>{{ t.gen ?? 1 }}</td><td><span class="badge" :class="v.status === 'token_failed' ? 'bad' : 'ok'">{{ v.status === 'token_failed' ? 'Rejected' : v.status === 'revoked' ? 'Revoked' : 'Active' }}</span></td></tr></tbody></table></div>
              <p class="muted small">Tokens are privilege-separated: effective rights are the intersection of the account's and the token's permissions. Secrets are never shown here.</p>
            </Card>
            <Card title="Roles">
              <div v-for="(r, cap) in v.roles" :key="cap" class="pv-res"><div class="wz-row"><b class="mono">{{ r.name }}</b><span class="muted small">{{ cap }}</span></div>
                <HelpNote :title="r.privileges.length + ' privileges'"><span v-for="p in r.privileges" :key="p" class="pv-priv mono">{{ p }}</span></HelpNote></div>
            </Card>
          </div>

          <Card title="Effective grants" hint="Every role on every path, who carries it and who enforces it">
            <div class="tablewrap"><table class="pv-table"><thead><tr><th>Path</th><th>Role</th><th>Privileges</th><th>Propagates</th><th>Held by</th><th>Enforced by</th></tr></thead><tbody>
              <tr v-for="(g, n) in v.grants ?? []" :key="n"><td class="mono">{{ g.path }}</td><td class="mono small">{{ g.role }}</td><td class="mono small">{{ g.privileges.join(', ') || '-' }}</td><td>{{ g.propagate ? 'yes' : 'no' }}</td><td class="small">{{ g.tokens.join(', ') || '-' }}</td><td><span class="badge" :class="g.enforced_by === 'proxmox' ? 'ok' : 'info'">{{ g.enforced_by === 'proxmox' ? 'Proxmox' : 'Office Unbound' }}</span><div class="muted small">{{ g.note }}</div></td></tr>
              <tr v-if="!(v.grants ?? []).length"><td colspan="6" class="muted">No grants recorded.</td></tr></tbody></table></div>
          </Card>
          <Card title="Permission paths per token (expected)" hint="Where each token holds privileges">
            <div class="tablewrap"><table class="pv-table"><thead><tr><th>Path</th><th>Token</th><th>Privileges</th></tr></thead><tbody>
              <tr v-for="(r, n) in aclRows" :key="n"><td class="mono">{{ r.path }}</td><td>{{ r.kind }}</td><td class="mono small">{{ r.privs.join(', ') }}</td></tr>
              <tr v-if="!aclRows.length"><td colspan="3" class="muted">No ACL entries recorded.</td></tr></tbody></table></div>
          </Card>

          <div class="grid cols-2">
            <Card title="Authorised resources">
              <dl class="pv-dl"><template v-for="[label, list] in scopeRows" :key="label"><dt>{{ label }}</dt><dd>{{ list?.length ? list.join(', ') : 'none' }}</dd></template></dl>
              <template v-if="icsLimits.length"><h3 class="pv-h3">Limits Office Unbound applies itself</h3><ul class="pv-list small"><li v-for="l in icsLimits" :key="l">{{ l }}</li></ul></template>
            </Card>
            <Card title="Allowed and restricted">
              <h3 class="pv-h3">Allowed</h3><ul class="pv-list small"><li v-for="c in preset?.can ?? []" :key="c" class="pv-yes">{{ c }}</li></ul>
              <h3 class="pv-h3">Restricted</h3><ul class="pv-list small"><li v-for="c in preset?.cannot ?? []" :key="c" class="pv-no">{{ c }}</li><li v-for="n in v.never_granted ?? []" :key="n" class="pv-no">Never granted: <span class="mono">{{ n }}</span></li></ul>
            </Card>
          </div>

          <Card title="Who enforces what" hint="Be sure you know which limits survive a compromise of Office Unbound">
            <div class="pv-enf">
              <div class="pv-enf-col" data-who="proxmox"><h4>Enforced by Proxmox</h4><ul class="pv-list"><li v-for="e in (v.enforcement ?? []).filter((x) => x.enforced_by === 'proxmox' || x.enforced_by === 'both')" :key="e.control"><b>{{ e.control }}</b><div class="muted small">{{ e.detail }}</div></li></ul></div>
              <div class="pv-enf-col" data-who="ics"><h4>Enforced by Office Unbound only</h4><ul class="pv-list"><li v-for="e in (v.enforcement ?? []).filter((x) => x.enforced_by === 'ics')" :key="e.control"><b>{{ e.control }}</b><div class="muted small">{{ e.detail }}</div></li></ul></div>
              <div v-if="(v.enforcement ?? []).some((x) => x.enforced_by === 'not_enforced')" class="pv-enf-col" data-who="none"><h4>Not enforced yet</h4><ul class="pv-list"><li v-for="e in (v.enforcement ?? []).filter((x) => x.enforced_by === 'not_enforced')" :key="e.control"><b>{{ e.control }}</b><div class="muted small">{{ e.detail }}</div></li></ul></div>
            </div>
          </Card>
        </template>
      </template>
      <ScopeChangeFlow v-if="scopeFlow && v" :endpoint-id="id" :name="d.ep.name" :view="v" @close="scopeFlow = false; void data.reload()" @done="data.reload" />
      <ActionFlow v-if="flow && v" :kind="flow" :endpoint-id="id" :name="d.ep.name" :view="v" @close="closeFlow" @done="data.reload" />
    </template>
  </div>
</template>
