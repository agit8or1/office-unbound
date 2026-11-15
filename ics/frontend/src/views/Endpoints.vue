<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { ApiError, post, type Endpoint, type PlanCreated } from '../api'
import { get } from '../api'
import { fmtTime, hasRole, useLoad } from '../store'
import { ago } from '../format'
import { loadDeployments, type Deployment } from '../infra'
import { hasPath } from '../router'
import { toast } from '../ui/toast'
import ErrorBox from '../components/ErrorBox.vue'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import Button from '../ui/Button.vue'
import Drawer from '../ui/Drawer.vue'
import Field from '../ui/Field.vue'
import EmptyState from '../ui/EmptyState.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import Skeleton from '../ui/Skeleton.vue'

// Integrations = Proxmox endpoints. All changes are typed plans (POST /plans) that go through approval; secrets are never shown.
type Raw = Endpoint & Record<string, unknown>
const eps = useLoad(() => get<Raw[]>('endpoints'), 15000)
const deps = useLoad(loadDeployments, 60000)
const canEdit = computed(() => hasRole('operator'))
const wizard = computed(() => hasPath('/setup'))

const list = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : typeof v === 'string' && v ? v.split(',').map((x) => x.trim()).filter(Boolean) : [])
type Obj = Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
const roles = (e: Raw): string[] => {
  const c = (e.credentials ?? {}) as Obj
  const out: string[] = []
  if (c.inventory?.present) out.push('inventory')
  if (c.provision?.present) out.push('provision')
  return out
}
// GET /endpoints returns health {status: ok|warning|critical|unknown|disabled|detached, reason}
const state = (e: Raw): string => {
  if (e.enabled === false) return 'disabled'
  const s = String(((e.health ?? {}) as Obj).status ?? '').toLowerCase()
  return ({ ok: 'online', warning: 'degraded', critical: 'failed', unknown: 'unknown', disabled: 'disabled', detached: 'detached' } as Record<string, string>)[s] ?? 'unknown'
}
const probeAt = (e: Raw) => (((e.last_probe ?? {}) as Obj).at ?? null) as string | null
const discAt = (e: Raw) => (((e.last_discovery ?? {}) as Obj).at ?? null) as string | null
const scope = (e: Raw, k: string): string[] => list((((e.scope ?? {}) as Obj)[k]))
const refs = (e: Raw): Deployment[] => (deps.data.value?.data ?? []).filter((d) => d.endpointId === e.id)

// ---- add / edit / disable / remove: all create plans ----
const err = ref<ApiError | null>(null), busy = ref(false)
const created = ref<PlanCreated | null>(null)
async function plan(action: string, params: Record<string, unknown>, done: string) {
  busy.value = true; err.value = null
  try {
    const r = await post<PlanCreated>('plans', { action, params })
    created.value = r
    toast(r.status === 'pending_approval' ? `${done} Sent for approval.` : `${done}`, 'ok')
    await eps.reload()
    return true
  } catch (e) { err.value = e as ApiError; return false } finally { busy.value = false }
}

const drawer = ref<'add' | 'edit' | null>(null)
const editing = ref<Raw | null>(null)
const f = reactive({ name: '', base_url: '', token_id: '', token_secret: '', trust: 'fingerprint' as 'fingerprint' | 'ca', fingerprint: '', ca_pem: '', pools: '', storage: '', networks: '' })
function openAdd() { err.value = null; Object.assign(f, { name: '', base_url: '', token_id: '', token_secret: '', fingerprint: '', ca_pem: '', pools: '', storage: '', networks: '' }); drawer.value = 'add' }
function openEdit(e: Raw) {
  err.value = null; editing.value = e
  Object.assign(f, { name: e.name, pools: scope(e, 'allowed_pools').join(', '), storage: scope(e, 'allowed_storage').join(', '), networks: scope(e, 'allowed_networks').join(', ') })
  drawer.value = 'edit'
}
async function register() {
  const params: Record<string, unknown> = { name: f.name.trim(), type: 'proxmox', base_url: f.base_url.trim(), token_id: f.token_id.trim(), token_secret: f.token_secret }
  if (f.trust === 'fingerprint') params.fingerprint_sha256 = f.fingerprint.trim(); else params.ca_pem = f.ca_pem
  const split = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)
  if (f.pools) params.allowed_pools = split(f.pools)
  if (f.storage) params.allowed_storage = split(f.storage)
  if (f.networks) params.allowed_networks = split(f.networks)
  const ok = await plan('endpoint.register', params, 'Endpoint registration submitted.')
  f.token_secret = ''
  if (ok) drawer.value = null
}
async function saveEdit() {
  if (!editing.value) return
  const split = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)
  const ok = await plan('endpoint.update', { endpoint_id: editing.value.id, display_name: f.name.trim(), allowed_pools: split(f.pools), allowed_storage: split(f.storage), allowed_networks: split(f.networks) }, 'Endpoint update submitted.')
  if (ok) drawer.value = null
}

const confirm = ref<{ kind: 'disable' | 'enable' | 'remove'; ep: Raw } | null>(null)
const confirmName = ref('')
async function doConfirm() {
  const c = confirm.value; if (!c) return
  const params = c.kind === 'remove' ? { endpoint_id: c.ep.id, confirm_name: confirmName.value, force_detach: refs(c.ep).length > 0 } : { endpoint_id: c.ep.id }
  const ok = await plan(`endpoint.${c.kind}`, params, c.kind === 'remove' ? 'Removal submitted.' : c.kind === 'disable' ? 'Disable submitted.' : 'Enable submitted.')
  if (ok) confirm.value = null
}
</script>
<template>
  <div class="page">
    <PageHeader title="Integrations" sub="Proxmox servers and clusters this console manages. Add as many as you need." help="Credentials are stored in the vault and never shown. Connection and permission changes go through approval.">
      <template #actions>
        <Button v-if="canEdit && wizard" variant="primary" icon="plus" to="/setup">Add endpoint</Button>
        <Button v-else-if="canEdit" variant="primary" icon="plus" @click="openAdd">Add endpoint</Button>
      </template>
    </PageHeader>
    <ErrorBox :error="eps.error.value" />
    <div v-if="created" class="alert ok" role="status"><span>Plan <router-link :to="'/plans/' + created.plan_id" class="mono">{{ created.plan_id.slice(0, 8) }}</router-link> created ({{ created.status.replace('_', ' ') }}<template v-if="created.approvals_required">, {{ created.approvals_required }} approvals required</template>). The change takes effect once approved and the job completes.</span></div>
    <Skeleton v-if="!eps.data.value && !eps.error.value" />
    <Card v-else-if="eps.data.value && !eps.data.value.length">
      <EmptyState icon="plug" title="Connect your first Proxmox cluster" text="Add a Proxmox server or cluster with a read-only API token to discover nodes, VMs, storage and networks. You can add a separate provisioning credential later.">
        <Button v-if="canEdit && wizard" variant="primary" icon="plus" to="/setup">Start setup wizard</Button>
        <Button v-else-if="canEdit" variant="primary" icon="plus" @click="openAdd">Add endpoint</Button>
        <span v-else class="muted">Ask an operator to connect one.</span>
      </EmptyState>
    </Card>
    <div v-else class="grid cols-2">
      <Card v-for="e in eps.data.value" :key="e.id">
        <div class="cardhead"><div><h2>{{ e.name }}</h2><div class="muted small mono wrap">{{ e.base_url }}</div></div><StatusBadge :s="state(e)" /></div>
        <dl class="kv">
          <dt>Last probe</dt><dd>{{ probeAt(e) ? ago(probeAt(e)) : 'Not recorded' }}</dd>
          <dt>Last discovery</dt><dd>{{ discAt(e) ? ago(discAt(e)) : 'Not recorded' }}</dd>
          <dt>Credentials</dt><dd><span v-if="roles(e).length" class="chips"><span v-for="r in roles(e)" :key="r" class="tag">{{ r }}</span></span><span v-else class="muted">None recorded</span><span class="muted small"> (secrets are never shown)</span></dd>
          <dt>Trust</dt><dd>{{ e.trust === 'ca_bundle' ? 'CA bundle' : 'Pinned fingerprint' }}<span v-if="e.fingerprint_sha256" class="mono small muted"> {{ e.fingerprint_sha256.slice(0, 17) }}…</span></dd>
          <dt>Allowed pools</dt><dd><span v-if="scope(e, 'allowed_pools').length" class="chips"><span v-for="p in scope(e, 'allowed_pools')" :key="p" class="tag">{{ p }}</span></span><span v-else class="muted">Not restricted</span></dd>
          <dt>Allowed storage</dt><dd><span v-if="scope(e, 'allowed_storage').length" class="chips"><span v-for="p in scope(e, 'allowed_storage')" :key="p" class="tag">{{ p }}</span></span><span v-else class="muted">Not restricted</span></dd>
          <dt>Allowed networks</dt><dd><span v-if="scope(e, 'allowed_networks').length" class="chips"><span v-for="p in scope(e, 'allowed_networks')" :key="p" class="tag">{{ p }}</span></span><span v-else class="muted">Not restricted</span></dd>
          <dt>Added</dt><dd>{{ fmtTime(e.created_at) }}</dd>
        </dl>
        <div class="row">
          <Button size="sm" :to="'/inventory/' + e.id">Inventory</Button>
          <template v-if="canEdit">
            <Button size="sm" icon="gear" @click="openEdit(e)">Edit</Button>
            <Button size="sm" variant="ghost" @click="confirm = { kind: state(e) === 'disabled' ? 'enable' : 'disable', ep: e }">{{ state(e) === 'disabled' ? 'Enable' : 'Disable' }}</Button>
            <Button size="sm" variant="danger" @click="confirmName = ''; confirm = { kind: 'remove', ep: e }">Remove</Button>
          </template>
        </div>
      </Card>
    </div>

    <Drawer v-if="drawer" :title="drawer === 'add' ? 'Add Proxmox endpoint' : 'Edit ' + (editing?.name ?? '')" @close="drawer = null">
      <form class="formgrid" @submit.prevent="drawer === 'add' ? register() : saveEdit()">
        <ErrorBox :error="err" />
        <Field label="Name" for="ep-name" help="A short label, e.g. dc1-cluster"><input id="ep-name" v-model="f.name" required maxlength="64"></Field>
        <template v-if="drawer === 'add'">
        <Field label="API URL" for="ep-url" help="Example: https://pve1.example.net:8006"><input id="ep-url" v-model="f.base_url" required placeholder="https://"></Field>
        <Field label="API token ID" for="ep-tid" help="Format: user@realm!tokenname. Read-only (PVEAuditor) is enough to start."><input id="ep-tid" v-model="f.token_id" required autocomplete="off"></Field>
        <Field label="API token secret" for="ep-sec" help="Stored in the vault and never shown again."><input id="ep-sec" v-model="f.token_secret" type="password" required autocomplete="off"></Field>
        <Field label="Server certificate trust">
          <div class="seg" role="group" aria-label="Trust"><button type="button" :aria-pressed="f.trust === 'fingerprint'" @click="f.trust = 'fingerprint'">Pin fingerprint</button><button type="button" :aria-pressed="f.trust === 'ca'" @click="f.trust = 'ca'">CA bundle</button></div>
        </Field>
        <Field v-if="f.trust === 'fingerprint'" label="SHA-256 fingerprint" for="ep-fp"><input id="ep-fp" v-model="f.fingerprint" class="mono" required></Field>
        <Field v-else label="CA certificate (PEM)" for="ep-ca"><textarea id="ep-ca" v-model="f.ca_pem" rows="5" class="mono" required></textarea></Field>
        </template>
        <div v-if="drawer === 'edit'" class="alert info"><span>Changing the URL, certificate trust or credentials is a high-risk change: use the connection step of the setup wizard so new details are probed first<template v-if="wizard"> (<router-link :to="'/setup?endpoint=' + (editing?.id ?? '')">Change connection</router-link>)</template>. All edits are submitted for approval.</span></div>
        <Field label="Allowed pools (optional)" for="ep-p" help="Comma separated. Limits where ICS may create or change guests."><input id="ep-p" v-model="f.pools"></Field>
        <Field label="Allowed storage (optional)" for="ep-s"><input id="ep-s" v-model="f.storage"></Field>
        <Field label="Allowed networks (optional)" for="ep-n"><input id="ep-n" v-model="f.networks"></Field>
        <div class="row"><Button type="submit" variant="primary" :loading="busy">Submit for approval</Button><Button variant="ghost" @click="drawer = null">Cancel</Button></div>
      </form>
    </Drawer>

    <Drawer v-if="confirm" modal :title="confirm.kind === 'remove' ? 'Remove ' + confirm.ep.name + '?' : confirm.kind === 'disable' ? 'Disable ' + confirm.ep.name + '?' : 'Enable ' + confirm.ep.name + '?'" @close="confirm = null">
      <ErrorBox :error="err" />
      <p v-if="confirm.kind === 'enable'">Discovery, monitoring and deployments that use this endpoint will resume.</p>
      <template v-else>
        <p v-if="confirm.kind === 'disable'">While disabled, ICS stops discovery and will not make changes through this endpoint. Existing guests keep running.</p>
        <p v-else>The endpoint and its stored credentials are removed from ICS. Guests on the cluster are not touched, but ICS can no longer manage or monitor them.</p>
        <div v-if="refs(confirm.ep).length" class="alert warn"><span>{{ refs(confirm.ep).length }} deployment{{ refs(confirm.ep).length > 1 ? 's' : '' }} use this endpoint: {{ refs(confirm.ep).map((d) => d.name).join(', ') }}. They will not be manageable until it is enabled again.</span></div>
        <template v-if="confirm.kind === 'remove'">
          <p class="muted small">Removal is high risk and needs two approvers. Nothing changes until it is approved.</p>
          <Field label="Type the endpoint name to confirm" for="ep-confirm"><input id="ep-confirm" v-model="confirmName" autocomplete="off" :placeholder="confirm.ep.name"></Field>
        </template>
      </template>
      <div class="row"><Button :variant="confirm.kind === 'remove' ? 'danger' : 'primary'" :loading="busy" :disabled="confirm.kind === 'remove' && confirmName !== confirm.ep.name" @click="doConfirm">{{ confirm.kind === 'remove' ? 'Submit removal' : confirm.kind === 'disable' ? 'Disable endpoint' : 'Enable endpoint' }}</Button><Button variant="ghost" @click="confirm = null">Cancel</Button></div>
    </Drawer>
  </div>
</template>
