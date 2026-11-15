<script setup lang="ts">
// Credentials: metadata only. Secrets are never displayed; a new secret is typed into a write-only field and sent once.
import { computed, onBeforeUnmount, reactive, ref } from 'vue'
import { useLoad, hasRole } from '../../store'
import { ago, fmtDuration } from '../../format'
import Button from '../../ui/Button.vue'
import Card from '../../ui/Card.vue'
import Drawer from '../../ui/Drawer.vue'
import EmptyState from '../../ui/EmptyState.vue'
import ErrorBox from '../../components/ErrorBox.vue'
import { Banner, Field, TOKEN_SECRET_RE } from '../../wizards/kit'
import ClusterHeader from './ClusterHeader.vue'
import RunPanel from './RunPanel.vue'
import { api, load } from './api'
import { credentialState, credentialsFor, daysUntil, type CredentialMeta } from './model'
import { useRun } from './run'
import './providers.css'

const props = defineProps<{ id: string }>()
const data = useLoad(async () => {
  const ep = await api.endpoint(props.id)
  const all = await load(() => api.credentials())
  return { ep, creds: all.state === 'ok' ? credentialsFor(ep, all.data) : [], state: all.state }
}, 60000)
const d = computed(() => data.data.value)
const canAdmin = computed(() => hasRole('admin')), canOperate = computed(() => hasRole('operator'))

type Mode = 'test' | 'rotate' | 'replace' | 'revoke'
const sel = ref<CredentialMeta | null>(null), mode = ref<Mode | null>(null)
const detail = ref<Awaited<ReturnType<typeof api.credential>> | null>(null)
const access = ref<Awaited<ReturnType<typeof api.accessReview>> | 'forbidden' | null>(null)
const form = reactive({ identity: '', reason: '', expires: '', confirm: '' })
const secret = { value: '' } // write-only; wiped after the request
const errors = ref<Record<string, string>>({})
const run = useRun()
onBeforeUnmount(() => { secret.value = '' })

async function open(c: CredentialMeta, m: Mode) {
  sel.value = c; mode.value = m; run.reset(); secret.value = ''; errors.value = {}
  Object.assign(form, { identity: c.identity ?? '', reason: '', expires: '', confirm: '' })
  detail.value = null; access.value = null
  try { detail.value = await api.credential(c.id) } catch { /* history is optional */ }
  const a = await load(() => api.accessReview(c.id)); access.value = a.state === 'ok' ? a.data : 'forbidden'
  if (m === 'test') await submit()
}
async function submit() {
  const c = sel.value!, e: Record<string, string> = {}
  if (mode.value !== 'test' && form.reason.trim().length < 3) e.reason = 'Give a short reason (3+ characters). It goes into the audit log.'
  if ((mode.value === 'rotate' || mode.value === 'replace') && !TOKEN_SECRET_RE.test(secret.value.trim())) e.secret = 'Paste the new secret (8-200 characters).'
  if (mode.value === 'revoke' && form.confirm !== c.label) e.confirm = `Type "${c.label}" to confirm.`
  errors.value = e
  if (Object.keys(e).length) return
  const base = { credential_id: c.id }
  const params: Record<string, unknown> = mode.value === 'test' ? base
    : mode.value === 'revoke' ? { ...base, reason: form.reason }
    : { ...base, secret: secret.value.trim(), reason: form.reason, ...(mode.value === 'replace' && form.identity ? { identity: form.identity } : {}), ...(form.expires ? { expires_at: new Date(form.expires + 'T23:59:59Z').toISOString() } : {}) }
  const job = await run.start('credential.' + mode.value, params)
  secret.value = ''
  if (job?.status === 'succeeded') void data.reload()
}
const TITLE: Record<Mode, string> = { test: 'Test credential', rotate: 'Rotate secret', replace: 'Replace credential', revoke: 'Revoke credential' }
const tone = (t: string) => t
</script>

<template>
  <div class="pv">
    <ClusterHeader :id="id" :ep="d?.ep ?? null" />
    <ErrorBox v-if="data.error.value" :error="data.error.value" />
    <Banner kind="info" title="Secrets are never shown">This page lists what exists, who may use it and when it expires. The secret itself is stored encrypted and cannot be read back, by anyone, from this console.</Banner>
    <template v-if="d">
      <EmptyState v-if="d.state === 'unavailable'" icon="shield" title="Credential vault is not available" text="This server does not provide the credential API." />
      <EmptyState v-else-if="!d.creds.length" icon="shield" title="No credentials on file" text="Credentials appear here once the cluster is connected." />
      <div v-else class="pv-cards">
        <Card v-for="c in d.creds" :key="c.id" class="pv-cred-card">
          <template #actions><span class="badge" :class="tone(credentialState(c).tone)">{{ credentialState(c).text }}</span></template>
          <h2 class="pv-h2">{{ c.label }}</h2>
          <dl class="pv-dl">
            <dt>Purpose</dt><dd>{{ c.purpose === 'inventory' ? 'Read the cluster' : c.purpose === 'provision' ? 'Create and change VMs' : 'Temporary setup' }}</dd>
            <dt>Type</dt><dd>{{ c.credential_type.replace('_', ' ') }}</dd><dt>Identity</dt><dd class="mono">{{ c.identity ?? '-' }}</dd>
            <dt>Created</dt><dd>{{ ago(c.created_at) }}</dd><dt>Last tested</dt><dd>{{ c.last_validated_at ? ago(c.last_validated_at) : 'never' }}</dd><dt>Last used</dt><dd>{{ c.last_used_at ? ago(c.last_used_at) : 'never' }}</dd>
            <dt>Expires</dt><dd>{{ c.expires_at ? new Date(c.expires_at).toLocaleDateString() + ' (' + (daysUntil(c.expires_at)! >= 0 ? 'in ' + daysUntil(c.expires_at) + ' days' : 'expired') + ')' : 'no expiry set' }}</dd>
          </dl>
          <p class="muted small">{{ credentialState(c).detail }}</p>
          <div class="row">
            <Button size="sm" :disabled="!canOperate || c.status === 'revoked'" @click="open(c, 'test')">Test</Button>
            <Button size="sm" :disabled="!canOperate || c.status === 'revoked'" @click="open(c, 'rotate')">Rotate</Button>
            <Button size="sm" :disabled="!canAdmin || c.status === 'revoked'" @click="open(c, 'replace')">Replace</Button>
            <Button size="sm" variant="danger" :disabled="!canAdmin || c.status === 'revoked'" @click="open(c, 'revoke')">Revoke</Button>
          </div>
        </Card>
      </div>
    </template>

    <Drawer v-if="sel && mode" :title="TITLE[mode] + ': ' + sel.label" @close="sel = null; mode = null; run.reset()">
      <div class="wz pv-flow">
        <p v-if="mode === 'test'" class="muted">Logs in with this credential and reports whether Proxmox accepts it.</p>
        <p v-if="mode === 'rotate'" class="muted">Same identity, new secret. Create the new secret in Proxmox first, then paste it. It is tested before the old one is retired.</p>
        <p v-if="mode === 'replace'" class="muted">The customer issued a new credential (the identity may change). It is tested before the old one is retired. The old record is kept unusable for 7 days.</p>
        <Banner v-if="mode === 'revoke'" kind="bad" title="Revoking destroys the secret immediately">Office Unbound will no longer be able to use it. This cannot be undone.</Banner>
        <template v-if="mode !== 'test'">
          <Field v-if="mode === 'replace'" label="New identity" hint="For example user@realm!tokenname" v-slot="{ id: fid }"><input :id="fid" v-model.trim="form.identity" type="text" autocomplete="off" /></Field>
          <Field v-if="mode === 'rotate' || mode === 'replace'" label="New secret" :error="errors.secret" hint="Write-only. Sent once, then cleared from this page." v-slot="{ id: fid, invalid }"><input :id="fid" v-model="secret.value" type="password" autocomplete="new-password" :aria-invalid="invalid" /></Field>
          <Field v-if="mode === 'rotate' || mode === 'replace'" label="Expiry date" optional hint="Office Unbound warns 14 days before." v-slot="{ id: fid }"><input :id="fid" v-model="form.expires" type="date" /></Field>
          <Field label="Reason" :error="errors.reason" hint="Recorded in the audit log." v-slot="{ id: fid, invalid }"><input :id="fid" v-model="form.reason" type="text" :aria-invalid="invalid" /></Field>
          <Field v-if="mode === 'revoke'" :label="`Type ${sel.label} to confirm`" :error="errors.confirm" v-slot="{ id: fid, invalid }"><input :id="fid" v-model="form.confirm" type="text" autocomplete="off" :aria-invalid="invalid" /></Field>
          <div class="wz-row mt"><button type="button" class="wz-btn primary" :disabled="run.busy.value" @click="submit">{{ run.busy.value ? 'Working...' : TITLE[mode] }}</button></div>
        </template>
        <RunPanel :run="run" :what="TITLE[mode]" />
        <Banner v-if="run.job.value?.status === 'succeeded' && mode === 'test'" kind="ok" title="Proxmox accepted the credential">Tested just now.</Banner>

        <h3>History</h3>
        <ul v-if="detail?.history?.length" class="pv-list small"><li v-for="(h, i) in detail.history" :key="i">{{ ago(h.at) }}: {{ h.event.replace('credential.', '') }}<template v-if="h.actor"> by {{ h.actor }}</template></li></ul>
        <p v-else class="muted small">No history to show.</p>
        <h3>Who used it</h3>
        <p v-if="access === 'forbidden'" class="muted small">Access history is visible to approvers.</p>
        <ul v-else-if="Array.isArray(access) && access.length" class="pv-list small"><li v-for="a in access.slice(0, 10)" :key="a.seq">{{ ago(a.at) }}: {{ a.event.replace('credential.', '') }} by {{ a.who ?? 'system' }}<template v-if="a.use"> ({{ a.use }})</template></li></ul>
        <p v-else class="muted small">Not used yet.</p>
      </div>
    </Drawer>
  </div>
</template>
