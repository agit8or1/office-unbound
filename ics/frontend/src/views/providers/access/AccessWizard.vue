<script setup lang="ts">
// Connect → Discover → Select → Authorize → Done (new), and Manage access → Select changes → Apply → Done (edit, `id` = the integration).
// The password and second-factor code go to the server once; only a short-lived Proxmox session (never the password) is kept there.
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { Banner, WizardShell, useWizard, type Errors, type StepDef } from '../../../wizards/kit'
import { api, msg } from '../api'
import { useRun } from '../run'
import RunPanel from '../RunPanel.vue'
import PlanView from '../PlanView.vue'
import type { PlanPreviewOut } from '../model'
import InventoryTree from './InventoryTree.vue'
import MaintenancePanel from './MaintenancePanel.vue'
import { accessApi, type Inventory, type PveSession, type TlsLookup } from './api'
import { DEFAULT_POOL, LEVELS, NEVER, apiUrl, suggestTargets, diffSelection, emptySelection, fromApproved, gib, pctOf, toPolicy, toScopeTarget, validate, visibleNodes, type Selection } from './model'
import '../providers.css'

const props = defineProps<{ id?: string }>()
const edit = computed(() => !!props.id)
const f = reactive({ host: '', port: 8006, username: 'root', realm: 'pam', customRealm: '', advanced: false, trust: 'auto' as 'auto' | 'fingerprint' | 'ca', caPem: '', compared: false, name: '' })
const pw = ref('')
const tfa = reactive({ method: 'totp', code: '' })
const tls = ref<TlsLookup | null>(null)
const session = ref<PveSession | null>(null)
const inv = ref<Inventory | null>(null)
const sel = reactive<Selection>(emptySelection())
const before = ref<Selection | null>(null)
const busy = ref(false)
const err = ref('')
const preview = ref<Record<string, unknown> | null>(null)
const previewRun = useRun()
const applyRun = useRun()
const done = ref<Record<string, unknown> | null>(null)
const st = reactive({ ok: false })
const epName = ref('')
onBeforeUnmount(() => { pw.value = ''; tfa.code = ''; if (session.value?.state === 'ready' || session.value?.state === 'need_tfa') accessApi.signOut(session.value.id).catch(() => {}) })

const realm = computed(() => (f.realm === 'other' ? f.customRealm.trim() : f.realm))
const baseUrl = computed(() => apiUrl(f.host, f.port))
const guests = computed(() => inv.value?.guests ?? [])
const errs = computed(() => (inv.value ? validate(sel, guests.value) : {}))
const change = computed(() => (before.value ? diffSelection(before.value, sel) : null))
const nodeStorages = computed(() => (inv.value?.storages ?? []).filter((s) => s.content.split(',').some((c) => c === 'images' || c === 'rootdir'))
  .filter((s) => !sel.nodes.length || s.nodes.some((n) => sel.nodes.includes(n))))
const nodeNetworks = computed(() => (inv.value?.networks ?? []).filter((x) => !sel.nodes.length || x.nodes.some((n) => sel.nodes.includes(n))))
const templates = computed(() => guests.value.filter((g) => g.template))
// Deployment targets: Office Unbound fills empty choices itself (its own new pool, the roomiest disk storage, the shared bridge); everything stays editable.
const newPool = ref(DEFAULT_POOL)
const showTemplates = ref(false)
const poolIsNew = computed(() => !(inv.value?.pools ?? []).includes(newPool.value.trim()))
watch(() => sel.nodes.length, (n, o) => {
  if (inv.value) Object.assign(sel, suggestTargets(sel, inv.value))
  if (!edit.value && n && !o) sel.level = 'deploy'                                         // a new connection picks hypervisors to deploy on by default
})
watch(newPool, (n, o) => { const i = sel.pools.indexOf(o); if (i >= 0) sel.pools.splice(i, 1, n.trim()) })
function toggleNewPool(on: boolean) {
  const n = newPool.value.trim(), i = sel.pools.indexOf(n)
  if (on && i < 0) sel.pools.push(n)
  if (!on && i >= 0) sel.pools.splice(i, 1)
}

const steps: StepDef<unknown>[] = [
  { id: 'connect', title: edit.value ? 'Sign in' : 'Connect', validate: (): Errors => (session.value?.state === 'ready' && inv.value ? {} : { connect: 'Sign in to Proxmox first.' }) },
  { id: 'discover', title: edit.value ? 'Resources' : 'Discover', validate: (): Errors => (errs.value.select ? { select: errs.value.select } : {}) },
  { id: 'targets', title: 'Deployment targets' },
  { id: 'permissions', title: 'Permissions', validate: () => { const e = { ...errs.value }; delete e.select; return sel.operate.length || sel.nodes.length ? e : { level: 'Select at least one node.' } } },
  { id: 'review', title: 'Review', validate: (): Errors => (st.ok ? {} : { review: 'Preview the change first.' }) },
  { id: 'done', title: 'Done' },
]
const w = useWizard(steps, {})
const cur = computed(() => w.current.value.id)

async function lookup() {
  err.value = ''; tls.value = null
  if (!f.host.trim()) { err.value = 'Enter the address of the Proxmox server.'; return }
  busy.value = true
  try { tls.value = await accessApi.tls(baseUrl.value) } catch (e) { err.value = msg(e) } finally { busy.value = false }
}
const trustMode = computed(() => (f.trust === 'ca' ? 'ca' : tls.value?.public_ca && f.trust === 'auto' ? 'public_ca' : 'fingerprint'))
async function signIn() {
  err.value = ''
  if (!edit.value && !f.host.trim()) { err.value = 'Enter the address of the Proxmox server.'; return }
  if (!f.username.trim()) { err.value = 'Enter the Proxmox user name.'; return }
  if (!pw.value) { err.value = 'Enter the password.'; return }
  if (!edit.value) {
    if (!tls.value) await lookup()
    if (!tls.value) return
    if (trustMode.value === 'fingerprint' && !f.compared) { err.value = 'Confirm that you compared the certificate fingerprint.'; return }
    if (trustMode.value === 'ca' && !f.caPem.includes('BEGIN CERTIFICATE')) { err.value = 'Paste the cluster CA certificate (PEM).'; return }
  }
  busy.value = true
  try {
    const b = edit.value
      ? { endpoint_id: props.id, username: f.username.trim(), realm: realm.value, password: pw.value }
      : { base_url: baseUrl.value, trust: trustMode.value, username: f.username.trim(), realm: realm.value, password: pw.value,
          ...(trustMode.value === 'fingerprint' ? { fingerprint_sha256: tls.value?.presented_fingerprint_sha256 } : {}), ...(trustMode.value === 'ca' ? { ca_pem: f.caPem } : {}) }
    session.value = await accessApi.signIn(b as never)
    pw.value = ''
    if (session.value.state === 'need_tfa') tfa.method = session.value.tfa_methods.find((m) => m !== 'webauthn') ?? 'totp'
    else await discover()
  } catch (e) { err.value = msg(e) } finally { busy.value = false; pw.value = '' }
}
async function sendTfa() {
  if (!session.value) return
  err.value = ''
  if (!tfa.code.trim()) { err.value = 'Enter the code.'; return }
  busy.value = true
  try {
    session.value = await accessApi.tfa(session.value.id, tfa.method, tfa.code.trim())
    tfa.code = ''
    await discover()
  } catch (e) { err.value = msg(e) } finally { busy.value = false; tfa.code = '' }
}
async function discover() {
  if (!session.value) return
  inv.value = await accessApi.inventory(session.value.id, props.id)
  if (edit.value) {
    if (!epName.value) epName.value = (await api.endpoint(props.id!)).name
    Object.assign(sel, fromApproved(inv.value))
    before.value = JSON.parse(JSON.stringify(sel))
  } else if (!f.name) f.name = (inv.value.cluster.name || f.host).toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+/, '').slice(0, 60) || 'proxmox'
  w.next()
}
async function rescan() { busy.value = true; try { await discover0() } catch (e) { err.value = msg(e) } finally { busy.value = false } }
async function discover0() { if (session.value) inv.value = await accessApi.inventory(session.value.id, props.id) }

const policy = computed(() => toPolicy(sel, guests.value))
async function runPreview() {
  if (!session.value) return
  st.ok = false; preview.value = null
  const params: Record<string, unknown> = edit.value
    ? { endpoint_id: props.id, purpose: 'scope_change', scope_target: toScopeTarget(sel, guests.value), admin_session: session.value.id }
    : { name: f.name, base_url: session.value.base_url, admin_session: session.value.id, policy: policy.value }   // TLS anchor: taken from the sign-in by the server
  const j = await previewRun.start('provider.provision.plan_preview', params)
  if (j?.status === 'succeeded') {
    preview.value = j.result as Record<string, unknown>
    const blocked = (edit.value ? (preview.value.blocked as string[]) : ((preview.value.plan as { blocked: string[] }).blocked)) ?? []
    st.ok = !blocked.length
  }
}
async function apply() {
  if (!session.value || !preview.value) return
  const pv = preview.value
  const params: Record<string, unknown> = edit.value
    ? { endpoint_id: props.id, preview_id: pv.preview_id, plan_hash: pv.plan_hash, direction: pv.direction, detach: !!(pv.scope as { detach?: unknown[] })?.detach?.length, admin_session: session.value.id }
    : { name: f.name, base_url: session.value.base_url, preview_id: pv.preview_id, plan_hash: pv.plan_hash, admin_session: session.value.id }
  const j = await applyRun.start(edit.value ? 'provider.scope.change' : 'provider.provision.apply', params)
  if (j?.status === 'succeeded') { done.value = j.result as Record<string, unknown>; w.next() }
}
const scopeDiff = computed(() => (preview.value?.scope as { diff?: Record<string, unknown>; impact?: { notes?: string[] } } | undefined))
const blockedList = computed<string[]>(() => (!preview.value ? [] : edit.value ? (preview.value.blocked as string[]) ?? [] : (preview.value.plan as { blocked: string[] })?.blocked ?? []))
function next() {
  if (cur.value === 'permissions') { st.ok = false; preview.value = null }
  w.next()
}
</script>

<template>
  <div class="pv-wiz">
    <WizardShell :title="edit ? 'Manage access' : 'Connect a Proxmox cluster'"
      :subtitle="edit ? 'Add or remove resources and change what Office Unbound may do. Existing access is kept unless you change it.' : 'Sign in, pick exactly what Office Unbound may use, and it sets up its own restricted access. Nothing changes in Proxmox until approved.'"
      :steps="steps.map((s) => ({ id: s.id, title: s.title }))" :index="w.m.index" :reached="w.m.reached" :busy="busy || previewRun.busy.value || applyRun.busy.value"
      :hide-next="cur === 'connect' || cur === 'review' || cur === 'done'" :next-label="cur === 'permissions' ? 'Review' : 'Next'" @next="next" @back="w.back()" @goto="w.goto($event)">

      <!-- 1. Connect / sign in -->
      <section v-if="cur === 'connect'" class="ax-step">
        <Banner v-if="edit" kind="info" title="Why sign in?">Changing what Office Unbound may do in Proxmox needs a Proxmox administrator once. Viewing inventory and status never does. Your password and code are used for this sign-in only and are never stored.</Banner>
        <form class="ax-form" novalidate @submit.prevent="session?.state === 'need_tfa' ? sendTfa() : signIn()">
          <template v-if="session?.state !== 'need_tfa'">
            <label v-if="!edit" class="fld"><span>Server address</span><input v-model="f.host" autocomplete="url" placeholder="pve.example.com or 10.0.0.5" required @change="tls = null" /></label>
            <div class="ax-row">
              <label class="fld"><span>User name</span><input v-model="f.username" autocomplete="username" required /></label>
              <label class="fld"><span>Realm</span><select v-model="f.realm"><option value="pam">Linux PAM (pam)</option><option value="pve">Proxmox VE (pve)</option><option value="other">Other…</option></select></label>
              <label v-if="f.realm === 'other'" class="fld"><span>Realm name</span><input v-model="f.customRealm" /></label>
            </div>
            <label class="fld"><span>Password</span><input v-model="pw" type="password" autocomplete="current-password" required /></label>
            <button v-if="!edit" type="button" class="wz-btn ax-adv-toggle" :aria-expanded="f.advanced" @click="f.advanced = !f.advanced">{{ f.advanced ? 'Hide advanced settings' : 'Advanced settings' }}</button>
            <div v-if="!edit && f.advanced" class="ax-adv">
              <label class="fld"><span>API port</span><input v-model.number="f.port" type="number" min="1" max="65535" @change="tls = null" /></label>
              <label class="fld"><span>Certificate trust</span><select v-model="f.trust"><option value="auto">Automatic (public certificate, or confirm the fingerprint)</option><option value="fingerprint">Confirm the fingerprint</option><option value="ca">Use the cluster's CA certificate</option></select></label>
              <label v-if="f.trust === 'ca'" class="fld"><span>Cluster CA (contents of /etc/pve/pve-root-ca.pem)</span><textarea v-model="f.caPem" rows="5" class="mono" /></label>
            </div>
            <div v-if="!edit && tls" class="ax-tls">
              <Banner v-if="trustMode === 'public_ca'" kind="ok" title="Trusted certificate">{{ tls.subject }}. Publicly trusted for this address: no manual check needed.</Banner>
              <template v-else-if="trustMode === 'fingerprint'">
                <Banner kind="warn" title="Check that this is really your server">This server uses its own certificate. Compare its fingerprint with the one Proxmox shows, then confirm.</Banner>
                <p class="mono small ax-fp">{{ tls.presented_fingerprint_sha256 }}</p>
                <p class="muted small">{{ tls.verify_hint }}</p>
                <label class="row"><input v-model="f.compared" type="checkbox" /> The fingerprint matches what my Proxmox server shows</label>
              </template>
              <Banner v-if="tls.error" kind="bad">{{ tls.error }}</Banner>
            </div>
            <div class="row">
              <button v-if="!edit && !tls" type="button" class="wz-btn" :disabled="busy" @click="lookup">Check certificate</button>
              <button type="submit" class="wz-btn primary" :disabled="busy">{{ busy ? 'Connecting…' : edit ? 'Sign in' : 'Connect' }}</button>
            </div>
          </template>
          <template v-else>
            <Banner v-if="session.webauthn_only" kind="warn" title="Security key sign-in is not possible here">This account only has a security key (WebAuthn). Proxmox binds those to its own web page, so Office Unbound cannot complete it. Add a TOTP app or use a recovery key for this account, or sign in with another administrator.</Banner>
            <template v-else>
              <h2>Two-factor authentication</h2>
              <label class="fld"><span>Method</span><select v-model="tfa.method"><option v-for="m in session.tfa_methods.filter((x) => x !== 'webauthn')" :key="m" :value="m">{{ m === 'totp' ? 'Authenticator app code' : m === 'recovery' ? 'Recovery key' : 'YubiKey OTP' }}</option></select></label>
              <label class="fld"><span>Code</span><input v-model="tfa.code" autocomplete="one-time-code" inputmode="text" required autofocus /></label>
              <button type="submit" class="wz-btn primary" :disabled="busy">{{ busy ? 'Checking…' : 'Verify' }}</button>
            </template>
          </template>
          <Banner v-if="err" kind="bad">{{ err }}</Banner>
        </form>
      </section>

      <!-- 2. Discover: overview + existing guests -->
      <section v-else-if="cur === 'discover' && inv" class="ax-step">
        <div class="ax-cards">
          <div class="ax-card"><b>{{ inv.cluster.name }}</b><span class="muted small">{{ inv.cluster.standalone ? 'Standalone node' : 'Cluster' }} · Proxmox VE {{ inv.cluster.version }}</span></div>
          <div class="ax-card"><b>{{ inv.cluster.nodes_online }} / {{ inv.cluster.nodes_total }}</b><span class="muted small">nodes online{{ inv.cluster.quorate ? '' : ' · NO QUORUM' }}</span></div>
          <div class="ax-card"><b>{{ pctOf(inv.cluster.cpu.used, inv.cluster.cpu.total) }}%</b><span class="muted small">CPU of {{ inv.cluster.cpu.total }} cores</span><progress :value="inv.cluster.cpu.used" :max="inv.cluster.cpu.total || 1" /></div>
          <div class="ax-card"><b>{{ pctOf(inv.cluster.mem.used, inv.cluster.mem.total) }}%</b><span class="muted small">RAM of {{ gib(inv.cluster.mem.total) }}</span><progress :value="inv.cluster.mem.used" :max="inv.cluster.mem.total || 1" /></div>
          <div class="ax-card"><b>{{ pctOf(inv.cluster.storage.used, inv.cluster.storage.total) }}%</b><span class="muted small">storage of {{ gib(inv.cluster.storage.total) }}</span><progress :value="inv.cluster.storage.used" :max="inv.cluster.storage.total || 1" /></div>
          <div class="ax-card"><b>{{ inv.cluster.vms }} VMs · {{ inv.cluster.containers }} CTs</b><span class="muted small">guests</span></div>
        </div>
        <Banner v-if="!inv.account.ok" kind="warn" title="This account cannot set up Office Unbound's access">
          Missing: <span v-for="m in inv.account.missing" :key="m.path + m.privilege" class="mono">{{ m.privilege }} on {{ m.path }} </span>. {{ inv.account.remediation }}
        </Banner>
        <Banner v-if="edit && inv.missing?.length" kind="warn" title="No longer found">{{ inv.missing.map((x) => `${x.kind} ${x.key}`).join(', ') }}: deleted in Proxmox, or no longer visible.</Banner>
        <h2>Which hypervisors may Office Unbound use?</h2>
        <p class="muted">Tick the nodes it may use. It sees their status and, with the Deployment level, creates its own guests there. Your existing VMs and containers stay invisible to it.</p>
        <InventoryTree :inv="inv" :sel="sel" :edit="edit" />
        <div class="row"><button type="button" class="wz-btn" :disabled="busy" @click="rescan">Rescan</button></div>
        <MaintenancePanel v-if="edit && session && id" :endpoint-id="id" :session-id="session.id" :endpoint-name="epName" />
        <p v-if="w.m.errors.select" class="err" role="alert">{{ w.m.errors.select }}</p>
      </section>

      <!-- 3. Deployment targets -->
      <section v-else-if="cur === 'targets' && inv" class="ax-step">
        <h2>Where do its new guests go?</h2>
        <p class="muted">On {{ sel.nodes.join(', ') || 'the selected nodes' }}. Only used with the Deployment level (next step); with Monitoring nothing here is granted.</p>
        <template v-if="sel.nodes.length">
          <Banner kind="info" title="Office Unbound picked these for you">Its own new pool, the disk storage with the most free space and the network your nodes share. Change anything you like.</Banner>
          <fieldset class="ax-set"><legend>Resource pool for new guests</legend>
            <label v-if="poolIsNew" class="row"><input type="checkbox" :checked="sel.pools.includes(newPool.trim())" @change="toggleNewPool(($event.target as HTMLInputElement).checked)" />
              New pool <input v-model="newPool" class="ax-pool" aria-label="New pool name" autocomplete="off" /> <span class="muted small">created by Office Unbound; everything it deploys goes here</span></label>
            <label v-for="p in inv.pools" :key="p" class="row"><input v-model="sel.pools" type="checkbox" :value="p" /> {{ p }} <span class="muted small">existing pool</span></label>
            <p v-if="w.m.errors.pools || errs.pools" class="err" role="alert">{{ w.m.errors.pools || errs.pools }}</p>
          </fieldset>
          <fieldset class="ax-set"><legend>Storage for disks</legend>
            <label v-for="s in nodeStorages" :key="s.storage" class="row"><input v-model="sel.storages" type="checkbox" :value="s.storage" /> {{ s.storage }} <span class="muted small">{{ s.type }}{{ s.shared ? ' · shared' : '' }} · {{ gib(s.total - s.used) }} free</span></label>
          </fieldset>
          <fieldset class="ax-set"><legend>Network new guests connect to</legend>
            <label v-for="x in nodeNetworks" :key="x.name" class="row"><input v-model="sel.networks" type="checkbox" :value="x.name" /> {{ x.name }} <span class="muted small">{{ x.kind }}{{ x.comment ? ' · ' + x.comment : '' }}</span></label>
            <p class="muted small">Office Unbound uses an existing bridge and never creates or changes bridges or VLANs: a wrong host network change can cut a node off. To give it its own network, create a bridge or SDN VNet in Proxmox, then Rescan.</p>
          </fieldset>
          <fieldset class="ax-set"><legend>Templates</legend>
            <p class="muted small">Not needed. After connecting, Office Unbound imports its own signed image as a template into its pool (Administration › Images).</p>
            <button v-if="templates.length && !showTemplates" type="button" class="wz-btn ax-adv-toggle" @click="showTemplates = true">Also allow existing templates ({{ templates.length }})</button>
            <template v-if="showTemplates || sel.templates.length">
              <label v-for="t in templates" :key="t.vmid" class="row"><input v-model="sel.templates" type="checkbox" :value="t.vmid" /> {{ t.vmid }} {{ t.name }} <span class="muted small">on {{ t.node }}</span></label>
            </template>
          </fieldset>
        </template>
      </section>

      <!-- 4. Permissions -->
      <section v-else-if="cur === 'permissions'" class="ax-step">
        <h2>What may Office Unbound do?</h2>
        <div class="ax-levels" role="radiogroup" aria-label="Permission level">
          <label v-for="l in LEVELS.filter((x) => x.id !== 'operations' || sel.operate.length)" :key="l.id" class="ax-level" :class="{ on: sel.level === l.id }">
            <input v-model="sel.level" type="radio" :value="l.id" />
            <b>{{ l.title }}</b><span class="muted small">{{ l.text }}</span>
          </label>
        </div>
        <p v-for="(m, k) in w.m.errors" :key="k" class="err" role="alert">{{ m }}</p>
        <label v-if="sel.level === 'deploy'" class="row"><input v-model="sel.allowMigrate" type="checkbox" /> Allow moving its own guests between the selected nodes (VM.Migrate)</label>
        <fieldset class="ax-set"><legend>Never granted by any level</legend>
          <label v-for="n in NEVER" :key="n" class="row muted"><input type="checkbox" disabled /> {{ n }}</label>
          <p class="muted small">Deleting a guest Office Unbound created is a separate, separately approved action. Proxmox cannot split "create" from "delete" inside a pool, so Office Unbound enforces it.</p>
        </fieldset>
        <p class="muted small">Visible nodes (status only): {{ visibleNodes(sel, guests).join(', ') || 'none' }}.</p>
      </section>

      <!-- 5. Review -->
      <section v-else-if="cur === 'review'" class="ax-step">
        <h2>Review</h2>
        <div v-if="change" class="ax-diff">
          <p v-if="before && before.level !== sel.level"><b>Permission level:</b> {{ LEVELS.find((l) => l.id === before!.level)?.title }} → {{ LEVELS.find((l) => l.id === sel.level)?.title }}</p>
          <p v-if="!change.added.length && !change.removed.length" class="muted">No resources added or removed.</p>
          <p v-if="change.added.length"><b>Adding:</b> {{ change.added.join(', ') }}</p>
          <p v-if="change.removed.length"><b>Removing access to:</b> {{ change.removed.join(', ') }} <span class="muted small">(nothing is deleted in Proxmox)</span></p>
        </div>
        <button v-if="!preview" type="button" class="wz-btn primary" :disabled="previewRun.busy.value" @click="runPreview">{{ previewRun.busy.value ? 'Calculating…' : 'Calculate the exact Proxmox changes' }}</button>
        <RunPanel v-if="previewRun.created.value && !preview" :run="previewRun" what="Preview" />
        <template v-if="preview">
          <Banner v-for="b in blockedList" :key="b" kind="bad" title="Cannot be applied">{{ b }}</Banner>
          <PlanView v-if="!edit" :preview="(preview as unknown as PlanPreviewOut)" />
          <template v-else-if="scopeDiff">
            <p><b>Direction:</b> {{ preview.direction === 'widen' ? 'More access (needs two approvers)' : preview.direction === 'narrow' ? 'Less access' : 'No change in Proxmox' }}</p>
            <ul class="ax-acl">
              <li v-for="a in ((scopeDiff.diff?.acl_add ?? []) as { path: string; role: string }[])" :key="'+' + a.path + a.role" class="add">+ {{ a.role }} on <span class="mono">{{ a.path }}</span></li>
              <li v-for="a in ((scopeDiff.diff?.acl_remove ?? []) as { path: string; role: string }[])" :key="'-' + a.path + a.role" class="rm">− {{ a.role }} on <span class="mono">{{ a.path }}</span></li>
            </ul>
            <Banner v-for="n in scopeDiff.impact?.notes ?? []" :key="n" kind="info">{{ n }}</Banner>
          </template>
          <div v-if="st.ok" class="row mt">
            <button type="button" class="wz-btn primary" :disabled="applyRun.busy.value" @click="apply">{{ edit ? 'Request approval and apply' : 'Request approval and connect' }}</button>
            <button type="button" class="wz-btn" :disabled="applyRun.busy.value" @click="preview = null; st.ok = false">Recalculate</button>
          </div>
          <RunPanel v-if="applyRun.created.value" :run="applyRun" :what="edit ? 'Access change' : 'Connection'" />
        </template>
        <p v-if="w.m.errors.review" class="err" role="alert">{{ w.m.errors.review }}</p>
      </section>

      <!-- 6. Done -->
      <section v-else-if="cur === 'done'" class="ax-step pv-done">
        <div class="pv-bigcheck" aria-hidden="true">&#10003;</div>
        <h2>{{ edit ? 'Access updated' : 'Connected' }}</h2>
        <p class="muted">Office Unbound now uses its own restricted account. Your Proxmox sign-in was destroyed.</p>
        <p v-if="change && edit"><span v-if="change.added.length">Added: {{ change.added.join(', ') }}. </span><span v-if="change.removed.length">Removed: {{ change.removed.join(', ') }}.</span></p>
        <div class="row">
          <router-link class="wz-btn primary" :to="`/infrastructure/providers/${edit ? id : (done?.endpoint_id as string)}`">Open the cluster</router-link>
          <router-link class="wz-btn" :to="`/infrastructure/providers/${edit ? id : (done?.endpoint_id as string)}/permissions`">Review permissions</router-link>
        </div>
      </section>
    </WizardShell>
  </div>
</template>

<style scoped>
.ax-step { display: grid; gap: 14px; }
.ax-form { display: grid; gap: 12px; max-width: 560px; }
.ax-row { display: flex; flex-wrap: wrap; gap: 12px; } .ax-row .fld { flex: 1 1 160px; }
.fld { display: grid; gap: 4px; } .fld input, .fld select, .fld textarea { width: 100%; font: inherit; }
.row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.mt { margin-top: 12px; }
.ax-adv { display: grid; gap: 12px; } .ax-pool { width: 14em; max-width: 100%; font: inherit; } .ax-adv-toggle { justify-self: start; }
.ax-fp { word-break: break-all; padding: 8px; border-radius: 6px; background: var(--code-bg, rgba(0, 0, 0, .04)); }
.ax-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 10px; }
.ax-card { display: grid; gap: 2px; padding: 12px; border: 1px solid var(--border, #d0d5dd); border-radius: 8px; }
.ax-card progress { width: 100%; height: 6px; }
.ax-set { border: 1px solid var(--border, #d0d5dd); border-radius: 8px; padding: 10px 14px; display: grid; gap: 4px; }
.ax-levels { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }
.ax-level { display: grid; gap: 4px; padding: 14px; border: 2px solid var(--border, #d0d5dd); border-radius: 10px; cursor: pointer; }
.ax-level.on { border-color: var(--accent, #175cd3); }
.ax-level input { justify-self: start; }
.ax-acl { list-style: none; padding: 0; margin: 0; display: grid; gap: 2px; }
.ax-acl .add { color: #067647; } .ax-acl .rm { color: #b42318; }
.err { color: #b42318; }
.mono { font-family: var(--mono, ui-monospace, monospace); }
</style>
