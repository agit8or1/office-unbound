<script setup lang="ts">
// Connect with SSH (ADR-0014): Connect > Host key > Discover > Choose > Review > Apply > Done.
// The administrator's SSH credential is used once and then destroyed; from then on Office Unbound uses only identities it created itself.
// Mode "offboard" (?offboard=1&endpoint=<id>) removes everything onboarding created (it needs the administrator's credential again).
import { computed, onBeforeUnmount, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { Banner, CodeBlock, Field, HelpNote, WizardShell, useWizard, type Errors, type StepDef } from '../../wizards/kit'
import PlanView from './PlanView.vue'
import RunPanel from './RunPanel.vue'
import { useRun } from './run'
import { msg } from './api'
import {
  ADVANCED, RIGHTS, newChoice, newForm, newSshSecrets, offboardParams, onboardParams, policyOf, previewParams, sameFingerprint, sshApi, suggestName, validateChoice, type Choice,
  validateForm, wipeSsh, FP_RE, type ApiCertificate, TRUST_LABEL, tib, type Overview, type SshPreviewOut, type SshSessionView,
} from './ssh'
import './providers.css'

const route = useRoute()
const endpointId = (route.query.endpoint as string | undefined) || null
const offboard = route.query.offboard === '1' && !!endpointId
const isOff = ref(offboard)
const epId = ref<string | null>(endpointId)
const form = reactive(newForm())
const secrets = newSshSecrets()                    // not reactive, never serialised, wiped after the request that stores it
const secretTick = ref(0)                           // re-render the password/key inputs after a wipe
const sess = ref<SshSessionView | null>(null)
const typed = ref('')
const overview = ref<Overview | null>(null)
const apiCert = ref<ApiCertificate | null>(null)
const proxyTyped = ref('')
const preview = ref<(SshPreviewOut & { preview_id: string }) | null>(null)
const sel = ref<Choice>(newChoice())
const name = ref('')
const confirmName = ref('')
const deletePool = ref(false)
const busy = ref(false)
const failure = ref('')
const run = useRun()
const { busy: runBusy, created: runCreated, view: runView } = run
const done = ref<Record<string, unknown> | null>(null)
let sessionLive = false
onBeforeUnmount(() => {
  wipeSsh(secrets)
  if (sessionLive && sess.value) void sshApi.cancel(sess.value.id).catch(() => undefined)   // a session that was not used is destroyed, not left to expire
})

const stepsAll: StepDef<unknown>[] = offboard
  ? [{ id: 'connect', title: 'Connect', validate: (): Errors => (sess.value ? {} : { connect: 'Store the connection first.' }) },
     { id: 'hostkey', title: 'Host key', validate: (): Errors => (sess.value?.state === 'pinned' ? {} : { hostkey: 'Confirm the host key first.' }) },
     { id: 'review', title: 'Review', validate: (): Errors => (confirmName.value ? {} : { confirm: 'Type the integration name to confirm.' }) },
     { id: 'apply', title: 'Remove', validate: (): Errors => (done.value ? {} : { apply: 'Run the removal to continue.' }) },
     { id: 'done', title: 'Done' }]
  : [{ id: 'connect', title: 'Connect', validate: (): Errors => (sess.value ? {} : { connect: 'Store the connection first.' }) },
     { id: 'hostkey', title: 'Host key', validate: (): Errors => (sess.value?.state === 'pinned' ? {} : { hostkey: 'Confirm the host key first.' }) },
     { id: 'discover', title: 'Discover', validate: (): Errors => (overview.value && !(apiCert.value?.needs_confirmation && sess.value?.api_proxy !== 'confirmed') ? {} : { discover: apiCert.value?.needs_confirmation ? 'Confirm the proxy certificate to continue.' : 'Run discovery to continue.' }) },
     { id: 'choose', title: 'Choose', validate: (): Errors => validateChoice(sel.value) },
     { id: 'review', title: 'Review', validate: (): Errors => (preview.value && !preview.value.blocked.length ? {} : { review: preview.value ? 'The plan is blocked: change the choices.' : 'Preview the changes first.' }) },
     { id: 'apply', title: 'Apply', validate: (): Errors => (done.value ? {} : { apply: 'Apply the change to continue.' }) },
     { id: 'done', title: 'Done' }]
const w = useWizard(stepsAll, {} as unknown)
const id = computed(() => w.current.value.id)
const errs = computed(() => w.m.errors)
const shellSteps = stepsAll.map((x) => ({ id: x.id, title: x.title }))
const last = computed(() => id.value === 'done')
const fieldErr = computed(() => validateForm(form, secrets))
const showErr = ref(false)

async function guarded<T>(fn: () => Promise<T>): Promise<T | undefined> {
  failure.value = ''; busy.value = true
  try { return await fn() } catch (e) { failure.value = msg(e) } finally { busy.value = false }
}
async function store() {
  showErr.value = true
  if (Object.keys(validateForm(form, secrets)).length) return
  const v = await guarded(() => sshApi.create(form, secrets))
  wipeSsh(secrets); secretTick.value++                 // the credential is now in the vault; it is gone from this page
  if (v) { sess.value = v; sessionLive = true; name.value = suggestName(form.host); await fetchKey() }
}
async function fetchKey() {
  if (!sess.value) return
  const v = await guarded(() => sshApi.hostkey(sess.value!.id))
  if (v) sess.value = v
}
async function confirmKey() {
  if (!sess.value) return
  const v = await guarded(() => sshApi.confirm(sess.value!.id, typed.value.trim()))
  if (v) { sess.value = v; typed.value = '' }
}
async function cancelSession() {
  if (!sess.value) return
  await guarded(() => sshApi.cancel(sess.value!.id))
  sessionLive = false; sess.value = null; typed.value = ''
}
async function runDiscover() {
  const j = await run.start('provider.ssh.discover', { ssh_session_id: sess.value!.id })
  const r = j?.status === 'succeeded' ? (j.result as { overview: Overview; api_certificate: ApiCertificate }) : null
  if (r) {
    overview.value = r.overview
    apiCert.value = r.api_certificate
    if (sess.value) sess.value = await sshApi.get(sess.value.id)
    if (!sel.value.nodes.length && overview.value.connected_node) sel.value.nodes = [overview.value.connected_node]
    if (!sel.value.networks.length && overview.value.networks.length) sel.value.networks = overview.value.networks.slice(0, 1).map((n) => n.name)
    sel.value.poolMode = overview.value.pools.includes(sel.value.pool) ? 'existing' : 'new'
  }
}
async function confirmProxy() {
  if (!sess.value) return
  const v = await guarded(() => sshApi.confirmProxy(sess.value!.id, proxyTyped.value.trim()))
  if (v) { sess.value = v; proxyTyped.value = '' }
}
async function runPreview() {
  const j = await run.start('provider.ssh.preview', previewParams(sess.value!.id, sel.value, name.value, endpointId, form.icsAddress))
  if (j?.status === 'succeeded') preview.value = j.result as SshPreviewOut & { preview_id: string }
}
async function runApply() {
  const j = await run.start('provider.ssh_onboard', onboardParams(sess.value!.id, preview.value!, name.value, endpointId))
  if (j?.status === 'succeeded') { done.value = j.result as Record<string, unknown>; sessionLive = false }
}
async function runOffboard() {
  const j = await run.start('provider.ssh_offboard', offboardParams(sess.value!.id, endpointId!, confirmName.value, deletePool.value))
  if (j?.status === 'succeeded') { done.value = j.result as Record<string, unknown>; sessionLive = false }
}
const planForView = computed(() => (preview.value ? { ...preview.value, plan_hash: preview.value.plan.plan_hash } : null))
const needSingleNode = computed(() => sel.value.mode === 'single_node')
const toggle = (arr: string[], v: string) => { const i = arr.indexOf(v); if (i >= 0) arr.splice(i, 1); else arr.push(v) }
const toggleN = (arr: number[], v: number) => { const i = arr.indexOf(v); if (i >= 0) arr.splice(i, 1); else arr.push(v) }
const localStorages = computed(() => (overview.value?.storages ?? []).filter((s) => !s.shared))
const fmtTib = (n: number): string => tib(n)
const trustLabel = (m: string): string => TRUST_LABEL[m] ?? m
const fpOk = computed(() => FP_RE.test(typed.value.trim()))
const policyPreview = computed(() => JSON.stringify(policyOf(sel.value), null, 1))
</script>

<template>
  <div class="pv-wiz">
    <WizardShell :title="isOff ? 'Remove the SSH-created access' : 'Connect with SSH'"
      :subtitle="isOff ? 'Deletes the service account, token, role, permissions and the node-side SSH identity that onboarding created.' : 'Log in to one Proxmox node once. Office Unbound reads the cluster, you choose what it may do, and it creates its own account, permissions and key. Your SSH login is then destroyed.'"
      :steps="shellSteps" :index="w.m.index" :reached="w.m.reached" :next-label="id === 'review' && !isOff ? 'Continue to apply' : 'Next'" :hide-next="last" :busy="busy || runBusy"
      @next="w.next()" @back="w.back()" @goto="w.goto($event)">

      <!-- 1. connect -->
      <div v-if="id === 'connect'" :key="'connect-' + secretTick">
        <h2>Where and how do we log in?</h2>
        <Banner v-if="sess" kind="ok" title="Stored">The credential is in the vault (never shown again) and is destroyed after use, on cancel, or after 30 minutes. <button type="button" class="wz-btn" @click="cancelSession">Start over</button></Banner>
        <div v-else class="wz-grid">
          <Field label="Node host name or IP" :error="showErr ? fieldErr.host : ''"><template #default="{ id: i }"><input :id="i" v-model="form.host" autocomplete="off" placeholder="pve06.example.net" /></template></Field>
          <Field label="SSH port" :error="showErr ? fieldErr.port : ''"><template #default="{ id: i }"><input :id="i" v-model.number="form.port" type="number" min="1" max="65535" /></template></Field>
          <Field label="User" hint="root, or a user that can run sudo without a password prompt (sudo -n)." :error="showErr ? fieldErr.username : ''"><template #default="{ id: i }"><input :id="i" v-model="form.username" autocomplete="off" /></template></Field>
          <fieldset class="wz-field"><legend>Authentication</legend>
            <label><input type="radio" name="form-auth" :checked="form.auth === 'password'" @change="form.auth = 'password'" /> Password</label>
            <label><input type="radio" name="form-auth" :checked="form.auth === 'key'" @change="form.auth = 'key'" /> Private key</label>
          </fieldset>
          <Field v-if="form.auth === 'password'" label="Password" :error="showErr ? fieldErr.password : ''"><template #default="{ id: i }"><input :id="i" v-model="secrets.password" type="password" autocomplete="off" /></template></Field>
          <template v-else>
            <Field label="Private key" :error="showErr ? fieldErr.privateKey : ''"><template #default="{ id: i }"><textarea :id="i" v-model="secrets.privateKey" rows="5" spellcheck="false" autocomplete="off" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></template></Field>
            <Field label="Passphrase" optional><template #default="{ id: i }"><input :id="i" v-model="secrets.passphrase" type="password" autocomplete="off" /></template></Field>
          </template>
          <HelpNote title="Optional settings">
            <Field label="API address if different from the SSH address" optional hint="Default is https://<SSH host>:8006. Use your public host name here if the API is reached that way (for example a Let's Encrypt certificate); the SSH address can stay internal. Both must be the same node: this is verified." :error="showErr ? fieldErr.apiUrl : ''"><template #default="{ id: i }"><input :id="i" v-model="form.apiUrl" placeholder="https://pve.example.net:8006" /></template></Field>
            <Field label="Address of this Office Unbound server" optional hint="Written as from= into the node's authorized_keys, so the new key only works from here." :error="showErr ? fieldErr.icsAddress : ''"><template #default="{ id: i }"><input :id="i" v-model="form.icsAddress" /></template></Field>
          </HelpNote>
          <div class="wz-row"><button type="button" class="wz-btn primary" :disabled="busy" @click="store">Store and fetch the host key</button></div>
        </div>
        <Banner kind="info">Your SSH password or key goes straight into the encrypted vault, is valid for 30 minutes, can be used for this one purpose only, is never shown or logged, and is destroyed when the job ends.</Banner>
        <Banner v-if="failure" kind="bad">{{ failure }}</Banner>
        <p v-if="errs.connect" class="err" role="alert">{{ errs.connect }}</p>
      </div>

      <!-- 2. host key -->
      <div v-else-if="id === 'hostkey'">
        <h2>Is this really your node?</h2>
        <template v-if="sess?.hostkey_candidate">
          <p>The server presented this host key. <b>Nothing else runs until you confirm it.</b> On the node's own console run:</p>
          <CodeBlock :lines="[sess.hostkey_verify_command ?? '']" label="verify command" />
          <p class="muted small">Compare its SHA256 output with:</p>
          <p class="pv-fp mono" data-test="fingerprint">{{ sess.hostkey_candidate }}</p>
          <Field label="Type or paste the fingerprint to confirm" :error="typed && !fpOk ? 'Looks like SHA256:xxxxxxxx...' : ''">
            <template #default="{ id: i }"><input :id="i" v-model="typed" class="mono" autocomplete="off" spellcheck="false" :disabled="sess.state === 'pinned'" /></template>
          </Field>
          <button v-if="sess.state !== 'pinned'" type="button" class="wz-btn primary" :disabled="busy || !sameFingerprint(typed, sess.hostkey_candidate)" @click="confirmKey">The fingerprints are identical: pin it</button>
          <Banner v-else kind="ok" title="Pinned">This host key is pinned for the whole flow and for the node account Office Unbound will create. A different key later stops everything.</Banner>
        </template>
        <button v-else type="button" class="wz-btn" :disabled="busy" @click="fetchKey">Fetch the host key</button>
        <Banner v-if="failure" kind="bad">{{ failure }}</Banner>
        <p v-if="errs.hostkey" class="err" role="alert">{{ errs.hostkey }}</p>
      </div>

      <!-- 3. discover -->
      <div v-else-if="id === 'discover'">
        <h2>Read the cluster</h2>
        <p class="muted">Read-only: fixed <span class="mono">pvesh get</span> commands. It also reads the node's API certificate and checks it against what this server sees on port 8006; a mismatch stops everything.</p>
        <button type="button" class="wz-btn primary" :disabled="runBusy" @click="runDiscover">{{ overview ? 'Run again' : 'Discover' }}</button>
        <RunPanel :run="run" what="Reading the cluster" />
        <template v-if="overview">
          <Banner v-if="apiCert && !apiCert.needs_confirmation" kind="ok" title="API certificate cross-check">{{ apiCert.explanation }} <b>{{ trustLabel(apiCert.mode) }}.</b> API address: <span class="mono">{{ apiCert.url }}</span>. Certificate: <span class="mono small">{{ apiCert.seen_leaf }}</span></Banner>
          <template v-if="apiCert?.needs_confirmation">
            <Banner kind="warn" title="Something sits in front of the API">{{ apiCert.explanation }}</Banner>
            <dl class="wz-dl"><dt>Certificate the node serves</dt><dd class="mono small">{{ apiCert.node_leaf }}</dd><dt>Certificate the API address presents</dt><dd class="mono small" data-test="proxy-fp">{{ apiCert.seen_leaf }}</dd></dl>
            <Field label="Type the proxy's certificate fingerprint (the second one) to confirm"><template #default="{ id: i }"><input :id="i" v-model="proxyTyped" class="mono" autocomplete="off" spellcheck="false" :disabled="sess?.api_proxy === 'confirmed'" /></template></Field>
            <button v-if="sess?.api_proxy !== 'confirmed'" type="button" class="wz-btn primary" :disabled="busy || !proxyTyped.trim()" @click="confirmProxy">I know about this proxy: continue</button>
            <Banner v-else kind="ok" title="Confirmed">The chain must still be valid for the host name every time.</Banner>
          </template>
          <dl class="wz-dl">
            <dt>Cluster</dt><dd>{{ overview.cluster_name ?? '(single node)' }}, Proxmox VE {{ overview.pve_version }}</dd>
            <dt>Connected node</dt><dd>{{ overview.connected_node }}</dd>
            <dt>Nodes</dt><dd>{{ overview.nodes.map((n) => `${n.name} (${n.status})`).join(', ') }}</dd>
            <dt>Storage</dt><dd>{{ overview.storages.map((s) => `${s.name} (${s.type}${s.shared ? ', shared' : ''})`).join(', ') }}</dd>
            <dt>Networks</dt><dd>{{ overview.networks.map((n) => n.name).join(', ') || 'none found' }}</dd>
            <dt>Pools</dt><dd>{{ overview.pools.join(', ') || 'none' }}</dd>
            <dt>Thin pools</dt><dd>
              <span v-if="!overview.storage_usage?.thin_pools.length && !overview.storage_usage?.zfs.length" class="muted">none found on this node</span>
              <div v-for="t in overview.storage_usage?.thin_pools ?? []" :key="t.vg + t.pool"><b>{{ t.vg }}/{{ t.pool }}</b> ({{ t.storages.join(', ') || 'no PVE storage' }}): {{ fmtTib(t.physical_bytes) }} physical, data {{ t.data_percent ?? '?' }}% / metadata {{ t.metadata_percent ?? '?' }}% used, {{ fmtTib(t.provisioned_bytes) }} provisioned = <b>{{ t.overprovision_ratio }}x</b><span v-for="w in t.warnings" :key="w" class="wz-chip warn"> {{ w }}</span></div>
              <div v-for="z in overview.storage_usage?.zfs ?? []" :key="z.pool"><b>{{ z.pool }}</b> (ZFS): {{ fmtTib(z.physical_bytes) }} physical, {{ fmtTib(z.provisioned_bytes) }} of volumes = <b>{{ z.overprovision_ratio ?? '?' }}x</b></div>
            </dd>
            <dt>Firewall</dt><dd>
              Datacenter firewall: <b>{{ overview.firewall?.datacenter_enabled ? 'ON' : 'OFF' }}</b>. Nodes with rules: {{ overview.firewall?.nodes_with_rules.join(', ') || 'none' }}.
              <span v-if="overview.firewall?.rules_would_become_active_on.length" class="wz-chip warn">would become active if the datacenter firewall is enabled: {{ overview.firewall.rules_would_become_active_on.join(', ') }}</span>
              <div class="muted small">{{ overview.firewall?.nodes.map((n) => `${n.name}: ${n.rules} rule(s)`).join(' | ') }}. Read-only: no other node is logged in to.</div>
            </dd>
            <dt>Guests</dt><dd>{{ overview.guests.total }} ({{ overview.guests.running }} running, {{ overview.guests.templates }} templates). They are only counted, never touched.</dd>
          </dl>
          <Banner v-if="overview.existing.service_user" kind="warn" title="Already onboarded">An officeunbound@pve account exists. Continuing re-uses it and rotates its token.</Banner>
        </template>
        <p v-if="errs.discover" class="err" role="alert">{{ errs.discover }}</p>
      </div>

      <!-- 4. choose -->
      <div v-else-if="id === 'choose' && overview">
        <h2>What may Office Unbound do, and where?</h2>
        <fieldset class="wz-field"><legend>Scope</legend>
          <label><input type="radio" name="sel-mode" :checked="sel.mode === 'single_node'" @change="sel.mode = 'single_node'" /> One node only (recommended for security)</label>
          <label><input type="radio" name="sel-mode" :checked="sel.mode === 'whole_cluster'" @change="sel.mode = 'whole_cluster'" /> The whole cluster</label>
        </fieldset>
        <fieldset v-if="needSingleNode" class="wz-field"><legend>Node</legend>
          <label v-for="n in overview.nodes" :key="n.name"><input type="radio" :checked="sel.nodes[0] === n.name" name="node" @change="sel.nodes = [n.name]" /> {{ n.name }} <span class="muted small">({{ n.status }}{{ n.local ? ', this session' : '' }})</span></label>
          <p v-if="errs.nodes" class="err" role="alert">{{ errs.nodes }}</p>
          <p class="muted small">The SSH identity is installed on the node you are connected to ({{ overview.connected_node }}), so a single-node scope must be that node. For the whole cluster one node is enough: <span class="mono">/etc/pve</span> and the API token are cluster-wide.</p>
        </fieldset>
        <fieldset class="wz-field"><legend>Rights</legend>
          <label v-for="r in RIGHTS" :key="r.id" class="pv-opt"><input type="radio" name="sel-rights" :checked="sel.rights === r.id" @change="sel.rights = r.id" /> <b>{{ r.title }}</b><span class="muted small"> {{ r.text }}</span></label>
          <div v-if="sel.rights === 'custom'" class="pv-advanced"><label v-for="a in ADVANCED" :key="a.id"><input type="checkbox" :checked="sel.advanced.includes(a.id)" @change="toggle(sel.advanced, a.id)" /> {{ a.title }}</label>
            <p v-if="errs.advanced" class="err" role="alert">{{ errs.advanced }}</p></div>
        </fieldset>
        <template v-if="sel.rights !== 'inventory'">
          <Field label="Pool" :error="errs.pool" hint="A dedicated pool keeps Office Unbound's guests together. It is created if it does not exist.">
            <template #default="{ id: i }"><input :id="i" v-model="sel.pool" list="pools" /><datalist id="pools"><option v-for="p in overview.pools" :key="p" :value="p" /></datalist></template>
          </Field>
          <fieldset class="wz-field"><legend>Storage</legend>
            <label v-for="s in (needSingleNode ? localStorages : overview.storages)" :key="s.name"><input type="checkbox" :checked="sel.storages.includes(s.name)" @change="toggle(sel.storages, s.name)" /> {{ s.name }} <span class="muted small">{{ s.type }}{{ s.shared ? ', shared' : '' }}</span></label>
            <p v-if="needSingleNode && overview.storages.some((s) => s.shared)" class="muted small">Shared storage is hidden: it is reachable from other nodes, so it does not fit a one-node scope.</p>
            <p v-if="errs.storages" class="err" role="alert">{{ errs.storages }}</p></fieldset>
          <fieldset class="wz-field"><legend>Networks (bridges / VLANs)</legend>
            <label v-for="n in overview.networks" :key="n.name"><input type="checkbox" :checked="sel.networks.includes(n.name)" @change="toggle(sel.networks, n.name)" /> {{ n.name }}</label></fieldset>
          <fieldset class="wz-field"><legend>Templates Office Unbound may clone</legend>
            <label v-for="t in overview.templates" :key="t.vmid"><input type="checkbox" :checked="sel.templates.includes(t.vmid)" @change="toggleN(sel.templates, t.vmid)" /> {{ t.vmid }} {{ t.name }} <span class="muted small">on {{ t.node }}</span></label>
            <p v-if="!overview.templates.length" class="muted small">No templates found.</p></fieldset>
        </template>
        <HelpNote title="The policy this builds (sent to the permission-plan generator)"><pre class="mono small">{{ policyPreview }}</pre></HelpNote>
      </div>

      <!-- 5. review -->
      <div v-else-if="id === 'review' && !isOff">
        <h2>Exactly what will happen</h2>
        <Field v-if="!epId" label="Name of this integration"><template #default="{ id: i }"><input :id="i" v-model="name" /></template></Field>
        <button type="button" class="wz-btn primary" :disabled="runBusy || !name && !epId" @click="runPreview">{{ preview ? 'Preview again' : 'Preview the changes' }}</button>
        <RunPanel :run="run" what="Computing the permission plan" />
        <template v-if="preview && planForView">
          <Banner kind="warn" title="High risk: needs approval">This changes accounts and permissions on your Proxmox node, so it needs {{ preview.approvals_required ?? 2 }} different approvers. Nothing runs before they approve.</Banner>
          <PlanView :preview="planForView as never" />
          <h3>Office Unbound's own SSH access on {{ preview.identity.node }}</h3>
          <dl class="wz-dl">
            <dt>Linux account</dt><dd class="mono">{{ preview.identity.account }} (locked password, no login except the one forced command)</dd>
            <dt>Key fingerprint</dt><dd class="mono">{{ preview.identity.key_fingerprint }} (ed25519; the private key is generated here and only ever stored in the vault)</dd>
            <dt>authorized_keys</dt><dd class="mono small">{{ preview.identity.authorized_keys_line }}</dd>
            <dt>Helper</dt><dd><span class="mono">{{ preview.identity.helper_path }}</span> sha256 <span class="mono small">{{ preview.identity.helper_sha256 }}</span>. It accepts only named, validated operations: read-only discovery, certificate read, drift check, rotating its own token and narrowing its own permissions. No shell, no pveum passthrough.</dd>
            <dt>sudoers</dt><dd><pre class="mono small">{{ preview.identity.sudoers }}</pre></dd>
            <dt>Pinned</dt><dd class="mono small">SSH host key {{ preview.ssh.host_key }}<br />API {{ preview.ssh.api_url }}: {{ trustLabel(preview.ssh.api_trust) }}<template v-if="preview.ssh.api_leaf_pinned"><br />certificate {{ preview.ssh.api_leaf_pinned }}</template></dd>
          </dl>
          <h3>The exact commands (nothing else is executed)</h3>
          <CodeBlock :lines="preview.commands" label="commands" />
          <Banner v-if="preview.rotates.length" kind="warn" title="Token rotation">Existing tokens are replaced so the new secret can be captured: {{ preview.rotates.join(', ') }}.</Banner>
          <Banner kind="info" title="Widening later">{{ preview.widening_note }}</Banner>
        </template>
        <Banner v-if="failure" kind="bad">{{ failure }}</Banner>
        <p v-if="errs.review" class="err" role="alert">{{ errs.review }}</p>
      </div>
      <div v-else-if="id === 'review'">
        <h2>Remove what SSH onboarding created</h2>
        <p>This deletes the <span class="mono">officeunbound@pve</span> account, its tokens, the Office Unbound roles and permissions, and on the node the <span class="mono">ou-ics</span> account, its key, the helper, its configuration and the sudoers file. Guests are never touched. A pool is only removed if it is empty and Office Unbound created it.</p>
        <Field label="Type the integration name to confirm"><template #default="{ id: i }"><input :id="i" v-model="confirmName" autocomplete="off" /></template></Field>
        <label><input v-model="deletePool" type="checkbox" /> Also delete the pool if it is empty</label>
        <p v-if="errs.confirm" class="err" role="alert">{{ errs.confirm }}</p>
      </div>

      <!-- 6. apply -->
      <div v-else-if="id === 'apply'">
        <h2>{{ isOff ? 'Remove' : 'Apply' }}</h2>
        <p class="muted">The job reconnects with the pinned host key, runs only the commands you reviewed, verifies the result{{ isOff ? '' : ' (the new token\'s permissions must equal the plan exactly, and the new SSH key must work and be refused for everything except the helper)' }}, then destroys your SSH credential. Any failure rolls back what it created.</p>
        <button v-if="!runCreated || runView?.phase === 'failed'" type="button" class="wz-btn primary" :disabled="runBusy" @click="isOff ? runOffboard() : runApply()">{{ isOff ? 'Remove the access' : 'Submit for approval and apply' }}</button>
        <RunPanel :run="run" :what="isOff ? 'Removing the access' : 'Onboarding the cluster'" />
        <p v-if="errs.apply" class="err" role="alert">{{ errs.apply }}</p>
      </div>

      <!-- 7. done -->
      <div v-else class="pv-done">
        <div class="pv-bigcheck" aria-hidden="true">&#10003;</div>
        <h2>{{ isOff ? 'The access was removed' : 'Connected' }}</h2>
        <p class="muted">Your SSH credential has been destroyed. {{ isOff ? '' : 'From now on Office Unbound uses only the account, token and key it created itself.' }}</p>
        <div class="wz-row mt">
          <router-link v-if="done && (done as any).endpoint_id" class="wz-btn primary" :to="`/infrastructure/providers/${(done as any).endpoint_id}`">Open the cluster</router-link>
          <router-link class="wz-btn" to="/infrastructure/providers">All clusters</router-link>
        </div>
      </div>
    </WizardShell>
  </div>
</template>
