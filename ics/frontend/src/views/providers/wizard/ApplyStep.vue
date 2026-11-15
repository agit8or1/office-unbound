<script setup lang="ts">
// Step 5: do it. Existing token: register. Set it up for me: apply the previewed plan. Package: generate, deliver, get customer approval, import tokens.
import { computed, onMounted, ref } from 'vue'
import { Banner, CodeBlock, Field, HelpNote } from '../../../wizards/kit'
import type { Errors } from '../../../wizards/kit'
import CredFields from '../CredFields.vue'
import RunPanel from '../RunPanel.vue'
import { api, msg, packageUrl, type Customer } from '../api'
import {
  applyParams, importParams, inventoryTokenId, needsProvisionToken, packageParams, provisionTokenIdFor, registerParams, riskOf, validateCreds, wipe, wipeAdmin,
  type SecretBag, type WizardModel,
} from '../model'
import { TOKEN_SECRET_RE } from '../../../wizards/kit'
import { useRun, type Run } from '../run'

export interface Outcome { verification: Record<string, { ok: boolean; verbs?: { verb: string; ok: boolean; missing?: unknown[] }[]; missing?: { path: string; privileges: string[] }[]; unexpected?: { path: string; privileges: string[] }[] }> | null; applied: string[]; version: string | null }
const props = defineProps<{ m: WizardModel; s: SecretBag; errors: Errors; run: Run; outcome: Outcome }>()
const emit = defineEmits<{ errors: [Errors]; done: [] }>()
const local = ref<Errors>({})
const providerId = computed(() => props.m.endpointId ?? 'unbound')
const risk = computed(() => riskOf(props.m))

function take(r: unknown) {
  const o = (r ?? {}) as { endpoint_id?: string; verification?: Outcome['verification']; applied?: string[]; pve_version?: string }
  if (o.endpoint_id) props.m.endpointId = o.endpoint_id
  props.outcome.verification = o.verification ?? null
  props.outcome.applied = o.applied ?? []
  props.outcome.version = o.pve_version ?? props.m.probe?.version ?? null
  emit('errors', {}); emit('done')
}

async function register() {
  const job = await props.run.start('endpoint.register', registerParams(props.m, props.s))
  wipe(props.s) // the token secrets are gone from the page now
  if (job?.status === 'succeeded') take(job.result)
}
async function applyNow() {
  local.value = validateCreds(props.m, props.s)
  if (Object.keys(local.value).length) return
  const job = await props.run.start('provider.provision.apply', applyParams(props.m, props.s))
  wipeAdmin(props.s)
  if (job?.status === 'succeeded') take(job.result)
}

// ---- package mode
const pkgRun = useRun()
const files = ref<Record<string, string> | null>(null)
const customers = ref<Customer[]>([])
const customerId = ref('')
const approvalTitle = ref('')
const ttl = ref(72)
const link = ref<{ url: string; expires: string } | null>(null)
const approvalBusy = ref(false), approvalError = ref(''), approvalId = ref('')
const importLocal = ref<Errors>({})
const copied = ref(false)
onMounted(async () => {
  approvalTitle.value = `Proxmox access for ${props.m.displayName || props.m.name}`
  if (props.m.method === 'package') { try { customers.value = (await api.customers()).filter((c) => !c.disabled_at); customerId.value = props.m.customerId ?? customers.value.find((c) => !c.msp_owned)?.id ?? '' } catch { /* customers optional */ } }
  if (props.m.packageId) await loadFiles()
})
async function generate() {
  const job = await pkgRun.start('provider.provision.package', packageParams(props.m))
  const r = job?.status === 'succeeded' ? (job.result as { package_id?: string }) : null
  if (r?.package_id) { props.m.packageId = r.package_id; await loadFiles() }
}
async function loadFiles() {
  if (!props.m.packageId) return
  try {
    const f = (await api.packageFiles(providerId.value, props.m.packageId)).files
    files.value = f
    const pj = JSON.parse(f['package.json'] ?? '{}') as { plan?: { facts?: { tokens?: Record<string, string>; service_user?: string } } }
    const facts = pj.plan?.facts
    if (facts?.tokens) props.m.packageTokens = facts.tokens
    if (facts?.service_user) props.m.packageUser = facts.service_user
  } catch (e) { approvalError.value = msg(e) }
}
const commands = computed(() => (files.value?.['commands.txt'] ?? '').split('\n').filter((l) => l.trim()))
const FILES: [string, string][] = [['provision.sh', 'Setup script'], ['rollback.sh', 'Rollback script'], ['commands.txt', 'Commands, one by one'], ['validate.txt', 'Validation commands'], ['report.html', 'Report (print or send)'], ['package.json', 'Machine-readable plan']]
async function sendApproval() {
  approvalError.value = ''
  if (!customerId.value) { approvalError.value = 'Choose the customer who must approve.'; return }
  approvalBusy.value = true
  try {
    const perms = (props.m.preview?.plan.steps ?? []).filter((x) => x.kind === 'acl' && x.op !== 'noop').map((x) => { const [path, , role] = x.target.split('|'); return { path: path ?? '', privilege: role ?? '', reason: x.reason || 'Granted to the Office Unbound service account' } })
    const a = await api.createApproval({ customer_id: customerId.value, title: approvalTitle.value, params: { provider: 'proxmox', summary: `Create a restricted service account for Office Unbound (${props.m.preset === 'deploy' ? 'deployment and management' : props.m.preset}).`, permissions: perms, package_id: props.m.packageId } })
    approvalId.value = a.id
    const sub = await api.submitApproval(a.id, ttl.value)
    link.value = { url: location.origin + sub.link_path, expires: sub.expires_at }
  } catch (e) { approvalError.value = msg(e) } finally { approvalBusy.value = false }
}
async function copyLink() { try { await navigator.clipboard.writeText(link.value?.url ?? ''); copied.value = true; setTimeout(() => (copied.value = false), 1500) } catch { /* clipboard blocked */ } }

const importRun = pkgRun
async function importTokens() {
  const e: Errors = {}
  if (!TOKEN_SECRET_RE.test(props.s.importInventory.trim())) e.importInventory = 'Paste the inventory token secret from the customer.'
  if (needsProvisionToken(props.m) && !TOKEN_SECRET_RE.test(props.s.importProvision.trim())) e.importProvision = 'Paste the provisioning token secret from the customer.'
  importLocal.value = e
  if (Object.keys(e).length) return
  const job = await importRun.start('provider.credential.import', importParams(props.m, props.s))
  wipe(props.s)
  if (job?.status === 'succeeded') take(job.result)
}
</script>

<template>
  <div>
    <!-- existing token -->
    <div v-if="m.method === 'token'" class="wz-card">
      <h2>Connect the cluster</h2>
      <p class="muted">Office Unbound registers the token, saves your limits and starts reading the cluster. Nothing in Proxmox is changed.</p>
      <Banner v-if="m.endpointId" kind="ok" title="Connected">The cluster is registered. Continue to verify the permissions.</Banner>
      <template v-else>
        <div class="wz-row"><button type="button" class="wz-btn primary" :disabled="run.busy.value" @click="register">{{ run.busy.value ? 'Connecting...' : riskOf(m) === 'high' ? 'Submit for approval' : 'Connect cluster' }}</button></div>
        <p class="muted small mt">Registering a cluster is a high-impact change: it needs two approvers unless your organisation's policy says otherwise.</p>
      </template>
      <RunPanel :run="run" what="Registering the cluster" />
    </div>

    <!-- automatic -->
    <div v-else-if="m.method === 'admin'" class="wz-card">
      <h2>Apply the change</h2>
      <Banner v-if="m.endpointId" kind="ok" title="Applied">The account, roles and tokens were created and the result was checked. The temporary login was discarded.</Banner>
      <template v-else>
        <p class="muted">Enter the administrator login again. It is never kept, so the preview and the apply each need it. It is used for this one job and then discarded.</p>
        <CredFields :m="m" :s="s" :errors="local" />
        <div class="wz-row mt"><button type="button" class="wz-btn primary" :disabled="run.busy.value" @click="applyNow">{{ run.busy.value ? 'Working...' : risk === 'high' ? 'Submit for approval' : 'Apply now' }}</button></div>
        <p class="muted small mt">If anything fails, exactly what this run created is removed again. Nothing is ever widened to make a step pass.</p>
      </template>
      <RunPanel :run="run" what="Creating the account and permissions" />
    </div>

    <!-- package -->
    <template v-else>
      <div class="wz-card">
        <h2>1. Generate the package</h2>
        <Banner v-if="m.packageId" kind="ok" title="Package ready">Nothing has been sent to the cluster. Give the files below to the customer's administrator.</Banner>
        <template v-else>
          <p class="muted">A script, a plain-language report and a rollback script. The files contain no secrets.</p>
          <button type="button" class="wz-btn primary" :disabled="pkgRun.busy.value" @click="generate">{{ pkgRun.busy.value ? 'Generating...' : 'Generate package' }}</button>
        </template>
        <RunPanel v-if="!m.packageId || pkgRun.busy.value" :run="pkgRun" what="Building the package" />
      </div>

      <template v-if="m.packageId && files">
        <div class="wz-card">
          <h2>2. Hand it to the administrator</h2>
          <div class="pv-files">
            <a v-for="f in FILES.filter((x) => files![x[0]])" :key="f[0]" class="wz-btn" :href="packageUrl(providerId, m.packageId!, f[0])" :download="f[0]" rel="noopener"><b>{{ f[1] }}</b><span class="muted small mono">{{ f[0] }}</span></a>
            <a class="wz-btn primary" :href="packageUrl(providerId, m.packageId!, 'zip')" download>Download everything (.zip)</a>
          </div>
          <HelpNote title="Prefer to copy and paste the commands?"><CodeBlock :lines="commands" label="setup commands" /></HelpNote>
          <p class="muted small">The script is safe to run twice. It stops if something unexpected already exists, and <span class="mono">rollback.sh</span> removes what it created.</p>
        </div>

        <div class="wz-card">
          <h2>3. Customer approval (optional)</h2>
          <p class="muted">If the cluster belongs to a customer, send them a private page where they can review and approve exactly these permissions. No account needed.</p>
          <Banner v-if="link" kind="ok" title="Approval link created">Copy it now. It is shown only once and works for one decision.
            <div class="pv-link"><input type="text" readonly :value="link.url" aria-label="Approval link" /><button type="button" class="wz-btn" @click="copyLink">{{ copied ? 'Copied' : 'Copy link' }}</button></div>
            <p class="small">Send it through a channel you trust (not by guessable email subjects). Expires {{ new Date(link.expires).toLocaleString() }}. Approval status appears under Customers.</p></Banner>
          <div v-else class="wz-grid two">
            <Field label="Customer" v-slot="{ id }"><select :id="id" v-model="customerId"><option value="">Choose...</option><option v-for="c in customers" :key="c.id" :value="c.id">{{ c.name }}</option></select></Field>
            <Field label="Link valid for" v-slot="{ id }"><select :id="id" v-model.number="ttl"><option :value="24">1 day</option><option :value="72">3 days</option><option :value="168">7 days</option></select></Field>
            <Field label="Title the customer sees" v-slot="{ id }"><input :id="id" v-model="approvalTitle" type="text" /></Field>
            <div class="wz-row"><button type="button" class="wz-btn" :disabled="approvalBusy" @click="sendApproval">{{ approvalBusy ? 'Creating...' : 'Create approval link' }}</button></div>
          </div>
          <Banner v-if="approvalError" kind="bad">{{ approvalError }}</Banner>
        </div>

        <div class="wz-card">
          <h2>4. Import the tokens</h2>
          <Banner v-if="m.endpointId" kind="ok" title="Imported">The tokens match the package, so the cluster is connected.</Banner>
          <template v-else>
            <p class="muted">When the administrator has run the script, they send you the token secrets (the script prints each once). Paste them here. They are checked against the package before anything is saved.</p>
            <div class="wz-grid two">
              <Field :label="'Secret for ' + inventoryTokenId(m)" :error="importLocal.importInventory" v-slot="{ id, invalid }"><input :id="id" v-model="s.importInventory" type="password" autocomplete="new-password" :aria-invalid="invalid" /></Field>
              <Field v-if="needsProvisionToken(m)" :label="'Secret for ' + provisionTokenIdFor(m)" :error="importLocal.importProvision" v-slot="{ id, invalid }"><input :id="id" v-model="s.importProvision" type="password" autocomplete="new-password" :aria-invalid="invalid" /></Field>
            </div>
            <button type="button" class="wz-btn primary" :disabled="pkgRun.busy.value" @click="importTokens">{{ pkgRun.busy.value ? 'Checking...' : 'Check and import' }}</button>
            <RunPanel v-if="m.packageId && (pkgRun.created.value || pkgRun.error.value)" :run="pkgRun" what="Validating the tokens against the package" />
          </template>
        </div>
      </template>
    </template>
  </div>
</template>
