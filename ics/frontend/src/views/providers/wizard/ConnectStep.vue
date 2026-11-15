<script setup lang="ts">
// Step 1: where is the cluster, is it really your server, and how should Office Unbound get access.
import { computed, ref, watch } from 'vue'
import { Banner, CodeBlock, Field, HelpNote } from '../../../wizards/kit'
import type { Errors } from '../../../wizards/kit'
import { api, msg } from '../api'
import {
  FINGERPRINT_CMD, connectionKey, fingerprintMismatch, identityKey, identityVerified, normDiscovery, probeRequest, suggestName, tlsRequest, validateIdentity,
  type AuthMethod, type SecretBag, type WizardModel,
} from '../model'
import { normalizeFingerprint } from '../../../wizards/kit'

const props = defineProps<{ m: WizardModel; s: SecretBag; errors: Errors }>()
const emit = defineEmits<{ errors: [Errors] }>()
const err = (k: string) => props.errors[k]
const checking = ref(false), probing = ref(false), tlsError = ref(''), probeError = ref('')
const verified = computed(() => identityVerified(props.m))
const mismatch = computed(() => fingerprintMismatch(props.m))
const tlsCurrent = computed(() => !!props.m.tls && props.m.tlsKey === identityKey(props.m))
const probeCurrent = computed(() => !!props.m.probe && props.m.probedKey === connectionKey(props.m))
const entered = computed(() => normalizeFingerprint(props.m.fingerprint))
const nameTouched = ref(false)
watch(() => props.m.host, (h) => { if (!nameTouched.value) props.m.name = suggestName(h) })

const METHODS: { id: AuthMethod; title: string; text: string; tag: string }[] = [
  { id: 'token', title: 'I already have an API token', text: 'Paste a token that was created for Office Unbound. Nothing is changed in Proxmox.', tag: 'Fastest' },
  { id: 'admin', title: 'Set it up for me', text: 'Use a temporary administrator login once to create a restricted account and tokens. The login is discarded straight after.', tag: 'Automatic' },
  { id: 'package', title: 'Send a setup package to the cluster\'s administrator', text: 'Generate a script and report your customer\'s administrator can review and run. You import the tokens afterwards.', tag: 'Customer-run' },
]

async function checkCertificate() {
  tlsError.value = ''
  const e = validateIdentity(props.m)
  emit('errors', e)
  if (Object.keys(e).length) return
  checking.value = true
  try {
    const key = identityKey(props.m)
    const r = await api.probeTls(tlsRequest(props.m))
    props.m.tls = r.tls; props.m.tlsKey = key
  } catch (x) { props.m.tls = null; props.m.tlsKey = null; tlsError.value = msg(x) } finally { checking.value = false }
}
async function testConnection() {
  probeError.value = ''
  if (!verified.value) { emit('errors', { identity: 'Check the server certificate first.' }); return }
  probing.value = true
  try {
    const key = connectionKey(props.m)
    const r = await api.probe(probeRequest(props.m, props.s))
    props.m.probe = r; props.m.probedKey = key
    props.m.discovery = normDiscovery(r.discovery)
    props.m.scopeSuggested = false
    emit('errors', {})
  } catch (x) { props.m.probe = null; props.m.probedKey = null; probeError.value = msg(x) } finally { probing.value = false }
}
const unnecessary = computed(() => props.m.probe?.permissions?.inventory.unnecessary ?? [])
const fixes = computed(() => [...(props.m.probe?.permissions?.inventory.fix_commands ?? []), ...(props.m.probe?.permissions?.provision.fix_commands ?? [])])
</script>

<template>
  <div>
    <div class="wz-card">
      <h2>Which cluster?</h2>
      <p class="muted">Enter any node of the cluster. Office Unbound will confirm it is really your server before it sends anything secret.</p>
      <div class="wz-grid two">
        <div class="wz-grid hostport">
          <Field label="Server address" :error="err('host')" hint="Name or IP of a Proxmox node." v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.host" type="text" placeholder="pve1.example.com" autocomplete="off" :aria-invalid="invalid" /></Field>
          <Field label="Port" :error="err('port')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.port" type="number" min="1" max="65535" :aria-invalid="invalid" /></Field>
        </div>
        <Field label="Friendly name" :error="err('name')" hint="Shown in the console, for example the site or customer. You can use any text; the short ID is set under Advanced details." v-slot="{ id }"><input :id="id" v-model="m.displayName" type="text" placeholder="Main office cluster" /></Field>
      </div>
    </div>

    <div class="wz-card">
      <h2>Is this really your server?</h2>
      <p class="muted">Compare the certificate fingerprint. Get it from the node itself, not from this page: that is what makes the check meaningful.</p>
      <div class="wz-row">
        <label class="wz-choice"><input v-model="m.trust" type="radio" value="fingerprint" /> Compare a fingerprint</label>
        <label class="wz-choice"><input v-model="m.trust" type="radio" value="ca" /> Trust my CA certificate</label>
      </div>
      <Field v-if="m.trust === 'fingerprint'" label="Fingerprint read on the node" :error="err('fingerprint')" v-slot="{ id, invalid }"><input :id="id" v-model="m.fingerprint" type="text" class="mono" placeholder="AB:CD:EF:..." spellcheck="false" autocomplete="off" :aria-invalid="invalid" /></Field>
      <Field v-else label="CA certificate (PEM)" :error="err('caPem')" v-slot="{ id, invalid }"><textarea :id="id" v-model="m.caPem" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" :aria-invalid="invalid"></textarea></Field>
      <HelpNote title="How do I get the fingerprint?" open>
        <p>On the Proxmox node (its own console or a trusted SSH session) run:</p>
        <CodeBlock :lines="[FINGERPRINT_CMD]" label="fingerprint command" />
        <p class="small muted">A cluster CA is at <span class="mono">/etc/pve/pve-root-ca.pem</span>. A self-signed node certificate must be compared by fingerprint.</p>
      </HelpNote>
      <div class="wz-row mt">
        <button type="button" class="wz-btn primary" :disabled="checking" @click="checkCertificate">{{ checking ? 'Checking...' : 'Check server certificate' }}</button>
        <span v-if="err('identity')" class="bad-text" role="alert">{{ err('identity') }}</span>
      </div>
      <Banner v-if="tlsError" kind="bad" title="Could not reach the server">{{ tlsError }}</Banner>
      <div v-if="tlsCurrent && m.tls" class="mt" aria-live="polite">
        <div v-if="m.tls.presented_fingerprint_sha256 && m.trust === 'fingerprint'" class="pv-fpcmp">
          <div><span class="muted small">You entered</span><div class="mono">{{ entered ?? m.fingerprint }}</div></div>
          <div><span class="muted small">Server presented</span><div class="mono">{{ m.tls.presented_fingerprint_sha256 }}</div></div>
        </div>
        <dl v-if="m.tls.subject || m.tls.not_after" class="wz-dl"><dt v-if="m.tls.subject">Certificate subject</dt><dd v-if="m.tls.subject">{{ m.tls.subject }}</dd><dt v-if="m.tls.not_after">Valid until</dt><dd v-if="m.tls.not_after">{{ m.tls.not_after }}</dd></dl>
        <Banner v-if="verified" kind="ok" title="Identity confirmed">{{ m.trust === 'ca' ? 'The certificate chains to your CA.' : 'The fingerprints are identical.' }} It is safe to continue.</Banner>
        <Banner v-else-if="mismatch" kind="bad" title="The fingerprints do not match">Do not continue. You may be talking to a different server than the one you read the fingerprint from. Check the address, or whether the node certificate was renewed.</Banner>
        <Banner v-else kind="bad" title="Certificate not trusted">{{ m.tls.error ?? 'Fix the fingerprint or CA, then check again.' }}</Banner>
      </div>
    </div>

    <div class="wz-card" :class="{ 'pv-locked': !verified }">
      <h2>How should Office Unbound get access?</h2>
      <p v-if="!verified" class="muted small">Unlocks after the certificate check passes, so credentials are never sent to an unverified server.</p>
      <fieldset class="wz-fieldset" :disabled="!verified">
        <div class="wz-cards pv-methods" role="radiogroup" aria-label="Access method">
          <button v-for="x in METHODS" :key="x.id" type="button" class="wz-pick" role="radio" :aria-checked="m.method === x.id" :aria-pressed="m.method === x.id" @click="m.method = x.id; m.probe = null; m.discovery = null">
            <span class="wz-row"><b>{{ x.title }}</b><span class="wz-chip info">{{ x.tag }}</span></span><span class="muted small">{{ x.text }}</span>
          </button>
        </div>

        <template v-if="m.method === 'token'">
          <div class="wz-grid two mt">
            <Field label="API token ID" :error="err('tokenId')" hint="Looks like user@realm!tokenname" v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.tokenId" type="text" placeholder="ics-inventory@pve!inventory" autocomplete="off" :aria-invalid="invalid" /></Field>
            <Field label="API token secret" :error="err('tokenSecret')" hint="Held in memory until the final step, then wiped. Never shown again." v-slot="{ id, invalid }"><input :id="id" v-model="s.tokenSecret" type="password" autocomplete="new-password" spellcheck="false" :aria-invalid="invalid" /></Field>
          </div>
          <HelpNote title="Advanced details: separate provisioning token">
            <p class="muted small">Optional. A second token that is allowed to create and change VMs (the first one only reads). Needs at least one pool on the next steps.</p>
            <div class="wz-grid two">
              <Field label="Provisioning token ID" :error="err('provisionTokenId')" v-slot="{ id }"><input :id="id" v-model.trim="m.provisionTokenId" type="text" autocomplete="off" /></Field>
              <Field label="Provisioning token secret" v-slot="{ id }"><input :id="id" v-model="s.provisionSecret" type="password" autocomplete="new-password" /></Field>
            </div>
          </HelpNote>
          <HelpNote title="How do I create a token?">
            <CodeBlock :lines="['pveum user add ics-inventory@pve --comment \'Office Unbound read-only inventory\'', 'pveum user token add ics-inventory@pve inventory --privsep 1', 'pveum acl modify / --users ics-inventory@pve --roles PVEAuditor', 'pveum acl modify / --tokens \'ics-inventory@pve!inventory\' --roles PVEAuditor']" label="token commands" />
            <p class="small muted">Run as root on a node. The secret is displayed once. Use a privilege-separated token, never root@pam.</p>
          </HelpNote>
          <div class="wz-row mt">
            <button type="button" class="wz-btn primary" :disabled="probing || !verified" @click="testConnection">{{ probing ? 'Testing...' : 'Test connection' }}</button>
            <span v-if="probing" class="muted small">Logging in, reading permissions and discovering your cluster...</span>
            <span v-if="err('probe')" class="bad-text" role="alert">{{ err('probe') }}</span>
          </div>
          <Banner v-if="probeError" kind="bad" title="Connection test failed">{{ probeError }}</Banner>
          <div v-if="probeCurrent && m.probe" class="mt" aria-live="polite">
            <Banner v-if="m.probe.ok" kind="ok" title="Connected">Proxmox VE {{ m.probe.version }}<template v-if="m.probe.cluster_name"> &middot; cluster {{ m.probe.cluster_name }}</template>. TLS verified and the token works.</Banner>
            <Banner v-else kind="bad" title="Connected, but not usable yet">{{ m.probe.error ?? 'The token is missing permissions Office Unbound needs.' }}</Banner>
            <div v-if="m.probe.permissions" class="wz-table-wrap"><table>
              <thead><tr><th>Permission set</th><th>Used for</th><th>Result</th><th>Missing</th></tr></thead>
              <tbody>
                <tr><td><b>Read inventory</b></td><td>See nodes, storage, networks and guests</td><td><span class="wz-chip" :class="m.probe.permissions.inventory.ok ? 'ok' : 'bad'">{{ m.probe.permissions.inventory.ok ? 'Granted' : 'Missing' }}</span></td>
                  <td><div v-for="x in m.probe.permissions.inventory.missing" :key="x.path + x.privilege" class="mono">{{ x.privilege }} on {{ x.path }}</div><span v-if="!m.probe.permissions.inventory.missing.length" class="muted">nothing</span></td></tr>
                <tr><td><b>Create and change VMs</b></td><td>Optional: needed only for deployments</td><td><span class="wz-chip" :class="m.probe.permissions.provision.ok ? 'ok' : 'warn'">{{ m.probe.permissions.provision.ok ? 'Granted' : m.provisionTokenId ? 'Missing' : 'Not configured' }}</span></td>
                  <td><div v-for="x in m.probe.permissions.provision.missing" :key="x.path + x.privilege" class="mono">{{ x.privilege }} on {{ x.path }}</div><span v-if="!m.probe.permissions.provision.missing.length" class="muted">nothing</span></td></tr>
              </tbody></table></div>
            <Banner v-if="unnecessary.length" kind="warn" title="Broader than needed">This token also holds {{ unnecessary.map((u) => u.privilege).join(', ') }}, which Office Unbound never uses. Removing {{ unnecessary.length > 1 ? 'them' : 'it' }} keeps the token least-privilege.</Banner>
            <Banner v-if="m.probe.self_vm" kind="warn" title="This token can reach the Office Unbound server itself">VM {{ m.probe.self_vm.vmid }} on {{ m.probe.self_vm.node }} is protected from changes by Office Unbound, but Proxmox would allow them. Keep it out of the authorised pool.</Banner>
            <template v-if="fixes.length"><h3>Commands that would grant the missing permissions (run as root on a node)</h3><CodeBlock :lines="fixes" label="fix commands" /></template>
          </div>
        </template>

        <template v-else-if="m.method === 'admin'">
          <Banner kind="info" title="How the temporary login is handled">You will be asked for it when you apply the change. It is sent once, kept encrypted for at most 15 minutes, used only for this job and then removed. It is never saved or written to the audit log.</Banner>
        </template>
        <template v-else>
          <Field label="Proxmox VE version of the cluster" hint="Privilege names differ between versions 8 and 9. Run pveversion on a node if unsure." v-slot="{ id }">
            <select :id="id" v-model.number="m.pveMajor"><option :value="9">Proxmox VE 9</option><option :value="8">Proxmox VE 8</option></select>
          </Field>
          <Banner kind="info" title="No login needed here">Office Unbound will generate a script, a plain-language report and a rollback script. Nothing is sent to the cluster until the customer's administrator runs it.</Banner>
        </template>
      </fieldset>
    </div>

    <HelpNote title="Advanced details: short ID">
      <Field label="Short ID" :error="err('name')" hint="Lowercase letters, digits, - and _. Used in URLs and the audit log. Cannot be changed later." v-slot="{ id, invalid }"><input :id="id" v-model="m.name" type="text" :aria-invalid="invalid" @input="nameTouched = true" /></Field>
    </HelpNote>
  </div>
</template>
