<script setup lang="ts">
// Connection step shared by the first-run setup and the "edit connection" flow.
// Two stages: (1) verify server identity (certificate fingerprint compared out of band; NO credentials sent), (2) credentials + permission test.
import { computed, ref } from 'vue'
import { api, ApiError } from '../api'
import type { Errors } from '../kit'
import { Banner, CodeBlock, Field, HelpNote, Unavailable } from '../kit'
import type { SetupModel } from './state'
import {
  connectionKey, fingerprintMismatch, fixCommands, identityKey, identityVerified, probeIsCurrent, probeRequest, sdnMissing, storageFor, tlsRequest,
  unnecessaryList, validateCredentialFields, validateIdentityFields,
} from './state'

const props = defineProps<{ m: SetupModel; errors: Errors; editing?: boolean }>()
const emit = defineEmits<{ (e: 'errors', v: Errors): void }>()
const err = (k: string) => props.errors[k]

const checking = ref(false)
const probing = ref(false)
const tlsError = ref('')
const probeError = ref('')
const missingEndpoint = ref('')
const verified = computed(() => identityVerified(props.m))
const mismatch = computed(() => fingerprintMismatch(props.m))
const tlsCurrent = computed(() => !!props.m.tlsCheck && props.m.tlsKey === identityKey(props.m))
const fixes = computed(() => fixCommands(props.m))
const sdn = computed(() => sdnMissing(props.m))
const extra = computed(() => unnecessaryList(props.m))

async function checkCertificate() {
  tlsError.value = ''; missingEndpoint.value = ''
  const e = validateIdentityFields(props.m)
  emit('errors', e)
  if (Object.keys(e).length) return
  checking.value = true
  try {
    const key = identityKey(props.m)
    const r = await api.probeTls(tlsRequest(props.m))
    props.m.tlsCheck = r.tls; props.m.tlsKey = key
  } catch (x) {
    props.m.tlsCheck = null; props.m.tlsKey = null
    if (x instanceof ApiError && x.status === 404) missingEndpoint.value = 'POST /api/v1/setup/probe'
    else tlsError.value = x instanceof Error ? x.message : String(x)
  } finally { checking.value = false }
}

async function testConnection() {
  probeError.value = ''; missingEndpoint.value = ''
  const e = { ...validateIdentityFields(props.m), ...validateCredentialFields(props.m) }
  emit('errors', e)
  if (Object.keys(e).length || !verified.value) return
  probing.value = true
  try {
    const key = connectionKey(props.m)
    const r = await api.probe(probeRequest(props.m))
    props.m.probe = r; props.m.probedKey = key
    const d = props.m.defaults
    if (r.discovery && !props.editing) { d.storage ||= storageFor(props.m, 'images')[0]?.id ?? ''; d.bridge ||= r.discovery.networks[0]?.name ?? '' }
  } catch (x) {
    props.m.probe = null; props.m.probedKey = null
    if (x instanceof ApiError && x.status === 404) missingEndpoint.value = 'POST /api/v1/setup/probe'
    else probeError.value = x instanceof Error ? x.message : String(x)
  } finally { probing.value = false }
}
</script>

<template>
  <div>
    <div class="wz-card">
      <h2>1. Server identity</h2>
      <p class="muted">Before any token is sent, confirm that you are talking to the right server. TLS is always verified; there is no "skip verification" option.</p>
      <div class="wz-grid two">
        <div class="wz-grid hostport">
          <Field label="Host" :error="err('host')" hint="Name or IP of a cluster node." v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.host" type="text" placeholder="pve1.example.internal" autocomplete="off" :aria-invalid="invalid" /></Field>
          <Field label="Port" :error="err('port')" v-slot="{ id, invalid }"><input :id="id" v-model.number="m.port" type="number" min="1" max="65535" :aria-invalid="invalid" /></Field>
        </div>
        <div>
          <div class="wz-row">
            <label class="wz-choice"><input v-model="m.trust" type="radio" value="fingerprint" /> Pin the certificate fingerprint</label>
            <label class="wz-choice"><input v-model="m.trust" type="radio" value="ca" /> Trust a CA certificate</label>
          </div>
          <Field v-if="m.trust === 'fingerprint'" label="Expected SHA-256 fingerprint" :error="err('fingerprint')" v-slot="{ id, invalid }">
            <input :id="id" v-model="m.fingerprint" type="text" class="mono" placeholder="AB:CD:EF:..." spellcheck="false" :aria-invalid="invalid" />
          </Field>
          <Field v-else label="Cluster CA certificate (PEM)" :error="err('caPem')" v-slot="{ id, invalid }">
            <textarea :id="id" v-model="m.caPem" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" :aria-invalid="invalid"></textarea>
          </Field>
        </div>
      </div>
      <HelpNote title="How do I get the fingerprint safely?" open>
        <p>Run this <b>on the Proxmox node itself</b> (console, or an SSH session you already trust) and paste the result above. Do not take the value from this page: that would only prove the server matches itself.</p>
        <CodeBlock :lines="['openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256']" label="fingerprint command" />
        <p class="small">Or paste the cluster CA from <span class="mono">/etc/pve/pve-root-ca.pem</span> and choose "Trust a CA certificate". A self-signed node certificate must be pinned by fingerprint.</p>
      </HelpNote>
      <div class="wz-row mt">
        <button type="button" class="wz-btn primary" :disabled="checking" @click="checkCertificate">{{ checking ? 'Checking…' : 'Check server certificate' }}</button>
        <span v-if="err('identity')" class="bad-text" role="alert">{{ err('identity') }}</span>
      </div>
      <Unavailable v-if="missingEndpoint" what="Connection testing" :endpoint="missingEndpoint" :status="404" />
      <Banner v-if="tlsError" kind="bad" title="Could not check the certificate">{{ tlsError }}</Banner>
      <div v-if="tlsCurrent && m.tlsCheck" class="mt" aria-live="polite">
        <Banner v-if="m.tlsCheck.error" kind="bad" title="TLS error">{{ m.tlsCheck.error }}</Banner>
        <dl v-if="m.tlsCheck.presented_fingerprint_sha256" class="wz-dl">
          <dt>Certificate presented by the server</dt><dd class="mono">{{ m.tlsCheck.presented_fingerprint_sha256 }}</dd>
          <dt v-if="m.tlsCheck.subject">Subject</dt><dd v-if="m.tlsCheck.subject">{{ m.tlsCheck.subject }}</dd>
          <dt v-if="m.tlsCheck.not_after">Valid until</dt><dd v-if="m.tlsCheck.not_after">{{ m.tlsCheck.not_after }}</dd>
        </dl>
        <Banner v-if="verified" kind="ok" title="Identity confirmed">{{ m.trust === 'ca' ? 'The certificate chains to the CA you supplied.' : 'The presented fingerprint matches the one you entered from the node.' }} Credentials can now be entered.</Banner>
        <Banner v-else-if="mismatch" kind="bad" title="Fingerprint does not match">The server presented a different certificate than the one you obtained from the node. Do not continue: you may not be talking to your server. Re-check the value, or the host name.</Banner>
        <Banner v-else-if="!m.tlsCheck.ok" kind="bad" title="Certificate not trusted">Fix the CA or fingerprint, then check again.</Banner>
      </div>
    </div>

    <div class="wz-card">
      <h2>2. Credentials</h2>
      <p v-if="!verified" class="muted">Locked until the server identity is confirmed above, so the token is never sent to an unverified server.</p>
      <fieldset class="wz-fieldset" :disabled="!verified">
        <div class="wz-grid two">
          <Field label="Endpoint name" :error="err('name')" hint="Short identifier shown in the console." v-slot="{ id, invalid }"><input :id="id" v-model="m.name" type="text" autocomplete="off" :readonly="editing" :aria-invalid="invalid" /></Field>
          <Field label="API token ID" :error="err('tokenId')" hint="user@realm!tokenname" v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.tokenId" type="text" placeholder="ics-inventory@pve!inventory" autocomplete="off" :aria-invalid="invalid" /></Field>
          <Field label="API token secret" :error="err('tokenSecret')" :hint="editing ? 'Re-enter the secret: the stored one is never shown or reused here.' : 'Held in memory only until you submit; it is never displayed again.'" v-slot="{ id, invalid }">
            <input :id="id" v-model="m.tokenSecret" type="password" autocomplete="new-password" spellcheck="false" :aria-invalid="invalid" />
          </Field>
        </div>
        <HelpNote title="How do I create the API token?">
          <p>Run on a Proxmox node as root (by the infrastructure owner). The secret is shown once. Use a privilege-separated token, never root@pam.</p>
          <CodeBlock :lines="[
            'pveum user add ics-inventory@pve --comment \'Office Unbound ICS read-only inventory\'',
            'pveum user token add ics-inventory@pve inventory --privsep 1',
            'pveum acl modify / --users ics-inventory@pve --roles PVEAuditor',
            'pveum acl modify / --tokens \'ics-inventory@pve!inventory\' --roles PVEAuditor']" label="token creation" />
        </HelpNote>
        <div class="wz-row mt">
          <button type="button" class="wz-btn primary" :disabled="probing || !verified" @click="testConnection">{{ probing ? 'Testing…' : 'Test connection' }}</button>
          <span v-if="err('probe')" class="bad-text" role="alert">{{ err('probe') }}</span>
        </div>
      </fieldset>
      <Banner v-if="probeError" kind="bad" title="Connection test failed">{{ probeError }}</Banner>
    </div>

    <div v-if="m.probe && probeIsCurrent(m)" class="wz-card" aria-live="polite">
      <h2>Test result</h2>
      <p>
        <span class="wz-chip" :class="m.probe.tls.ok ? 'ok' : 'bad'">TLS {{ m.probe.tls.ok ? 'verified' : 'failed' }}</span>
        <template v-if="m.probe.tls.ok"> by {{ m.probe.tls.verified_by === 'ca' ? 'CA bundle' : 'pinned fingerprint' }}</template>
        <span v-if="m.probe.version" class="muted"> &middot; Proxmox VE {{ m.probe.version }}</span>
        <span v-if="m.probe.cluster_name" class="muted"> &middot; cluster {{ m.probe.cluster_name }}</span>
      </p>
      <Banner v-if="m.probe.tls.error" kind="bad">{{ m.probe.tls.error }}</Banner>
      <h3>Permission matrix</h3>
      <div class="wz-table-wrap"><table>
        <thead><tr><th>Capability</th><th>Used for</th><th>Result</th><th>Missing</th></tr></thead>
        <tbody>
          <tr>
            <td><b>Inventory</b></td><td>Read nodes, storage, networks, guests (required)</td>
            <td><span class="wz-chip" :class="m.probe.permissions.inventory.ok ? 'ok' : 'bad'">{{ m.probe.permissions.inventory.ok ? 'Granted' : 'Missing' }}</span></td>
            <td><div v-for="x in m.probe.permissions.inventory.missing" :key="x.path + x.privilege" class="mono">{{ x.privilege }} on {{ x.path }}</div><span v-if="!m.probe.permissions.inventory.missing.length" class="muted">nothing</span></td>
          </tr>
          <tr>
            <td><b>Provision</b></td><td>Create and change VMs inside the allowed pool (needed for deployments)</td>
            <td><span class="wz-chip" :class="m.probe.permissions.provision.ok ? 'ok' : sdn.length ? 'bad' : 'warn'">{{ m.probe.permissions.provision.ok ? 'Granted' : sdn.length ? 'Blocked' : 'Missing' }}</span></td>
            <td>
              <div v-for="x in m.probe.permissions.provision.missing" :key="x.path + x.privilege" class="mono">{{ x.privilege }} on {{ x.path }}<span v-if="x.privilege === 'SDN.Use'" class="wz-chip bad"> blocks provisioning</span></div>
              <span v-if="!m.probe.permissions.provision.missing.length" class="muted">nothing</span>
            </td>
          </tr>
          <tr v-if="extra.length">
            <td><b>Not needed</b></td><td>Held by the token but never used by ICS</td>
            <td><span class="wz-chip warn">Remove</span></td><td><span v-for="p in extra" :key="p" class="mono">{{ p }} </span></td>
          </tr>
        </tbody>
      </table></div>
      <Banner v-if="sdn.length" kind="bad" title="Provisioning is blocked: SDN.Use is missing on bridges">New VMs cannot be attached to {{ sdn.map((x) => x.path).join(', ') }}. Grant it with the command below, then test again.</Banner>
      <Banner v-if="extra.length" kind="warn" title="Unnecessary privileges">{{ extra.join(', ') }} {{ extra.length > 1 ? 'are' : 'is' }} not used by ICS (for example VM.Console gives console access to guests). Removing {{ extra.length > 1 ? 'them' : 'it' }} keeps the token least-privilege.</Banner>
      <template v-if="fixes.inventory.length"><h3>Fix inventory access (run on a Proxmox node as root)</h3><CodeBlock :lines="fixes.inventory" label="inventory fix commands" /></template>
      <template v-if="fixes.provision.length">
        <h3>{{ sdn.length ? 'Grant SDN access on the bridges (run on a Proxmox node as root)' : 'Grant provision access (pool-scoped, never cluster-wide)' }}</h3>
        <CodeBlock :lines="fixes.provision" label="provision fix commands" />
        <p class="small muted">Replace <span class="mono">&lt;STORAGE&gt;</span> and <span class="mono">&lt;BRIDGE&gt;</span> if you have not chosen them yet, then test again.</p>
      </template>
    </div>
  </div>
</template>
