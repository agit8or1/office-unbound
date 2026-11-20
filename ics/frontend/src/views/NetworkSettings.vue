<script setup lang="ts">
// Settings -> Network & domains. One public address per installation: ONE router forward per port (not one per deployment), the DNS
// records of each deployment that can be published, public certificates, and read-only checks that prove which machine answered.
import { computed, ref, watch } from 'vue'
import { get, post, type ApiError } from '../api'
import { useLoad } from '../store'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import Button from '../ui/Button.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import EmptyState from '../ui/EmptyState.vue'
import ErrorBox from '../components/ErrorBox.vue'
import RunPanel from './providers/RunPanel.vue'
import { useRun } from './providers/run'

interface Rec { name: string; type: string; value: string; required: boolean; purpose: string; status?: string; seen?: string[]; detail?: string }
interface Test { name: string | null; status: string; detail: string }
interface Fwd { port: number; port_end?: number | null; proto: string; vm: string; address: string | null; purpose: string; when: string;
  deployments: string[]; names: string[]; conflict: string | null; status?: string; tests?: Test[] }
interface Certs { public: { names: string[]; issued_at: string; certificate: string } | null; names: string[] }
interface Dep { deployment: string; status: string; domain: string; records: Rec[]; certificates?: Certs }
interface Local { deployment: string; status: string; domain: string | null; reason: string }
interface Overview { settings: { public_ipv4: string | null; entry_address: string | null }; detected_public_ipv4: string | null; forwards: Fwd[];
  deployments: Dep[]; local_only: Local[]; notes: string[] }
interface Checked { checked_at: string; records: { deployment: string; records: Rec[] }[]; forwards: Fwd[]; notes: string[] }

const ov = useLoad(() => get<Overview>('settings/network'), 60000)
const ip = ref(''), entry = ref('')
const thisServer = window.location.hostname
watch(() => ov.data.value, (v) => {
  if (!v) return
  if (!ip.value) ip.value = v.settings.public_ipv4 ?? ''
  if (!entry.value) entry.value = v.settings.entry_address ?? ''
}, { immediate: true })
const dirty = computed(() => (ip.value || null) !== (ov.data.value?.settings.public_ipv4 ?? null) || (entry.value || null) !== (ov.data.value?.settings.entry_address ?? null))
const run = useRun()
async function save() { await run.start('settings.network.update', { public_ipv4: ip.value.trim() || null, entry_address: entry.value.trim() || null }) }
watch(() => run.job.value?.status, (s) => { if (s === 'succeeded') { checked.value = null; void ov.reload() } })

const checking = ref(false), checkErr = ref<ApiError | null>(null), checked = ref<Checked | null>(null)
async function runChecks() {
  checking.value = true; checkErr.value = null
  try { checked.value = await post<Checked>('settings/network/check', {}) } catch (e) { checkErr.value = e as ApiError } finally { checking.value = false }
}
const recOf = (d: string, r: Rec) => checked.value?.records.find((x) => x.deployment === d)?.records.find((x) => x.name === r.name && x.type === r.type)
const fwdOf = (f: Fwd) => checked.value?.forwards.find((x) => x.port === f.port && x.proto === f.proto)
const TONE: Record<string, string> = { ok: 'ok', open: 'ok', wrong: 'failed', missing: 'failed', refused: 'failed', no_answer: 'warning', error: 'warning', differs: 'idle', unknown: 'idle', not_testable: 'idle' }
const LABEL: Record<string, string> = { ok: 'OK', open: 'Open', wrong: 'Wrong', missing: 'Missing', refused: 'Refused', no_answer: 'No answer', error: 'Error', differs: 'Not yet', unknown: 'Set the public address', not_testable: 'Not testable' }
const portText = (f: Fwd) => `${f.port}${f.port_end ? '-' + f.port_end : ''} ${f.proto.toUpperCase()}`
const nowFwds = computed(() => (ov.data.value?.forwards ?? []).filter((f) => f.when === 'now'))
const laterFwds = computed(() => (ov.data.value?.forwards ?? []).filter((f) => f.when !== 'now'))

const certRun = useRun()
const certFor = ref('')
async function issue(dep: string, directory: 'staging' | 'production') { certFor.value = dep; await certRun.start('gateway.certificates.issue', { deployment: dep, directory }) }
watch(() => certRun.job.value?.status, (s) => { if (s === 'succeeded') void ov.reload() })
</script>
<template>
  <div class="page">
    <PageHeader title="Network & domains" sub="How the internet reaches your deployments through one public address: router forwards, DNS records, certificates, and checks."
                help="Nothing here changes your DNS or your router. Checks are read-only." />
    <ErrorBox :error="ov.error.value" />

    <Card title="1. Public address" hint="The one public IPv4 address of this installation, and where your router sends web traffic.">
      <form class="ns-row" @submit.prevent="save">
        <label class="small">Public IPv4
          <input v-model.trim="ip" inputmode="decimal" :placeholder="ov.data.value?.detected_public_ipv4 ?? '203.0.113.10'" autocomplete="off" data-testid="ns-ip"></label>
        <Button v-if="!ip && ov.data.value?.detected_public_ipv4" size="sm" variant="ghost" type="button" @click="ip = ov.data.value!.detected_public_ipv4!">
          Use {{ ov.data.value?.detected_public_ipv4 }} (found in your DNS)</Button>
        <label class="small">Router forwards 80/443 to
          <input v-model.trim="entry" inputmode="decimal" placeholder="the gateway VM" autocomplete="off" data-testid="ns-entry"></label>
        <Button v-if="entry !== thisServer" size="sm" variant="ghost" type="button" @click="entry = thisServer">Use this server ({{ thisServer }})</Button>
        <Button size="sm" type="submit" :disabled="!dirty" :loading="run.busy.value">Save</Button>
      </form>
      <p class="muted small">"This server" routes each web name to the right deployment, so one forward serves every deployment. Saving is an audited change.</p>
      <RunPanel v-if="run.created.value" :run="run" what="Saving the network settings" />
    </Card>

    <Card title="2. Router port forwards" :hint="checked ? 'Checked ' + checked.checked_at : 'One forward per port, from your public address'" flush data-testid="ns-forwards">
      <template #actions><Button size="sm" :loading="checking" data-testid="ns-run" @click="runChecks">Run checks</Button></template>
      <ErrorBox :error="checkErr" />
      <EmptyState v-if="ov.data.value && !ov.data.value.forwards.length" compact title="Nothing to forward" text="No deployment on a public domain yet." />
      <table v-else class="dense"><thead><tr><th>Port</th><th>Forward to</th><th>For</th><th>Status</th></tr></thead>
        <tbody>
          <tr v-for="f in nowFwds" :key="f.port + f.proto">
            <td><b>{{ portText(f) }}</b></td>
            <td><code>{{ f.address ?? '?' }}</code><div class="muted small">{{ f.vm }}</div></td>
            <td class="small">{{ f.purpose }}<div class="muted">{{ f.names.join(', ') }}</div><div v-if="f.conflict" class="ns-bad">{{ f.conflict }}</div></td>
            <td><template v-if="fwdOf(f)"><StatusBadge :s="TONE[fwdOf(f)!.status!] ?? 'idle'" :text="LABEL[fwdOf(f)!.status!] ?? fwdOf(f)!.status" />
              <div v-for="t in fwdOf(f)!.tests" :key="String(t.name)" class="muted small">{{ t.name ? t.name + ': ' : '' }}{{ t.detail }}</div></template>
              <span v-else class="muted small">not checked</span></td>
          </tr>
          <tr v-if="laterFwds.length"><td colspan="4" class="ns-sub small">Later: only when external mail (or the service) is enabled</td></tr>
          <tr v-for="f in laterFwds" :key="'l' + f.port + f.proto" class="ns-later">
            <td>{{ portText(f) }}</td>
            <td><code>{{ f.address ?? '?' }}</code><div class="muted small">{{ f.vm }}</div></td>
            <td class="small">{{ f.purpose }}<div v-if="f.conflict" class="ns-bad">{{ f.conflict }}</div></td>
            <td><template v-if="fwdOf(f)"><StatusBadge :s="TONE[fwdOf(f)!.status!] ?? 'idle'" :text="LABEL[fwdOf(f)!.status!] ?? fwdOf(f)!.status" />
              <div v-for="t in fwdOf(f)!.tests" :key="String(t.name)" class="muted small">{{ t.detail }}</div></template>
              <span v-else class="muted small">not needed yet</span></td>
          </tr>
        </tbody></table>
      <ul class="muted small pad"><li v-for="(n, i) in (ov.data.value?.notes ?? [])" :key="i">{{ n }}</li></ul>
    </Card>

    <Card v-for="d in (ov.data.value?.deployments ?? [])" :key="d.deployment" :title="'3. DNS records: ' + d.domain" :hint="'Deployment ' + d.deployment + ' — create these at your DNS provider'" flush :data-testid="'ns-dep-' + d.deployment">
      <table class="dense"><thead><tr><th>Name</th><th>Type</th><th>Value</th><th>Status</th></tr></thead>
        <tbody><tr v-for="r in d.records" :key="r.name + r.type" :class="{ 'ns-later': !r.required }">
          <td><code>{{ r.name }}</code><div v-if="!r.required" class="muted small">only when external mail is enabled</div></td><td>{{ r.type }}</td><td><code>{{ r.value }}</code></td>
          <td><template v-if="recOf(d.deployment, r)"><StatusBadge :s="TONE[recOf(d.deployment, r)!.status!] ?? 'idle'" :text="LABEL[recOf(d.deployment, r)!.status!] ?? recOf(d.deployment, r)!.status" />
            <div class="muted small">{{ recOf(d.deployment, r)!.detail }}<template v-if="recOf(d.deployment, r)!.seen?.length"> (now: {{ recOf(d.deployment, r)!.seen!.join(', ') }})</template></div></template>
            <span v-else class="muted small">not checked</span></td>
        </tr></tbody></table>
      <div class="pad small ns-certs">
        <h4>Public certificates (Let's Encrypt, renewed by the gateway itself)</h4>
        <p v-if="d.certificates?.public">Serving a public certificate for {{ d.certificates.public.names.join(', ') }} since {{ d.certificates.public.issued_at }}.</p>
        <p v-else class="muted">Not yet: browsers warn until this is done. Needs the records above and the 80/443 forward. Covers: {{ (d.certificates?.names ?? []).join(', ') }}</p>
        <div class="ns-row">
          <Button size="sm" variant="secondary" :loading="certRun.busy.value && certFor === d.deployment" @click="issue(d.deployment, 'staging')">Test (staging)</Button>
          <Button size="sm" :loading="certRun.busy.value && certFor === d.deployment" @click="issue(d.deployment, 'production')">{{ d.certificates?.public ? 'Re-issue' : 'Get certificates' }}</Button>
          <span class="muted">Test first: staging proves the names validate without counting against Let's Encrypt limits.</span>
        </div>
        <RunPanel v-if="certRun.created.value && certFor === d.deployment" :run="certRun" :what="'Certificates for ' + d.deployment" />
      </div>
    </Card>

    <Card v-if="ov.data.value?.local_only.length" title="Not published" hint="These deployments have nothing to set up for the internet." flush>
      <table class="dense"><tbody><tr v-for="l in ov.data.value.local_only" :key="l.deployment"><td><b>{{ l.deployment }}</b></td><td class="small muted">{{ l.reason }}</td></tr></tbody></table>
    </Card>
  </div>
</template>
<style scoped>
.ns-row { display: flex; flex-wrap: wrap; gap: 8px 10px; align-items: end; }
.ns-row label { display: grid; gap: 2px; } .ns-row input { width: 13em; }
.pad { padding: 4px 16px 12px; } .ns-certs h4 { margin: 12px 0 4px; font-size: 14px; }
.ns-later td { opacity: .75; } .ns-sub { font-weight: 600; padding-top: 14px; }
.ns-bad { color: var(--bad, #b91c1c); margin-top: 4px; }
td code { overflow-wrap: anywhere; }
</style>
