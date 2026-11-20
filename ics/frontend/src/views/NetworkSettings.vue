<script setup lang="ts">
// Settings -> Network & domains: the public address, every DNS record and port forward the deployments need, and real checks.
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
interface Port { port: number; port_end?: number | null; proto: string; vm: string; address: string | null; purpose: string; when: string; status?: string; detail?: string }
interface Dep { deployment: string; status: string; ready: boolean; domain?: string; records?: Rec[]; ports?: Port[] }
interface Overview { settings: { public_ipv4: string | null }; deployments: Dep[]; notes: string[] }
interface Checked { public_ipv4: string | null; checked_at: string; results: { deployment: string; records: Rec[]; ports: Port[] }[]; notes: string[] }

const ov = useLoad(() => get<Overview>('settings/network'), 60000)
const ip = ref('')
watch(() => ov.data.value?.settings.public_ipv4, (v) => { if (v && !ip.value) ip.value = v }, { immediate: true })
const run = useRun()
async function saveIp() { await run.start('settings.network.update', { public_ipv4: ip.value.trim() || null }); ov.reload() }
watch(() => run.job.value?.status, (s) => { if (s === 'succeeded') void ov.reload() })

const checking = ref(false), checkErr = ref<ApiError | null>(null), checked = ref<Checked | null>(null)
async function runChecks() {
  checking.value = true; checkErr.value = null
  try { checked.value = await post<Checked>('settings/network/check', {}) } catch (e) { checkErr.value = e as ApiError } finally { checking.value = false }
}
const byDep = computed(() => Object.fromEntries((checked.value?.results ?? []).map((r) => [r.deployment, r])))
const recOf = (d: string, r: Rec) => byDep.value[d]?.records.find((x) => x.name === r.name && x.type === r.type)
const portOf = (d: string, p: Port) => byDep.value[d]?.ports.find((x) => x.port === p.port && x.proto === p.proto)
const TONE: Record<string, string> = { ok: 'ok', open: 'ok', wrong: 'failed', missing: 'failed', refused: 'failed', no_answer: 'warning', error: 'warning', differs: 'idle', unknown: 'idle', not_testable: 'idle' }
const LABEL: Record<string, string> = { ok: 'OK', open: 'Open', wrong: 'Wrong', missing: 'Missing', refused: 'Refused', no_answer: 'No answer', error: 'Error', differs: 'Not yet', unknown: 'Unknown', not_testable: 'Not testable' }
const portText = (p: Port) => `${p.port}${p.port_end ? '-' + p.port_end : ''} ${p.proto.toUpperCase()}`
</script>
<template>
  <div class="page">
    <PageHeader title="Network & domains" sub="Your public address, the DNS records and the router port forwards your deployments need, and checks that they are right."
                help="Nothing here changes your DNS or router. Checks are read-only." />
    <ErrorBox :error="ov.error.value" />
    <Card title="Public address" hint="The one public IPv4 address of this installation. Your router forwards the ports below to the machines shown.">
      <form class="ns-ip" @submit.prevent="saveIp">
        <label class="small">Public IPv4<input v-model.trim="ip" inputmode="decimal" placeholder="203.0.113.10" autocomplete="off" data-testid="ns-ip"></label>
        <Button size="sm" type="submit" :loading="run.busy.value">Save</Button>
        <span class="muted small">Saved through an audited change.</span>
      </form>
      <RunPanel v-if="run.created.value" :run="run" what="Saving the public address" />
    </Card>
    <Card title="Checks" :hint="checked ? 'Last run ' + checked.checked_at : 'Not run yet'">
      <Button size="sm" :loading="checking" data-testid="ns-run" @click="runChecks">Run checks</Button>
      <ErrorBox :error="checkErr" />
      <ul class="muted small"><li v-for="(n, i) in (ov.data.value?.notes ?? [])" :key="i">{{ n }}</li></ul>
    </Card>
    <EmptyState v-if="ov.data.value && !ov.data.value.deployments.length" icon="rocket" title="No deployments yet" text="Records and port forwards appear here once a deployment exists." />
    <Card v-for="d in (ov.data.value?.deployments ?? [])" :key="d.deployment" :title="d.deployment" :hint="d.domain" flush :data-testid="'ns-dep-' + d.deployment">
      <p v-if="!d.ready" class="muted small pad">Listed once the deployment has been created.</p>
      <template v-else>
        <h4 class="pad">DNS records (at your DNS provider)</h4>
        <table class="dense"><thead><tr><th>Name</th><th>Type</th><th>Value</th><th>Needed</th><th>Status</th></tr></thead>
          <tbody><tr v-for="r in d.records" :key="r.name + r.type">
            <td><code>{{ r.name }}</code></td><td>{{ r.type }}</td><td><code>{{ r.value }}</code></td>
            <td class="small">{{ r.required ? 'now' : 'external mail (later)' }}</td>
            <td><template v-if="recOf(d.deployment, r)"><StatusBadge :s="TONE[recOf(d.deployment, r)!.status!] ?? 'idle'" :text="LABEL[recOf(d.deployment, r)!.status!] ?? recOf(d.deployment, r)!.status" />
              <span class="muted small"> {{ recOf(d.deployment, r)!.detail }}<template v-if="recOf(d.deployment, r)!.seen?.length"> (now: {{ recOf(d.deployment, r)!.seen!.join(', ') }})</template></span></template>
              <span v-else class="muted small">not checked</span></td>
          </tr></tbody></table>
        <h4 class="pad">Port forwards (on your router, from the public address)</h4>
        <table class="dense"><thead><tr><th>Public port</th><th>Forward to</th><th>For</th><th>When</th><th>Status</th></tr></thead>
          <tbody><tr v-for="p in d.ports" :key="p.port + p.proto">
            <td>{{ portText(p) }}</td><td><code>{{ p.address ?? '?' }}:{{ p.port }}</code> <span class="muted small">{{ p.vm }}</span></td>
            <td class="small">{{ p.purpose }}</td><td class="small">{{ p.when }}</td>
            <td><template v-if="portOf(d.deployment, p)"><StatusBadge :s="TONE[portOf(d.deployment, p)!.status!] ?? 'idle'" :text="LABEL[portOf(d.deployment, p)!.status!] ?? portOf(d.deployment, p)!.status" />
              <span class="muted small"> {{ portOf(d.deployment, p)!.detail }}</span></template>
              <span v-else class="muted small">not checked</span></td>
          </tr></tbody></table>
      </template>
    </Card>
  </div>
</template>
<style scoped>
.ns-ip { display: flex; flex-wrap: wrap; gap: 8px; align-items: end; }
.ns-ip label { display: grid; gap: 2px; } .ns-ip input { width: 12em; }
.pad { padding: 0 16px; } h4.pad { margin: 14px 0 6px; font-size: 14px; }
td code { overflow-wrap: anywhere; }
</style>
