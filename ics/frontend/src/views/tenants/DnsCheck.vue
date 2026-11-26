<script setup lang="ts">
// ADR-0021 §2a: the DNS checker for one deployment's domain. Read-only; names come from the deployment's plan on the server.
import { computed, ref } from 'vue'
import Button from '../../ui/Button.vue'
import StatusBadge from '../../ui/StatusBadge.vue'
import ErrorBox from '../../components/ErrorBox.vue'
import { ApiError } from '../../api'
import { DNS_GROUPS, dnsTone, tenantsApi, type DnsResult } from './tenants'

// tenant: the tenant page's checker; without it (deployment page) the deployment's own endpoint answers
const props = defineProps<{ tenant?: string; deployment: string; domain: string | null }>()
const res = ref<DnsResult | null>(null)
const err = ref<ApiError | null>(null)
const busy = ref(false)
const copied = ref('')
async function run(refresh: boolean) {
  busy.value = true
  try { res.value = props.tenant ? await tenantsApi.dns(props.tenant, props.deployment, refresh) : await tenantsApi.deploymentDns(props.deployment, refresh); err.value = null }
  catch (e) { err.value = e instanceof ApiError ? e : new ApiError(0, String(e)) }
  finally { busy.value = false }
}
const groups = computed(() => DNS_GROUPS.map((g) => ({ g, rows: (res.value?.rows ?? []).filter((r) => r.group === g) })).filter((x) => x.rows.length))
const needsWork = computed(() => (res.value?.rows ?? []).filter((r) => r.required && (r.status === 'missing' || r.status === 'differs')).length)
async function copy(t: string) {
  try { await navigator.clipboard.writeText(t); copied.value = t; setTimeout(() => { if (copied.value === t) copied.value = '' }, 2000) } catch { /* no clipboard: the value stays selectable */ }
}
const when = (s: string | null) => (s ? new Date(s).toLocaleString() : '')
</script>
<template>
  <div class="dnscheck">
    <div class="row between">
      <p class="muted small">Checks every record <strong class="mono">{{ domain ?? res?.domain ?? "the domain" }}</strong> needs for this deployment, from this server.</p>
      <div class="row">
        <Button size="sm" :loading="busy" data-testid="dns-check" @click="run(!!res)">{{ res ? 'Check again' : 'Check DNS' }}</Button>
      </div>
    </div>
    <ErrorBox :error="err" />
    <p v-if="res && !res.available" class="muted" role="status">{{ res.reason }}</p>
    <template v-if="res && res.available">
      <p class="small" role="status">
        <span v-if="needsWork">{{ needsWork }} required {{ needsWork === 1 ? 'record needs' : 'records need' }} attention.</span>
        <span v-else>Every required record is in place.</span>
        <span class="muted"> Checked {{ when(res.checked_at) }}{{ res.cached ? ' (kept from the last check)' : '' }}.</span>
      </p>
      <section v-for="x in groups" :key="x.g" class="dnsgroup">
        <h3>{{ x.g }}</h3>
        <div class="tablewrap" tabindex="0" role="region" :aria-label="x.g + ' records'">
          <table class="dense dnstable">
            <thead><tr><th scope="col">Record</th><th scope="col">Type</th><th scope="col">Should be</th><th scope="col">Found</th><th scope="col">Status</th></tr></thead>
            <tbody>
              <tr v-for="r in x.rows" :key="r.type + r.name">
                <th scope="row"><span class="mono">{{ r.name }}</span><div class="muted small">{{ r.why }}</div></th>
                <td class="mono">{{ r.type }}</td>
                <td><span class="mono">{{ r.expected }}</span>
                  <button v-if="r.status !== 'ok' && r.status !== 'not_available' && r.expected !== '-'" type="button" class="linkbtn small"
                          :aria-label="'Copy the value for ' + r.name" @click="copy(r.expected)">{{ copied === r.expected ? 'Copied' : 'Copy' }}</button></td>
                <td><span v-if="r.found.length" class="mono">{{ r.found.join(', ') }}</span><span v-else class="muted">Nothing</span>
                  <div v-if="r.how" class="muted small">{{ r.how }}</div></td>
                <td><StatusBadge :s="dnsTone(r).s" :text="dnsTone(r).text" /></td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
      <p v-if="res.note" class="muted small">{{ res.note }}</p>
    </template>
  </div>
</template>
<style scoped>
.between { justify-content: space-between; flex-wrap: wrap; gap: 8px; }
.dnsgroup h3 { font-size: 14px; font-weight: 600; margin: 16px 0 6px; }
.dnstable th[scope="row"] { font-weight: 400; }
.dnstable .mono { overflow-wrap: anywhere; }
.linkbtn { background: none; border: 0; color: var(--link, var(--accent)); cursor: pointer; padding: 0 0 0 6px; text-decoration: underline; }
</style>
