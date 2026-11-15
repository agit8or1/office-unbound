<script setup lang="ts">
import { computed, ref } from 'vue'
import { ApiError, get, type AuditEvent, type ChainResult } from '../api'
import { fmtTime, pretty, useLoad } from '../store'
import ErrorBox from '../components/ErrorBox.vue'

// The API only supports `limit` (max 500), newest first; pages are cut client-side from that window.
const PAGE = 25
const window_ = ref(200)
const log = useLoad(() => get<AuditEvent[]>(`audit?limit=${window_.value}`))
const page = ref(0)
const rows = computed(() => (log.data.value ?? []).slice(page.value * PAGE, page.value * PAGE + PAGE))
const pages = computed(() => Math.max(1, Math.ceil((log.data.value?.length ?? 0) / PAGE)))
const open = ref<number | null>(null)

const chain = ref<ChainResult | null>(null), cerr = ref<ApiError | null>(null), verifying = ref(false)
async function verify() {
  verifying.value = true; cerr.value = null
  try { chain.value = await get<ChainResult>('audit/verify') } catch (e) { cerr.value = e as ApiError } finally { verifying.value = false }
}
async function setWindow(n: number) { window_.value = n; page.value = 0; await log.reload() }
</script>
<template>
  <div class="page">
    <div class="head"><h1>Audit</h1>
      <div class="row">
        <button class="ghost" @click="log.reload()">Refresh</button>
        <button class="primary" :disabled="verifying" @click="verify">{{ verifying ? 'Verifying…' : 'Verify chain' }}</button>
      </div>
    </div>
    <ErrorBox :error="cerr" />
    <div v-if="chain" class="alert" :class="chain.ok ? 'ok' : 'bad'" role="status">
      <strong>{{ chain.ok ? 'Chain intact' : 'Chain problems found' }}</strong>: {{ chain.checked }} entries checked, MACs {{ chain.mac_checked ? 'checked' : 'not checked' }},
      {{ chain.legacy_unauthenticated }} legacy unauthenticated. Head <span class="mono">{{ chain.head.slice(0, 16) }}…</span>
      <ul v-if="chain.problems.length" class="plain"><li v-for="p in chain.problems" :key="p.seq + p.kind">#{{ p.seq }} {{ p.kind }}: {{ p.detail }}</li></ul>
    </div>
    <ErrorBox :error="log.error.value" />
    <section class="panel fill">
      <div class="scroll">
        <table v-if="rows.length">
          <thead><tr><th>Seq</th><th>Time</th><th>Action</th><th>Actor</th><th>IP</th><th>Resource</th><th><span class="sr">Details</span></th></tr></thead>
          <tbody>
            <template v-for="a in rows" :key="a.seq">
              <tr>
                <td class="num">{{ a.seq }}</td><td>{{ fmtTime(a.at) }}</td><td class="mono">{{ a.action }}</td><td>{{ a.actor_name ?? '-' }}</td>
                <td class="mono">{{ a.ip ?? '-' }}</td><td class="mono">{{ a.resource ? a.resource + ' ' + (a.resource_id ?? '').slice(0, 8) : '-' }}</td>
                <td><button class="ghost" :aria-expanded="open === a.seq" @click="open = open === a.seq ? null : a.seq">Details</button></td>
              </tr>
              <tr v-if="open === a.seq"><td colspan="7"><pre class="code" tabindex="0">{{ pretty({ id: a.id, hash: a.hash, details: a.details }) }}</pre></td></tr>
            </template>
          </tbody>
        </table>
        <p v-else-if="log.data.value" class="empty">No audit entries.</p>
      </div>
      <div class="row pager">
        <button class="ghost" :disabled="page === 0" @click="page--">Newer</button>
        <span>Page {{ page + 1 }} of {{ pages }}</span>
        <button class="ghost" :disabled="page + 1 >= pages" @click="page++">Older</button>
        <label class="inline">Window
          <select :value="window_" @change="setWindow(Number(($event.target as HTMLSelectElement).value))">
            <option :value="100">latest 100</option><option :value="200">latest 200</option><option :value="500">latest 500</option>
          </select></label>
        <span class="muted small">Chain verification covers the whole log, not just this window.</span>
      </div>
    </section>
  </div>
</template>
