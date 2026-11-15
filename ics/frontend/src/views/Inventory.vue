<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ApiError, get, post, type Endpoint, type PlanCreated } from '../api'
import { fmtBytes, fmtTime, go, hasRole, route, useLoad } from '../store'
import ErrorBox from '../components/ErrorBox.vue'
import Status from '../components/Status.vue'

interface Row { [k: string]: unknown }
interface NodeInv { node: string; status: string; info?: Row; qemu?: Row[]; lxc?: Row[]; storage?: Row[]; network?: Row[]; error?: string }
interface Snap { snapshot_id: number; collected_at: string; data: { version?: Row; nodes: NodeInv[] } }

const eps = useLoad(() => get<Endpoint[]>('endpoints'))
const epId = computed(() => route.value.arg || eps.data.value?.[0]?.id || '')
const snap = ref<Snap | null>(null), serr = ref<ApiError | null>(null), loading = ref(false)
async function loadSnap() {
  snap.value = null; serr.value = null
  if (!epId.value) return
  loading.value = true
  try { snap.value = await get<Snap>(`endpoints/${epId.value}/inventory`) } catch (e) { serr.value = e as ApiError } finally { loading.value = false }
}
watch(epId, loadSnap, { immediate: true })

const busy = ref(false), rerr = ref<ApiError | null>(null), queued = ref<PlanCreated | null>(null)
async function refresh() {
  busy.value = true; rerr.value = null; queued.value = null
  try { queued.value = await post<PlanCreated>('plans', { action: 'inventory.refresh', params: { endpoint_id: epId.value } }) }
  catch (e) { rerr.value = e as ApiError } finally { busy.value = false }
}
const str = (v: unknown) => (v === undefined || v === null || v === '' ? '-' : String(v))
const cols = {
  qemu: [['vmid', 'VMID'], ['name', 'Name'], ['status', 'Status'], ['cpus', 'CPUs'], ['maxmem', 'Memory', 'b'], ['maxdisk', 'Disk', 'b']],
  lxc: [['vmid', 'VMID'], ['name', 'Name'], ['status', 'Status'], ['cpus', 'CPUs'], ['maxmem', 'Memory', 'b'], ['maxdisk', 'Disk', 'b']],
  storage: [['storage', 'Storage'], ['type', 'Type'], ['content', 'Content'], ['used', 'Used', 'b'], ['total', 'Total', 'b'], ['active', 'Active']],
  network: [['iface', 'Interface'], ['type', 'Type'], ['cidr', 'Address'], ['bridge_ports', 'Ports'], ['active', 'Active']],
} as const
const titles = { qemu: 'VMs', lxc: 'Containers (LXC)', storage: 'Storage', network: 'Network' } as const
const kinds = ['qemu', 'lxc', 'storage', 'network'] as const
function cell(r: Row, c: readonly string[]) {
  const v = r[c[0]]
  return c[2] === 'b' ? fmtBytes(v) : str(v)
}
</script>
<template>
  <div class="page">
    <div class="head"><h1>Inventory</h1>
      <div class="row" v-if="eps.data.value?.length">
        <label class="inline">Endpoint
          <select :value="epId" @change="go('inventory', ($event.target as HTMLSelectElement).value)">
            <option v-for="e in eps.data.value" :key="e.id" :value="e.id">{{ e.name }}</option>
          </select>
        </label>
        <button v-if="hasRole('operator')" class="primary" :disabled="busy" @click="refresh">Request refresh</button>
      </div>
    </div>
    <ErrorBox :error="eps.error.value" />
    <ErrorBox :error="rerr" />
    <div v-if="queued" class="alert ok" role="status">Refresh queued as job <a :href="'#/jobs/' + queued.job_id" class="mono">{{ queued.job_id }}</a>. Reload this page when it has succeeded.
      <button class="ghost" @click="loadSnap">Reload snapshot</button></div>
    <p v-if="eps.data.value && !eps.data.value.length" class="panel empty">
      No endpoint is registered yet, so there is no inventory. Register a Proxmox endpoint on the <a href="#/endpoints">Endpoints</a> page; after it is approved,
      request an inventory refresh here.
    </p>
    <template v-else-if="epId">
      <ErrorBox :error="serr" />
      <p v-if="loading" class="muted">Loading…</p>
      <div v-if="snap" class="inv">
        <p class="muted">Collected {{ fmtTime(snap.collected_at) }} (snapshot {{ snap.snapshot_id }}), Proxmox {{ str(snap.data.version?.version) }}</p>
        <section v-for="n in snap.data.nodes" :key="n.node" class="panel">
          <h2>Node {{ n.node }} <Status :s="n.status === 'online' ? 'ok' : 'failed'" /> <span class="muted small">{{ n.status }}</span></h2>
          <div v-if="n.error" class="alert bad">{{ n.error }}</div>
          <template v-for="k in kinds" :key="k">
            <details v-if="n[k]" :open="k !== 'network'">
              <summary>{{ titles[k] }} ({{ n[k]!.length }})</summary>
              <div class="scroll short" tabindex="0" role="region" aria-label="Scrollable table">
                <table v-if="n[k]!.length">
                  <thead><tr><th v-for="c in cols[k]" :key="c[0]">{{ c[1] }}</th></tr></thead>
                  <tbody><tr v-for="(r, i) in n[k]" :key="i"><td v-for="c in cols[k]" :key="c[0]" :class="{ num: c[2] === 'b' }">{{ cell(r, c) }}</td></tr></tbody>
                </table>
                <p v-else class="muted">None.</p>
              </div>
            </details>
          </template>
        </section>
      </div>
    </template>
  </div>
</template>
