<script setup lang="ts">
import { reactive, ref } from 'vue'
import { ApiError, get, post, type Endpoint, type PlanCreated } from '../api'
import { fmtTime, hasRole, useLoad } from '../store'
import ErrorBox from '../components/ErrorBox.vue'

const eps = useLoad(() => get<Endpoint[]>('endpoints'))
const f = reactive({ name: '', base_url: '', token_id: '', token_secret: '', trust: 'fingerprint' as 'fingerprint' | 'ca', fingerprint: '', ca_pem: '' })
const err = ref<ApiError | null>(null), busy = ref(false), created = ref<PlanCreated | null>(null)
const open = ref(false)

async function register() {
  busy.value = true; err.value = null; created.value = null
  const params: Record<string, unknown> = {
    name: f.name.trim(), type: 'proxmox', base_url: f.base_url.trim(), token_id: f.token_id.trim(), token_secret: f.token_secret,
  }
  if (f.trust === 'fingerprint') params.fingerprint_sha256 = f.fingerprint.trim()
  else params.ca_pem = f.ca_pem
  try {
    created.value = await post<PlanCreated>('plans', { action: 'endpoint.register', params })
    f.token_secret = ''; f.name = f.base_url = f.token_id = f.fingerprint = f.ca_pem = ''
    open.value = false
    await eps.reload()
  } catch (e) { err.value = e as ApiError } finally { busy.value = false; f.token_secret = '' }
}
</script>
<template>
  <div class="page">
    <div class="head"><h1>Endpoints</h1>
      <button v-if="hasRole('operator')" class="primary" :aria-expanded="open" @click="open = !open">Register endpoint</button>
    </div>
    <div v-if="created" class="alert ok" role="status">
      Plan <span class="mono">{{ created.plan_id }}</span> created ({{ created.status.replace('_', ' ') }}, {{ created.approvals_required }} approvals
      required). The endpoint appears here after approval and a successful job.
      <span v-if="created.resolved_ips?.length"> Resolved: <span class="mono">{{ created.resolved_ips.join(', ') }}</span>.</span>
      Params hash <span class="mono">{{ created.params_hash }}</span>. <a href="#/plans">Open plans</a>
    </div>
    <form v-if="open" class="panel formgrid" @submit.prevent="register" aria-label="Register Proxmox endpoint">
      <h2>Register Proxmox endpoint</h2>
      <p class="muted small">This creates a high-risk plan that needs two approvers. The token secret is sent once, stored encrypted by the server, and never shown again.</p>
      <ErrorBox :error="err" />
      <label>Name<input v-model="f.name" required pattern="[a-z0-9][a-z0-9_\-]{0,62}" placeholder="pve-lab"></label>
      <label>Base URL<input v-model="f.base_url" required type="url" placeholder="https://pve.example:8006"></label>
      <label>Token ID<input v-model="f.token_id" required autocomplete="off" placeholder="user@realm!tokenname"></label>
      <label>Token secret<input v-model="f.token_secret" required type="password" autocomplete="off" minlength="8"></label>
      <fieldset>
        <legend>TLS trust (always verified)</legend>
        <label class="inline"><input type="radio" v-model="f.trust" value="fingerprint"> SHA-256 fingerprint</label>
        <label class="inline"><input type="radio" v-model="f.trust" value="ca"> CA certificate (PEM)</label>
      </fieldset>
      <label v-if="f.trust === 'fingerprint'">Certificate SHA-256 fingerprint<input v-model="f.fingerprint" required class="mono" spellcheck="false"></label>
      <label v-else>CA PEM<textarea v-model="f.ca_pem" required rows="5" class="mono" spellcheck="false"></textarea></label>
      <div><button class="primary" :disabled="busy">{{ busy ? 'Submitting…' : 'Create plan' }}</button></div>
    </form>
    <ErrorBox :error="eps.error.value" />
    <section class="panel fill">
      <div class="scroll">
        <table v-if="eps.data.value?.length">
          <thead><tr><th>Name</th><th>Type</th><th>Base URL</th><th>Token ID</th><th>TLS trust</th><th>Created</th><th></th></tr></thead>
          <tbody>
            <tr v-for="e in eps.data.value" :key="e.id">
              <td><strong>{{ e.name }}</strong></td><td>{{ e.type }}</td><td class="mono">{{ e.base_url }}</td><td class="mono">{{ e.token_id }}</td>
              <td>{{ e.has_ca_bundle ? 'CA bundle' : 'pinned fingerprint' }}<span v-if="e.fingerprint_sha256" class="mono small"> {{ e.fingerprint_sha256.slice(0, 17) }}…</span></td>
              <td>{{ fmtTime(e.created_at) }}</td><td><a :href="'#/inventory/' + e.id">Inventory</a></td>
            </tr>
          </tbody>
        </table>
        <p v-else-if="eps.data.value" class="empty">No endpoint is registered yet.<span v-if="hasRole('operator')"> Use "Register endpoint" to create a plan; it takes effect once two approvers approve it.</span></p>
        <p v-else-if="!eps.error.value" class="muted">Loading…</p>
      </div>
    </section>
  </div>
</template>
