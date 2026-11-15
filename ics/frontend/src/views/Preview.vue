<script setup lang="ts">
import { ref } from 'vue'
import { ApiError, post } from '../api'
import ErrorBox from '../components/ErrorBox.vue'
import { fmtBytes } from '../store'

interface Step { order: number; operation: string; component: string; version: string; vm_name: string; pool: string; size: { cores: number; memory_mb: number; disk_gb: number }; after: string[] }
interface Out { valid: boolean; errors: { loc: (string | number)[]; msg: string }[]; plan?: { deployment_id: string; customer_id: string; endpoint: string; steps: Step[]; totals: { vms: number; cores: number; memory_mb: number; disk_gb: number } } }
const yaml = ref('')
const out = ref<Out | null>(null), err = ref<ApiError | null>(null), busy = ref(false)
async function run() {
  busy.value = true; err.value = null; out.value = null
  try { out.value = await post<Out>('plans/preview', { blueprint_yaml: yaml.value }) } catch (e) { err.value = e as ApiError } finally { busy.value = false }
}
</script>
<template>
  <div class="page">
    <h1>Plan preview</h1>
    <p class="muted">Dry run only: validates a blueprint and shows the ordered steps. Nothing is executed. The preview is recorded in the audit log.</p>
    <div class="split">
      <form class="panel" @submit.prevent="run">
        <label>Blueprint YAML<textarea v-model="yaml" rows="18" class="mono" spellcheck="false" required maxlength="200000"
          placeholder="deployment_id: ...&#10;customer_id: ...&#10;target: {endpoint: ..., pool: ...}&#10;components: [...]"></textarea></label>
        <button class="primary" :disabled="busy">{{ busy ? 'Checking…' : 'Preview' }}</button>
      </form>
      <section class="panel fill" aria-live="polite">
        <ErrorBox :error="err" />
        <template v-if="out">
          <div v-if="!out.valid">
            <div class="alert bad" role="alert">Blueprint is not valid ({{ out.errors.length }}).</div>
            <ul class="plain"><li v-for="(e, i) in out.errors" :key="i"><span class="mono">{{ e.loc.join('.') || '(document)' }}</span>: {{ e.msg }}</li></ul>
          </div>
          <div v-else-if="out.plan">
            <div class="alert ok">Valid. Deployment <strong>{{ out.plan.deployment_id }}</strong> for {{ out.plan.customer_id }} on endpoint {{ out.plan.endpoint }}.</div>
            <div class="scroll short">
              <table>
                <thead><tr><th>#</th><th>Operation</th><th>Component</th><th>VM name</th><th>Cores</th><th>Memory</th><th>Disk</th><th>After</th></tr></thead>
                <tbody><tr v-for="s in out.plan.steps" :key="s.order">
                  <td class="num">{{ s.order }}</td><td class="mono">{{ s.operation }}</td><td>{{ s.component }} {{ s.version }}</td><td class="mono">{{ s.vm_name }}</td>
                  <td class="num">{{ s.size.cores }}</td><td class="num">{{ fmtBytes(s.size.memory_mb * 1048576) }}</td><td class="num">{{ s.size.disk_gb }} GiB</td><td>{{ s.after.join(', ') || '-' }}</td>
                </tr></tbody>
              </table>
            </div>
            <p>Totals: {{ out.plan.totals.vms }} VMs, {{ out.plan.totals.cores }} cores, {{ fmtBytes(out.plan.totals.memory_mb * 1048576) }} memory, {{ out.plan.totals.disk_gb }} GiB disk.</p>
          </div>
        </template>
        <p v-else-if="!err" class="muted">Paste a blueprint and press Preview.</p>
      </section>
    </div>
  </div>
</template>
