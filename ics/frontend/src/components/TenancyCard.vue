<script setup lang="ts">
// The installation's tenancy mode (owner 2026-11-20: "system should have two modes; single tenant mode and multi tenant mode").
// Chosen once; while deployments exist a different mode is refused (conversion is not available yet) — shown plainly, never faked.
import { ref, watch } from 'vue'
import { get } from '../api'
import { useLoad, hasRole } from '../store'
import Card from '../ui/Card.vue'
import Button from '../ui/Button.vue'
import RunPanel from '../views/providers/RunPanel.vue'
import { useRun } from '../views/providers/run'

interface Tenancy { mode: 'single' | 'multi' | null; deployments: number; can_change: boolean; note: string | null }
const t = useLoad(() => get<Tenancy>('settings/tenancy'), 0)
const pick = ref<'single' | 'multi'>('single')
watch(() => t.data.value?.mode, (m) => { if (m) pick.value = m }, { immediate: true })
const run = useRun()
async function save() { await run.start('settings.tenancy.set', { mode: pick.value }); void t.reload() }
const TEXT = {
  single: 'Single tenant: one organisation runs Office Unbound for itself. No customer screens; accounts are your own people.',
  multi: 'Multi tenant (MSP): several customers, each with its own separate stack, domains and administrators.',
}
</script>
<template>
  <Card title="Tenancy mode" :hint="t.data.value?.mode ? (t.data.value.mode === 'single' ? 'Single tenant' : 'Multi tenant (MSP)') : 'Not chosen yet'" data-testid="tenancy-card">
    <p v-if="t.data.value?.mode" class="small">{{ TEXT[t.data.value.mode] }}</p>
    <p v-if="t.data.value?.note" class="muted small">{{ t.data.value.note }}</p>
    <form v-if="hasRole('admin') && t.data.value?.can_change" class="tc-row" @submit.prevent="save">
      <label class="small"><input v-model="pick" type="radio" value="single"> {{ TEXT.single }}</label>
      <label class="small"><input v-model="pick" type="radio" value="multi"> {{ TEXT.multi }}</label>
      <Button size="sm" type="submit" :disabled="pick === t.data.value?.mode" :loading="run.busy.value">Save mode</Button>
      <span class="muted small">Can be changed only while no deployment exists.</span>
    </form>
    <RunPanel v-if="run.created.value" :run="run" what="Setting the tenancy mode" />
  </Card>
</template>
<style scoped>
.tc-row { display: grid; gap: 6px; } .tc-row label { display: flex; gap: 8px; align-items: baseline; }
</style>
