<script setup lang="ts">
// Diagnostics (administrators): the last lines of an allowlisted service journal or log file of one of this deployment's VMs, read by the
// node agent (guest.journal) and redacted on the VM. Read-only; every read is audited without its content. Needs node agent 0.8.1 or later.
import { computed, ref, watch } from 'vue'
import { get, post, type ApiError } from '../api'
import { useLoad } from '../store'
import Card from '../ui/Card.vue'
import Button from '../ui/Button.vue'
import ErrorBox from './ErrorBox.vue'
import { body, choices, type DiagForm, type DiagResult, type DiagSources } from '../diagnostics'

const props = defineProps<{ slug: string }>()
const enc = encodeURIComponent(props.slug)
const err = ref<ApiError | null>(null)
const src = useLoad(async () => { try { return await get<DiagSources>(`deployments/${enc}/diagnostics`) } catch (e) { err.value = e as ApiError; return null } }, 0)
const form = ref<DiagForm>({ vm: '', kind: 'unit', name: '', lines: 100, since: null, grep: '' })
const result = ref<DiagResult | null>(null)
const busy = ref(false)
const vm = computed(() => src.data.value?.vms.find((v) => v.name === form.value.vm))
const opts = computed(() => (src.data.value && form.value.vm ? choices(src.data.value, form.value.vm, form.value.kind) : { suggested: [], other: [] }))
watch(() => src.data.value, (s) => { if (s && !form.value.vm) form.value.vm = (s.vms.find((v) => v.available) ?? s.vms[0])?.name ?? '' }, { immediate: true })
watch(() => [form.value.vm, form.value.kind], () => { form.value.name = opts.value.suggested[0] ?? opts.value.other[0] ?? '' }, { immediate: true })
async function read() {
  if (!form.value.vm || !form.value.name) return
  busy.value = true; err.value = null
  try { result.value = await post<DiagResult>(`deployments/${enc}/diagnostics/logs`, body(form.value, src.data.value?.max_lines)) }
  catch (e) { err.value = e as ApiError; result.value = null }
  finally { busy.value = false }
}
</script>
<template>
  <Card title="Diagnostics" hint="Read-only service logs, redacted on the VM" flush data-testid="diagnostics-panel">
    <ErrorBox :error="err" />
    <form v-if="src.data.value?.vms.length" class="dg-form pad" @submit.prevent="read">
      <label class="small">VM<select v-model="form.vm">
        <option v-for="v in src.data.value.vms" :key="v.name" :value="v.name">{{ v.name }}{{ v.components.length ? ' (' + v.components.join(', ') + ')' : '' }}{{ v.available ? '' : ' - not available' }}</option></select></label>
      <label class="small">Source<select v-model="form.kind"><option value="unit">Service journal</option><option value="file">Log file</option></select></label>
      <label class="small">{{ form.kind === 'unit' ? 'Service' : 'File' }}<select v-model="form.name">
        <optgroup v-if="opts.suggested.length" label="For this VM"><option v-for="n in opts.suggested" :key="n" :value="n">{{ n }}</option></optgroup>
        <optgroup label="Other"><option v-for="n in opts.other" :key="n" :value="n">{{ n }}</option></optgroup></select></label>
      <label class="small">Lines<input v-model.number="form.lines" type="number" min="1" :max="src.data.value.max_lines"></label>
      <label v-if="form.kind === 'unit'" class="small">Last<select v-model="form.since"><option :value="null">any time</option><option :value="15">15 min</option>
        <option :value="60">1 hour</option><option :value="360">6 hours</option><option :value="1440">24 hours</option></select></label>
      <label class="small">Only lines about<select v-model="form.grep"><option value="">everything</option>
        <option v-for="g in src.data.value.greps" :key="g" :value="g">{{ g }}</option></select></label>
      <Button size="sm" type="submit" :disabled="!vm?.available || !form.name" :loading="busy">Read</Button>
    </form>
    <p v-if="vm && !vm.available" class="muted small pad" data-testid="diag-unavailable">
      {{ vm.enrolled ? "This VM's agent predates diagnostics (it needs node agent 0.8.1 or later, from a newer golden image)." : 'This VM has no enrolled agent.' }}</p>
    <p v-else-if="src.data.value && !src.data.value.vms.length" class="muted small pad">No VMs recorded for this deployment.</p>
    <div v-if="result" class="pad" data-testid="diag-result">
      <p class="muted small">{{ result.target }}: {{ result.lines_returned }} line(s){{ result.truncated ? ', cut to the size limit' : '' }}{{ result.redacted ? '; tokens, passwords and cookies replaced by ***' : '' }}
        <span v-if="result.exists === false"> - the file does not exist on this VM</span><span v-if="result.error"> - {{ result.error }}</span></p>
      <pre class="code dg-log" tabindex="0">{{ result.log.join('\n') || '(no lines)' }}</pre>
    </div>
  </Card>
</template>
<style scoped>
.pad { padding: 4px 16px 12px; }
.dg-form { display: flex; flex-wrap: wrap; gap: 8px 10px; align-items: end; }
.dg-form label { display: grid; gap: 2px; } .dg-form input { width: 6em; } .dg-form select { max-width: 22em; }
.dg-log { max-height: 28em; overflow: auto; white-space: pre-wrap; word-break: break-all; font-size: 12px; }
</style>
