<script setup lang="ts">
// Small confirmation dialog that submits one typed plan action and reports what happens next.
import { onMounted, ref } from 'vue'
import { ApiError, type PlanCreated } from '../../../api'
import ErrorBox from '../../../components/ErrorBox.vue'
import { outcomeText, submitPlan } from './users'

const props = defineProps<{
  title: string; action: string; params: Record<string, unknown>; confirmLabel: string; danger?: boolean
  note?: string; reasonLabel?: string
}>()
const emit = defineEmits<{ close: []; done: [p: PlanCreated] }>()
const reason = ref(''), busy = ref(false), err = ref<ApiError | null>(null), result = ref<PlanCreated | null>(null)
const box = ref<HTMLElement | null>(null)
onMounted(() => box.value?.focus())
async function go() {
  busy.value = true; err.value = null
  try {
    result.value = await submitPlan(props.action, { ...props.params, ...(reason.value.trim() ? { reason: reason.value.trim() } : {}) })
    emit('done', result.value)
  } catch (e) { err.value = e as ApiError } finally { busy.value = false }
}
</script>
<template>
  <div class="ux-modal" @keydown.esc="emit('close')">
    <div ref="box" class="ux-dialog" role="dialog" aria-modal="true" :aria-label="title" tabindex="-1">
      <h2>{{ title }}</h2>
      <template v-if="!result">
        <p v-if="note" class="muted">{{ note }}</p>
        <label>{{ reasonLabel ?? 'Reason (optional, recorded in the audit log)' }}
          <textarea v-model="reason" rows="2" maxlength="500"></textarea></label>
        <ErrorBox :error="err" />
        <div class="row end">
          <button class="ghost" @click="emit('close')">Cancel</button>
          <button :class="danger ? 'danger' : 'primary'" :disabled="busy" @click="go">{{ busy ? 'Submitting…' : confirmLabel }}</button>
        </div>
      </template>
      <template v-else>
        <div class="alert" :class="result.status === 'approved' ? 'ok' : 'warn'" role="status">{{ outcomeText(result) }}</div>
        <p v-if="result.status !== 'approved'" class="small"><a :href="'#/plans/' + result.plan_id">Open the plan in Approvals</a> to follow it.</p>
        <div class="row end"><button class="primary" @click="emit('close')">Close</button></div>
      </template>
    </div>
  </div>
</template>
