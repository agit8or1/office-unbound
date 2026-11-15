<script setup lang="ts">
import { ref } from 'vue'
const props = defineProps<{ lines: string[]; label?: string }>()
const copied = ref(false)
async function copy() {
  try { await navigator.clipboard.writeText(props.lines.join('\n')); copied.value = true; setTimeout(() => (copied.value = false), 1500) } catch { /* clipboard unavailable */ }
}
</script>

<template>
  <div class="wz-code">
    <pre :aria-label="label">{{ lines.join('\n') }}</pre>
    <button type="button" class="wz-btn" @click="copy">{{ copied ? 'Copied' : 'Copy commands' }}</button>
  </div>
</template>
