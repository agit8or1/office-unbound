<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ s: string }>()
const kind = computed(() => ({
  succeeded: 'ok', approved: 'ok', ok: 'ok', ready: 'ok', running: 'info', queued: 'info',
  pending_approval: 'warn', failed: 'bad', rejected: 'bad', high: 'warn', low: 'info',
} as Record<string, string>)[props.s] ?? 'info')
</script>
<template><span class="chip" :class="kind">{{ s.replace('_', ' ') }}</span></template>
