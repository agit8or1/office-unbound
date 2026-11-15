<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ s: string }>()
const kind = computed(() => ({
  succeeded: 'ok', recovered: 'ok', verified: 'ok', acked: 'info', open: 'bad', critical: 'bad', warning: 'warn', unknown: 'info',
  pending_approval: 'warn', failed: 'bad', rejected: 'bad', high: 'warn', low: 'info',
} as Record<string, string>)[props.s] ?? 'info')
</script>
<template><span class="chip" :class="kind">{{ s.replace('_', ' ') }}</span></template>
