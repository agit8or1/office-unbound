<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ pct: number | null | undefined; label?: string }>()
const v = computed(() => Math.max(0, Math.min(100, Number(props.pct ?? 0))))
const cls = computed(() => (v.value >= 90 ? 'bad' : v.value >= 75 ? 'warn' : ''))
</script>
<template>
  <div v-if="pct != null" class="bar" :class="cls" role="progressbar" :aria-valuenow="Math.round(v)" aria-valuemin="0" aria-valuemax="100" :aria-label="label"><i :data-w="Math.round(v)" :ref="(el) => { if (el) (el as HTMLElement).style.width = v + '%' }"></i></div>
  <span v-else class="faint">-</span>
</template>
