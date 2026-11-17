<script setup lang="ts">
import { computed } from 'vue'
import { ICONS, type IconName } from './icons'
const props = defineProps<{ name: IconName }>()
const d = computed(() => ICONS[props.name] ?? '')
</script>
<template>
  <svg viewBox="0 0 24 24" width="1em" height="1em" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path :d="d" /></svg>
</template>
