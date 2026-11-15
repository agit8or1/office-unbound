<script setup lang="ts">
import { computed } from 'vue'
import { label, tone } from './status'
const props = defineProps<{ s: string | null | undefined }>()
const t = computed(() => tone(props.s))
</script>
<template><span class="dot" :class="t" role="img" :aria-label="label(s)" :title="label(s)"></span></template>
