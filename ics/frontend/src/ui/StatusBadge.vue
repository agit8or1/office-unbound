<script setup lang="ts">
import { computed } from 'vue'
import { label, tone } from './status'
const props = defineProps<{ s: string | null | undefined; text?: string }>()
const t = computed(() => tone(props.s))
</script>
<template><span class="badge" :class="t">{{ text ?? label(s) }}</span></template>
