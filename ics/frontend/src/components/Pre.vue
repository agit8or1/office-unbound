<script setup lang="ts">
import { pretty } from '../store'
defineProps<{ v: unknown }>()
</script>
<template><pre class="code" tabindex="0">{{ typeof v === 'string' ? v : pretty(v) }}</pre></template>
