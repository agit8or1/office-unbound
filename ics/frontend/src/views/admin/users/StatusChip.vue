<script setup lang="ts">
import { STATUS_KIND, STATUS_LABEL } from './users'
defineProps<{ status: string }>()
</script>
<template><span class="chip" :class="STATUS_KIND[status] ?? 'info'">{{ STATUS_LABEL[status] ?? status }}</span></template>
