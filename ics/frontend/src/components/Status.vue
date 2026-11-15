<script setup lang="ts">
import StatusBadge from '../ui/StatusBadge.vue'
defineProps<{ s: string }>()
</script>
<template><StatusBadge :s="s" /></template>
