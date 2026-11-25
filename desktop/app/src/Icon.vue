<script setup lang="ts">
import { ICONS } from './icons'
defineProps<{ name: string }>()
</script>
<template>
  <svg class="icon" viewBox="0 0 20 20" width="20" height="20" aria-hidden="true" focusable="false">
    <path :d="ICONS[name]" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
  </svg>
</template>
