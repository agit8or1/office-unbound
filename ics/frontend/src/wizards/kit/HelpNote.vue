<script setup lang="ts">
defineProps<{ title: string; open?: boolean }>()
</script>

<template>
  <details class="wz-help" :open="open">
    <summary>{{ title }}</summary>
    <slot />
  </details>
</template>
