<script setup lang="ts">
defineProps<{ kind: 'info' | 'ok' | 'warn' | 'bad'; title?: string }>()
</script>

<template>
  <div class="wz-banner" :class="kind" :role="kind === 'bad' ? 'alert' : 'status'">
    <div><b v-if="title">{{ title }}</b><slot /></div>
  </div>
</template>
