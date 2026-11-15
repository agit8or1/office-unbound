<script setup lang="ts">
import { dismiss, toasts } from './toast'
</script>
<template>
  <div class="toasts" role="status" aria-live="polite">
    <div v-for="t in toasts" :key="t.id" class="toast" :class="t.kind" @click="dismiss(t.id)">{{ t.text }}</div>
  </div>
</template>
