<script setup lang="ts">
import Icon from './Icon.vue'
import type { IconName } from './icons'
defineProps<{ title: string; text?: string; icon?: IconName; compact?: boolean }>()
</script>
<template>
  <div class="emptystate" :class="{ compact }">
    <div v-if="!compact" class="ico"><Icon :name="icon ?? 'inbox'" /></div>
    <h2>{{ title }}</h2>
    <p v-if="text">{{ text }}</p>
    <div class="row"><slot /></div>
  </div>
</template>
