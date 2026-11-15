<script setup lang="ts">
import Icon from './Icon.vue'
import type { IconName } from './icons'
// A button, or a link styled as one when `to` is set (hash route).
defineProps<{ variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; size?: 'sm' | 'md'; icon?: IconName; to?: string; loading?: boolean; disabled?: boolean; type?: 'button' | 'submit' }>()
</script>
<template>
  <a v-if="to" class="btn" :class="[variant ?? 'secondary', size === 'sm' ? 'sm' : '']" :href="'#' + to"><Icon v-if="icon" :name="icon" /><slot /></a>
  <button v-else class="btn" :class="[variant ?? 'secondary', size === 'sm' ? 'sm' : '']" :type="type ?? 'button'" :disabled="disabled || loading" :aria-busy="loading || undefined">
    <Icon v-if="icon" :name="icon" /><slot />
  </button>
</template>
