<script setup lang="ts">
import Icon from './Icon.vue'
import type { IconName } from './icons'
import type { Tone } from './status'
defineProps<{ label: string; value: string | number; of?: string | number; sub?: string; icon?: IconName; tone?: Tone; to?: string; loading?: boolean }>()
</script>
<template>
  <component :is="to ? 'a' : 'div'" class="stat" :class="tone ?? 'idle'" :href="to ? '#' + to : undefined">
    <div class="lbl"><Icon v-if="icon" :name="icon" />{{ label }}</div>
    <span v-if="loading" class="skel big" />
    <div v-else class="val">{{ value }}<small v-if="of !== undefined"> / {{ of }}</small></div>
    <div class="sub">{{ sub ?? ' ' }}</div>
  </component>
</template>
