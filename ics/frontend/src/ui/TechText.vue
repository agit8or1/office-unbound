<script setup lang="ts">
import { computed } from 'vue'
import { friendly } from '../friendly'
// Shows a message in plain language when it is a known technical failure; the raw text stays available under "Technical details".
const props = defineProps<{ text: string | null | undefined; fallback?: string }>()
const plain = computed(() => friendly(props.text))
</script>
<template>
  <span v-if="!text">{{ fallback ?? '' }}</span>
  <span v-else-if="!plain">{{ text }}</span>
  <span v-else class="tech"><span>{{ plain }}</span>
    <details class="techd"><summary>Technical details</summary><code class="mono wrap">{{ text }}</code></details></span>
</template>
