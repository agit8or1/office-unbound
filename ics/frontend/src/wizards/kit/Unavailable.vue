<script setup lang="ts">
// Honest "not available yet" state. Dev builds say which endpoint is missing; production builds never expose internals
// (the developer text sits behind import.meta.env.DEV so it is compiled out of production bundles).
import { computed } from 'vue'
import Banner from './Banner.vue'
const props = defineProps<{ what: string; endpoint: string; status?: number }>()
const devText = computed(() =>
  import.meta.env.DEV ? `Developer notice: ${props.endpoint} returned ${props.status ?? 404}. The API behind "${props.what}" has not been merged into this ICS build yet. No data is simulated here.` : null)
</script>

<template>
  <Banner v-if="devText" kind="warn" title="Backend endpoint not available (dev build)">{{ devText }}</Banner>
  <Banner v-else kind="info" title="Not available yet">{{ what }} is not available on this ICS yet. It will appear here once it is enabled.</Banner>
</template>
