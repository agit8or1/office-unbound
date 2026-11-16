<script setup lang="ts">
// Persistent notice when this console runs on a standby (or replaced) controller. Source: public /readyz, polled.
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { fetchReady, type Ready } from '../api'
import { RUNBOOK_URL, bannerView } from '../controller'
import Icon from '../ui/Icon.vue'

const ready = ref<Ready | null>(null)
const view = computed(() => bannerView(ready.value))
let timer: number | undefined
async function load() { ready.value = await fetchReady() }
onMounted(() => { void load(); timer = window.setInterval(() => { if (!document.hidden) void load() }, 15000) })
onUnmounted(() => clearInterval(timer))
</script>
<template>
  <div v-if="view.show" class="alert ctl-banner" :class="view.kind" :role="view.kind === 'bad' ? 'alert' : 'status'" data-testid="controller-banner">
    <Icon name="shield" />
    <div class="grow">
      <b>{{ view.title }}</b>
      <p>{{ view.text }}</p>
      <ul v-if="view.facts.length" class="small"><li v-for="f in view.facts" :key="f">{{ f }}</li></ul>
      <p class="small"><a :href="RUNBOOK_URL" target="_blank" rel="noopener noreferrer">Open the recovery runbook</a></p>
    </div>
  </div>
</template>
<style scoped>
.ctl-banner { border-radius: 0; margin: 0; border-bottom: 1px solid var(--line); }
.ctl-banner p { margin: 4px 0 0; } .ctl-banner ul { margin: 4px 0 0; padding-left: 18px; }
</style>
