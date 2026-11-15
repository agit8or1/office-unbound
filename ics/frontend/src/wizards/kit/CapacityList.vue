<script setup lang="ts">
import type { CapacityLine } from '../api'
defineProps<{ lines: CapacityLine[] }>()
</script>

<template>
  <ul class="wz-checks">
    <li v-for="l in lines" :key="l.scope + l.id"><span class="wz-chip info">{{ l.scope === 'node' ? 'Node' : 'Storage' }}</span><span><b class="mono">{{ l.id }}</b>: {{ l.text }}</span></li>
    <li v-if="!lines.length" class="muted">No capacity figures were produced for this plan.</li>
  </ul>
</template>
