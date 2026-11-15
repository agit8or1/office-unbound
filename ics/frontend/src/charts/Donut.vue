<script setup lang="ts">
import { computed } from 'vue'
import { donutArcs } from './geometry'
const props = defineProps<{ items: { label: string; value: number }[]; center?: string; caption?: string }>()
const R = 54, C = 2 * Math.PI * R
const total = computed(() => props.items.reduce((a, b) => a + b.value, 0))
const arcs = computed(() => donutArcs(props.items.map((i) => i.value), C))
</script>
<template>
  <div class="donutwrap">
    <svg class="donut" width="120" height="120" viewBox="0 0 140 140" role="img" :aria-label="items.map((i) => i.label + ' ' + i.value).join(', ')">
      <circle class="seg0" cx="70" cy="70" :r="R" />
      <template v-if="total"><circle v-for="(a, i) in arcs" :key="i" :class="'seg' + ((i % 4) + 1)" cx="70" cy="70" :r="R" :stroke-dasharray="`${a.dash} ${C - a.dash}`" :stroke-dashoffset="a.offset" transform="rotate(-90 70 70)" /></template>
      <text x="70" y="72" text-anchor="middle" font-size="26" font-weight="700">{{ center ?? total }}</text>
      <text x="70" y="90" text-anchor="middle" font-size="11" opacity=".7">{{ caption ?? 'total' }}</text>
    </svg>
    <ul class="legend"><li v-for="(i, k) in items" :key="i.label"><i :class="'lg' + ((k % 4) + 1)"></i>{{ i.label }}<b>{{ i.value }}</b></li></ul>
  </div>
</template>
