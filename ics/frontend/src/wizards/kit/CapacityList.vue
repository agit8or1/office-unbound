<script setup lang="ts">
import type { CapacityLine } from '../api'
import CapacityBar from './CapacityBar.vue'
defineProps<{ lines: CapacityLine[] }>()
</script>

<template>
  <div>
    <CapacityBar v-for="l in lines" :key="l.scope + l.id + l.unit" :label="`${l.scope === 'node' ? 'Node' : 'Storage'} ${l.id}`" :total="l.total" :used="l.used" :added="l.added" :unit="l.unit" />
    <div class="wz-legend"><span><i class="lg-used wz-lg-used"></i>in use now</span><span><i class="wz-lg-added"></i>this plan</span></div>
  </div>
</template>

<style>
.wz-lg-used { background: var(--info, #24364f); opacity: .55; } .wz-lg-added { background: var(--accent, #a4451f); }
</style>
