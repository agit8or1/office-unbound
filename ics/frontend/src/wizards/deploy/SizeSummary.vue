<script setup lang="ts">
// Live estimate beside the wizard (sticky on wide screens, below the step on narrow ones). Every figure comes from the size response.
import { fmtGb, fmtMem } from '../kit'
import { ARCH_INFO, type Summary } from './sizing'
defineProps<{ summary: Summary; recommendation: string | null; busy: boolean; error: string; hint: string }>()
</script>

<template>
  <aside class="dw-summary wz-card" aria-label="Estimated size" aria-live="polite">
    <h2>Estimated size</h2>
    <p v-if="busy" class="small muted" role="status">Updating…</p>
    <p v-if="error" class="small dw-bad" role="alert">{{ error }}</p>
    <p v-if="!summary.ready && !busy && !error" class="small muted">{{ hint }}</p>
    <template v-if="summary.ready">
      <dl class="dw-stats">
        <div><dt>VMs</dt><dd>{{ summary.vms }}</dd></div>
        <div><dt>vCPU</dt><dd>{{ summary.vcpu }}</dd></div>
        <div><dt>Memory</dt><dd>{{ fmtMem(summary.memoryMb) }}</dd></div>
        <div><dt>Storage</dt><dd>{{ fmtGb(summary.storageGb) }}</dd></div>
      </dl>
      <p class="small muted">Layout: {{ summary.architecture ? ARCH_INFO[summary.architecture].title : '-' }}</p>
      <template v-if="summary.headroom">
        <h3>Left over afterwards</h3>
        <ul class="dw-head small">
          <li :class="{ 'dw-bad': summary.headroom.vcpu < 0 }">{{ summary.headroom.vcpu }} vCPU</li>
          <li :class="{ 'dw-bad': summary.headroom.memoryMb < 0 }">{{ fmtMem(summary.headroom.memoryMb) }} memory<span v-if="summary.headroom.memoryPct !== null"> ({{ Math.round(summary.headroom.memoryPct) }}%)</span></li>
          <li :class="{ 'dw-bad': summary.headroom.storageGb < 0 }">{{ fmtGb(summary.headroom.storageGb) }} storage</li>
        </ul>
      </template>
      <p v-if="summary.fits === false" class="small dw-bad">Does not fit the approved capacity.</p>
      <p v-else-if="summary.fits" class="small dw-ok">Fits the approved capacity.</p>
    </template>
    <p v-if="recommendation" class="small dw-rec">{{ recommendation }}</p>
    <p class="small muted">Estimates from the sizing models. Nothing is created until you approve a plan.</p>
  </aside>
</template>
