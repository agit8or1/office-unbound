<script setup lang="ts">
import { computed } from 'vue'
import { fmtNum, pct } from './format'
const props = defineProps<{ label: string; total: number; used: number; added?: number; unit: string }>()
const usedP = computed(() => pct(props.used, props.total))
const addedP = computed(() => Math.min(100 - usedP.value, pct(props.added ?? 0, props.total)))
const afterP = computed(() => pct(props.used + (props.added ?? 0), props.total))
const over = computed(() => props.used + (props.added ?? 0) > props.total)
const level = computed(() => (over.value || afterP.value > 90 ? 'bad' : afterP.value > 75 ? 'warn' : 'ok'))
const remaining = computed(() => props.total - props.used - (props.added ?? 0))
</script>

<template>
  <div class="wz-cap">
    <div class="cap-head">
      <span>{{ label }}</span>
      <span class="muted">
        {{ fmtNum(used + (added ?? 0)) }} / {{ fmtNum(total) }} {{ unit }}
        ({{ Math.round(afterP) }}%) &middot; <b :class="over ? 'bad' : ''">{{ over ? 'over by ' + fmtNum(-remaining) : fmtNum(remaining) + ' free' }}</b>
      </span>
    </div>
    <div class="wz-bar" :data-level="level" role="img" :aria-label="`${label}: ${Math.round(afterP)} percent used after change`">
      <span class="used" :style="{ width: usedP + '%' }"></span><span class="added" :style="{ width: addedP + '%' }"></span>
    </div>
  </div>
</template>
