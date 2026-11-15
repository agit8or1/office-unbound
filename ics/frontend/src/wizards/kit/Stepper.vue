<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ steps: { id: string; title: string }[]; index: number; reached: number }>()
const emit = defineEmits<{ (e: 'goto', i: number): void }>()
const percent = computed(() => ((props.index + 1) / props.steps.length) * 100)
function state(i: number) { return i === props.index ? 'current' : i < props.index ? 'done' : i <= props.reached ? 'reached' : 'todo' }
</script>

<template>
  <nav class="wz-stepper" aria-label="Wizard progress">
    <div class="wz-progress" role="progressbar" aria-valuemin="1" :aria-valuemax="steps.length" :aria-valuenow="index + 1">
      <span :style="{ width: percent + '%' }"></span>
    </div>
    <div class="wz-mobile-step">Step {{ index + 1 }} of {{ steps.length }}: {{ steps[index].title }}</div>
    <ol class="wz-steps">
      <li v-for="(s, i) in steps" :key="s.id">
        <button type="button" class="wz-step" :data-state="state(i)" :disabled="i > reached" :aria-current="i === index ? 'step' : undefined" @click="emit('goto', i)">
          <span class="wz-dot">{{ i < index ? '✓' : i + 1 }}</span>
          <span class="wz-label">{{ s.title }}</span>
        </button>
      </li>
    </ol>
  </nav>
</template>
