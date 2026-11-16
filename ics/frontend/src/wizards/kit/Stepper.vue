<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ steps: { id: string; title: string }[]; index: number; reached: number }>()
const emit = defineEmits<{ (e: 'goto', i: number): void }>()
const percent = computed(() => ((props.index + 1) / props.steps.length) * 100)
function state(i: number) { return i === props.index ? 'current' : i < props.index ? 'done' : i <= props.reached ? 'reached' : 'todo' }
</script>

<template>
  <nav class="wz-stepper" aria-label="Wizard progress">
    <div class="wz-progress" role="progressbar" :aria-label="`Step ${index + 1} of ${steps.length}`" aria-valuemin="1" :aria-valuemax="steps.length" :aria-valuenow="index + 1">
      <span :style="{ width: percent + '%' }"></span>
    </div>
    <div class="wz-mobile-step">Step {{ index + 1 }} of {{ steps.length }}: {{ steps[index].title }}</div>
    <ol class="wz-steps">
      <li v-for="(s, i) in steps" :key="s.id">
        <!-- the current step is not a control: going to the step you are on does nothing -->
        <span v-if="i === index" class="wz-step" :data-state="state(i)" aria-current="step">
          <span class="wz-dot">{{ i + 1 }}</span>
          <span class="wz-label">{{ s.title }}</span>
        </span>
        <button v-else type="button" class="wz-step" :data-state="state(i)" :disabled="i > reached" @click="emit('goto', i)">
          <span class="wz-dot">{{ i < index ? '✓' : i + 1 }}</span>
          <span class="wz-label">{{ s.title }}</span>
        </button>
      </li>
    </ol>
  </nav>
</template>
