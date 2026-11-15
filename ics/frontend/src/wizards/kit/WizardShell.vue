<script setup lang="ts">
// Frame: title, stepper, step body (slot), Back/Next footer. The last step supplies its own action through the `actions` slot.
import './kit.css'
import Stepper from './Stepper.vue'
defineProps<{
  title: string; subtitle?: string
  steps: { id: string; title: string }[]; index: number; reached: number
  nextLabel?: string; busy?: boolean; hideNext?: boolean; nextDisabled?: boolean; hideNav?: boolean
}>()
const emit = defineEmits<{ (e: 'next'): void; (e: 'back'): void; (e: 'goto', i: number): void }>()
</script>

<template>
  <section class="wz" :aria-label="title">
    <h1>{{ title }}</h1>
    <p v-if="subtitle" class="sub">{{ subtitle }}</p>
    <Stepper :steps="steps" :index="index" :reached="reached" @goto="emit('goto', $event)" />
    <div class="wz-body"><slot /></div>
    <div v-if="!hideNav" class="wz-footer">
      <button type="button" class="wz-btn" :disabled="index === 0 || busy" @click="emit('back')">Back</button>
      <span class="spacer"></span>
      <slot name="actions" />
      <button v-if="!hideNext" type="button" class="wz-btn primary" :disabled="busy || nextDisabled" @click="emit('next')">{{ nextLabel ?? 'Next' }}</button>
    </div>
  </section>
</template>
