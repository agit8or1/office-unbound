<script setup lang="ts">
// Label + control slot + hint + field-level error. The slot receives ids to wire aria attributes.
import { useId } from 'vue'
defineProps<{ label: string; error?: string; hint?: string; optional?: boolean }>()
const id = useId()
</script>

<template>
  <div class="wz-field">
    <label :for="id">{{ label }}<span v-if="optional" class="muted small"> (optional)</span></label>
    <slot :id="id" :invalid="!!error" :described-by="id + '-d'" />
    <span v-if="hint && !error" :id="id + '-d'" class="hint">{{ hint }}</span>
    <span v-if="error" :id="id + '-d'" class="err" role="alert">{{ error }}</span>
  </div>
</template>
