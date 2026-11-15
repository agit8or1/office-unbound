<script setup lang="ts">
// Labelled form field with help text and error; the control goes in the default slot.
defineProps<{ label: string; help?: string; error?: string; for?: string }>()
</script>
<template>
  <div class="field">
    <label class="lbl" :for="$props.for">{{ label }}</label>
    <slot />
    <div v-if="error" class="err" role="alert">{{ error }}</div>
    <div v-else-if="help" class="help">{{ help }}</div>
  </div>
</template>
