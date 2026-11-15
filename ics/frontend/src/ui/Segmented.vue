<script setup lang="ts">
// Segmented control (range picker, filters).
defineProps<{ modelValue: string; options: { value: string; label: string }[]; label?: string }>()
defineEmits<{ 'update:modelValue': [string] }>()
</script>
<template>
  <div class="seg" role="group" :aria-label="label ?? 'Options'">
    <button v-for="o in options" :key="o.value" type="button" :aria-pressed="modelValue === o.value" @click="$emit('update:modelValue', o.value)">{{ o.label }}</button>
  </div>
</template>
