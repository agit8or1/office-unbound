<script setup lang="ts">
defineProps<{ modelValue: boolean; label: string }>()
defineEmits<{ 'update:modelValue': [boolean] }>()
</script>
<template>
  <label class="toggle">
    <input type="checkbox" role="switch" :checked="modelValue" @change="$emit('update:modelValue', ($event.target as HTMLInputElement).checked)">
    <span class="track" aria-hidden="true"></span>{{ label }}
  </label>
</template>
