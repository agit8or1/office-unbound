<script setup lang="ts">
defineProps<{ modelValue: string; tabs: { id: string; label: string }[] }>()
defineEmits<{ 'update:modelValue': [string] }>()
</script>
<template>
  <div class="tabs" role="tablist">
    <button v-for="t in tabs" :key="t.id" type="button" role="tab" :aria-selected="modelValue === t.id" @click="$emit('update:modelValue', t.id)">{{ t.label }}</button>
  </div>
</template>
