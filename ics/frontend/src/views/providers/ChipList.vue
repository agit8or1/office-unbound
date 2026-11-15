<script setup lang="ts">
// Free-text list editor for names/IDs when discovery is not available (or to add a new pool).
import { ref } from 'vue'
const props = defineProps<{ modelValue: string[]; placeholder?: string; label: string; mono?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [string[]] }>()
const draft = ref('')
function add() {
  const parts = draft.value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
  if (parts.length) emit('update:modelValue', [...new Set([...props.modelValue, ...parts])])
  draft.value = ''
}
</script>
<template>
  <div class="pv-chips">
    <span v-for="c in modelValue" :key="c" class="pv-chip"><span :class="{ mono }">{{ c }}</span>
      <button type="button" class="pv-x" :aria-label="'Remove ' + c" @click="emit('update:modelValue', modelValue.filter((x) => x !== c))">&times;</button></span>
    <input v-model="draft" type="text" :placeholder="placeholder ?? 'Add and press Enter'" :aria-label="label" @keydown.enter.prevent="add" @blur="add" />
  </div>
</template>
