<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import Icon from './Icon.vue'
// Right-side drawer (modal=false -> drawer, modal=true -> centered dialog). Esc and backdrop click close it.
const props = defineProps<{ title: string; modal?: boolean }>()
const emit = defineEmits<{ close: [] }>()
const box = ref<HTMLElement | null>(null)
function onKey(e: KeyboardEvent) { if (e.key === 'Escape') emit('close') }
onMounted(() => { document.addEventListener('keydown', onKey); box.value?.focus() })
onUnmounted(() => document.removeEventListener('keydown', onKey))
</script>
<template>
  <div class="overlay" :class="props.modal ? 'center-ov' : 'right'" @mousedown.self="emit('close')">
    <div ref="box" :class="props.modal ? 'modal' : 'drawer'" role="dialog" aria-modal="true" :aria-label="title" tabindex="-1">
      <div class="head"><h2>{{ title }}</h2><button class="iconbtn" aria-label="Close" @click="emit('close')"><Icon name="x" /></button></div>
      <slot />
    </div>
  </div>
</template>
