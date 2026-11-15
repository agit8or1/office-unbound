<script setup lang="ts">
defineProps<{ title?: string; hint?: string; flush?: boolean }>()
</script>
<template>
  <section class="card" :class="{ flush }">
    <header v-if="title || $slots.actions">
      <div><h2>{{ title }}</h2><div v-if="hint" class="hint">{{ hint }}</div></div>
      <div v-if="$slots.actions" class="row"><slot name="actions" /></div>
    </header>
    <slot />
  </section>
</template>
