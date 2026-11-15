<script setup lang="ts">
import Icon from './Icon.vue'
// Page title, one-line contextual help (the "i" shows the longer help text), and an actions slot.
defineProps<{ title: string; sub?: string; help?: string }>()
</script>
<template>
  <div class="pagehead">
    <div>
      <h1>{{ title }} <span v-if="help" class="help faint" :title="help" tabindex="0" :aria-label="'About ' + title + ': ' + help"><Icon name="info" class="infoico" /></span></h1>
      <p v-if="sub" class="sub">{{ sub }}</p>
    </div>
    <div class="row"><slot name="actions" /></div>
  </div>
</template>
