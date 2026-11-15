<script setup lang="ts">
import { ref, useId } from 'vue'
import Icon from './Icon.vue'
// Page title, one-line contextual help (the "i" button toggles the longer help text; Escape closes it), and an actions slot.
defineProps<{ title: string; sub?: string; help?: string }>()
const open = ref(false)
const tipId = 'help-' + useId()
</script>
<template>
  <div class="pagehead">
    <div>
      <h1>{{ title }}
        <button v-if="help" type="button" class="help" :title="help" :aria-label="'About ' + title" :aria-expanded="open" :aria-controls="tipId"
                @click="open = !open" @keydown.esc="open = false"><Icon name="info" class="infoico" /></button></h1>
      <p v-if="help" v-show="open" :id="tipId" class="helptext" role="note">{{ help }}</p>
      <p v-if="sub" class="sub">{{ sub }}</p>
    </div>
    <div class="row"><slot name="actions" /></div>
  </div>
</template>
