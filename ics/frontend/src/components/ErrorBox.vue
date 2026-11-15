<script setup lang="ts">
import { computed } from 'vue'
import type { ApiError } from '../api'
import { friendly } from '../friendly'
import Icon from '../ui/Icon.vue'
const props = defineProps<{ error: ApiError | string | null }>()
const raw = computed(() => { const e = props.error; return !e ? '' : typeof e === 'string' ? e : e.message })
// Friendly wording by class of failure. Server validation / policy messages (4xx) are meant for people and shown as is,
// unless they carry raw technical text (TLS, sockets, DNS): that gets a plain sentence with the original under "Technical details".
const text = computed(() => {
  const e = props.error
  if (!e) return ''
  if (typeof e === 'string') return friendly(e) ?? e
  if (e.status === 0) return 'We cannot reach the server right now. Check your connection and try again.'
  if (e.status >= 500) return 'Something went wrong on the server. Try again in a moment; if it keeps happening, check Operations > Jobs and the audit log.'
  if (e.status === 403) return 'Your role or the approval rules do not allow this.'
  if (e.status === 404) return 'That item was not found. It may have been removed.'
  return friendly(e.message) ?? e.message
})
// only text that was rewritten from a technical failure keeps its original under the expander
const details = computed(() => (friendly(raw.value) && text.value !== raw.value ? raw.value : ''))
</script>
<template>
  <div v-if="error" class="alert bad" role="alert"><Icon name="alert" />
    <span><span>{{ text }}</span>
      <details v-if="details" class="techd"><summary>Technical details</summary><code class="mono wrap">{{ details }}</code></details></span></div>
</template>
