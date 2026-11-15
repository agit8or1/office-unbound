<script setup lang="ts">
import { computed } from 'vue'
import type { ApiError } from '../api'
import Icon from '../ui/Icon.vue'
const props = defineProps<{ error: ApiError | string | null }>()
// Friendly wording by class of failure. Server validation / policy messages (4xx) are meant for people and shown as is.
const text = computed(() => {
  const e = props.error
  if (!e) return ''
  if (typeof e === 'string') return e
  if (e.status === 0) return 'We cannot reach the server right now. Check your connection and try again.'
  if (e.status >= 500) return 'Something went wrong on the server. Try again in a moment; if it keeps happening, check Operations > Jobs and the audit log.'
  if (e.status === 403) return 'Your role or the approval rules do not allow this.'
  if (e.status === 404) return 'That item was not found. It may have been removed.'
  if (e.status === 429) return e.message
  return e.message
})
</script>
<template>
  <div v-if="error" class="alert bad" role="alert"><Icon name="alert" /><span>{{ text }}</span></div>
</template>
