<script setup lang="ts">
import type { ApiError } from '../api'
defineProps<{ error: ApiError | string | null }>()
function hint(e: ApiError | string) {
  if (typeof e === 'string') return ''
  if (e.status === 403) return 'Forbidden: your role or the approval rules do not allow this.'
  if (e.status === 429) return 'Rate limited: wait before trying again.'
  if (e.status === 0) return 'Network problem.'
  return ''
}
</script>
<template>
  <div v-if="error" class="alert bad" role="alert">
    <strong v-if="typeof error !== 'string'">{{ error.status || 'Error' }}</strong>
    <span class="msg">{{ typeof error === 'string' ? error : error.message }}</span>
    <span v-if="hint(error)" class="muted"> {{ hint(error) }}</span>
  </div>
</template>
