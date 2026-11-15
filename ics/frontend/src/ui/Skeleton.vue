<script setup lang="ts">
withDefaults(defineProps<{ rows?: number }>(), { rows: 4 })
</script>
<template>
  <div class="page" role="status" aria-label="Loading">
    <span v-for="n in rows" :key="n" class="skel" :class="n % 2 ? '' : 'w70'" />
  </div>
</template>
