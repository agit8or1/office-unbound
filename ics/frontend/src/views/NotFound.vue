<script setup lang="ts">
import EmptyState from '../ui/EmptyState.vue'
import Button from '../ui/Button.vue'
</script>
<template>
  <EmptyState title="Page not found" text="This page does not exist or has moved." icon="alert"><Button variant="primary" to="/overview">Back to overview</Button></EmptyState>
</template>
