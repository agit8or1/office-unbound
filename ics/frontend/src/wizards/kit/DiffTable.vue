<script setup lang="ts">
// Current vs proposed summary diff.
defineProps<{ rows: { resource: string; field: string; current: string | number | null; proposed: string | number | null }[] }>()
const show = (v: string | number | null) => (v === null || v === '' ? '(none)' : String(v))
</script>

<template>
  <div class="wz-table-wrap">
    <table>
      <thead><tr><th>Resource</th><th>Setting</th><th>Current</th><th>Proposed</th></tr></thead>
      <tbody>
        <tr v-for="(r, i) in rows" :key="i" :class="{ changed: r.current !== r.proposed }">
          <td class="mono">{{ r.resource }}</td><td>{{ r.field }}</td>
          <td>{{ show(r.current) }}</td><td><b>{{ show(r.proposed) }}</b></td>
        </tr>
        <tr v-if="!rows.length"><td colspan="4" class="muted">No differences.</td></tr>
      </tbody>
    </table>
  </div>
</template>
