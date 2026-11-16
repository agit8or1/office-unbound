<script setup lang="ts">
// Observe / modify / never, each line labelled with who enforces it (Proxmox RBAC or Office Unbound). Read-only display: nothing here is a control.
import { computed } from 'vue'
import { permissionSummary, type EnforcedBy, type Selection } from './model'

const props = defineProps<{ sel: Selection; compact?: boolean }>()
const s = computed(() => permissionSummary(props.sel))
const BY: Record<EnforcedBy, string> = { proxmox: 'Proxmox enforces', ou: 'Office Unbound enforces', both: 'Proxmox + Office Unbound' }
</script>

<template>
  <div class="ps" :class="{ compact }">
    <section class="ps-col read" aria-label="Can observe">
      <h3><span aria-hidden="true">👁</span> Can observe</h3>
      <ul><li v-for="i in s.observe" :key="i.text"><span>{{ i.text }}</span><span class="by" :data-by="i.by" :title="i.detail">{{ BY[i.by] }}</span>
        <small v-if="i.detail && !compact" class="muted">{{ i.detail }}</small></li></ul>
    </section>
    <section class="ps-col write" aria-label="Can modify">
      <h3><span aria-hidden="true">✎</span> Can modify</h3>
      <p v-if="!s.modify.length" class="muted small">Nothing. Monitoring never changes anything in Proxmox.</p>
      <ul><li v-for="i in s.modify" :key="i.text"><span>{{ i.text }}</span><span class="by" :data-by="i.by" :title="i.detail">{{ BY[i.by] }}</span>
        <small v-if="i.detail && !compact" class="muted">{{ i.detail }}</small></li></ul>
    </section>
    <section class="ps-col never" aria-label="Never allowed">
      <h3><span aria-hidden="true">🔒</span> Never allowed</h3>
      <ul><li v-for="i in s.never" :key="i.text"><span>🔒 {{ i.text }}</span><span class="by" :data-by="i.by" :title="i.detail">{{ BY[i.by] }}</span>
        <small v-if="i.detail && !compact" class="muted">{{ i.detail }}</small></li></ul>
    </section>
  </div>
</template>

<style scoped>
.ps { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; }
.ps-col { border: 1px solid var(--border, #d0d5dd); border-radius: 10px; padding: 12px 14px; min-width: 0; }
.ps-col h3 { margin: 0 0 8px; font-size: 15px; }
.ps-col.read { border-top: 3px solid #175cd3; } .ps-col.write { border-top: 3px solid #b54708; } .ps-col.never { border-top: 3px solid #b42318; }
.ps ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
.ps li { display: grid; gap: 2px; font-size: 14px; }
.by { justify-self: start; font-size: 11px; padding: 1px 8px; border-radius: 999px; border: 1px solid currentColor; }
.by[data-by="proxmox"] { color: #067647; } .by[data-by="ou"] { color: #b54708; } .by[data-by="both"] { color: #175cd3; }
.compact li small { display: none; }
</style>
