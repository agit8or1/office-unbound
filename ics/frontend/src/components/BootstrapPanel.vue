<script setup lang="ts">
// Guest bootstrap health for one deployment: per VM, what happened and what to do next.
import { computed } from 'vue'
import { get, type BootstrapOut } from '../api'
import { useLoad, fmtTime } from '../store'
import { bootstrapView, summary, worstTone } from '../bootstrap'
import Card from '../ui/Card.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import EmptyState from '../ui/EmptyState.vue'

const props = defineProps<{ slug: string }>()
const data = useLoad(() => get<BootstrapOut>(`deployments/${encodeURIComponent(props.slug)}/bootstrap`).catch(() => ({ deployment: props.slug, vms: [] }) as BootstrapOut), 10000)
const rows = computed(() => (data.data.value?.vms ?? []).map((v) => ({ v, view: bootstrapView(v) })))
const sum = computed(() => summary(rows.value.map((r) => r.view)))
const tone = computed(() => worstTone(rows.value.map((r) => r.view)))
const badge = { ok: 'ok', warn: 'warning', bad: 'failed', idle: 'idle' } as const
</script>
<template>
  <Card v-if="rows.length || data.data.value" title="Guest start-up" :hint="sum" data-testid="bootstrap-panel">
    <EmptyState v-if="!rows.length" compact title="No start-up records" text="VMs created from the golden image report here while they first start." />
    <ul v-else class="bs-list">
      <li v-for="r in rows" :key="r.v.vm + r.v.vmid" class="bs-item" :data-state="r.view.key">
        <div class="bs-head"><b>{{ r.v.vm }}</b><span class="muted small">VM {{ r.v.vmid }}</span><StatusBadge :s="badge[r.view.tone]" :text="r.view.label" /></div>
        <!-- an enrolled VM needs nothing: one line each, so a healthy deployment's card stays short -->
        <template v-if="r.view.key !== 'enrolled'">
          <p class="small">{{ r.view.detail }}</p>
          <p class="small"><b>Next step:</b> {{ r.view.next }}</p>
        </template>
        <p v-if="r.view.key === 'pending'" class="muted small">The one-time secret is valid until {{ fmtTime(r.v.expires_at) }}.</p>
      </li>
    </ul>
    <span class="sr-only" :data-tone="tone"></span>
  </Card>
</template>
<style scoped>
.bs-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 4px; }
.bs-item { padding: 8px 0; border-top: 1px solid var(--line); } .bs-item:first-child { border-top: 0; }
.bs-item p { margin: 4px 0 0; } .bs-head { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
</style>
