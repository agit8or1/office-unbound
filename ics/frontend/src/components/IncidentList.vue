<script setup lang="ts">
import { computed } from 'vue'
import type { Incident } from '../api'
import { fmtDuration } from '../format'
import { nextAction, sortIncidents } from '../incidents'
import StatusBadge from '../ui/StatusBadge.vue'
import Icon from '../ui/Icon.vue'
const props = defineProps<{ incidents: Incident[]; now: number; limit?: number }>()
const rows = computed(() => sortIncidents(props.incidents).slice(0, props.limit ?? 50))
</script>
<template>
  <div class="incidents">
    <div v-for="i in rows" :key="i.id" class="incident" :class="i.severity">
      <StatusBadge :s="i.severity" />
      <div><router-link class="t" :to="'/incidents/' + i.id">{{ i.title || i.check_name }}</router-link></div>
      <div class="small"><b>{{ fmtDuration(now - +new Date(i.opened_at)) }}</b></div>
      <div class="meta">Resource: <router-link :to="'/checks/' + i.check_id">{{ i.check_name }}</router-link> · {{ i.status }}<template v-if="i.escalated_at"> · escalated</template></div>
      <div class="next"><Icon name="bulb" /><span><b>Next:</b> {{ nextAction(i) }}</span></div>
    </div>
  </div>
</template>
