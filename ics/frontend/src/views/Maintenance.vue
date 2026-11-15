<script setup lang="ts">
import { get } from '../api'
import { fmtTime, useLoad } from '../store'
import type { MaintenanceWindow } from '../infra'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import DataTable from '../ui/DataTable.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import EmptyState from '../ui/EmptyState.vue'
import Skeleton from '../ui/Skeleton.vue'
import ErrorBox from '../components/ErrorBox.vue'

const list = useLoad(() => get<MaintenanceWindow[]>('maintenance'), 30000)
const cols = [{ key: 'name', label: 'Window' }, { key: 'scope', label: 'Applies to' }, { key: 'state', label: 'State' }, { key: 'starts_at', label: 'Starts' }, { key: 'ends_at', label: 'Ends' }, { key: 'reason', label: 'Reason' }]
</script>
<template>
  <div class="page">
    <PageHeader title="Maintenance" sub="Planned windows during which alerts for the affected checks are suppressed." help="Maintenance windows are created with a typed plan and reviewed through approvals." />
    <ErrorBox :error="list.error.value" />
    <Skeleton v-if="!list.data.value && !list.error.value" />
    <Card v-else-if="list.data.value" flush>
      <EmptyState v-if="!list.data.value.length" icon="calendar" title="No maintenance windows" text="Scheduled windows appear here. Alerts continue normally when none is active." />
      <DataTable v-else :cols="cols" :rows="list.data.value" :row-key="(w: MaintenanceWindow) => w.id">
        <template #cell-scope="{ row }">{{ row.check_name ?? 'All checks' }}</template>
        <template #cell-state="{ row }"><StatusBadge :s="row.active ? 'maintenance' : new Date(row.ends_at) < new Date() ? 'cancelled' : 'planned'" :text="row.active ? 'active' : new Date(row.ends_at) < new Date() ? 'ended' : 'scheduled'" /></template>
        <template #cell-starts_at="{ row }">{{ fmtTime(row.starts_at) }}</template>
        <template #cell-ends_at="{ row }">{{ fmtTime(row.ends_at) }}</template>
      </DataTable>
    </Card>
  </div>
</template>
