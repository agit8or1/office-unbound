<script setup lang="ts">
import { computed, ref } from 'vue'
import { useLoad } from '../store'
import { ago } from '../format'
import { loadDeployments, splitDeployments, type Deployment } from '../infra'
import { hasPath } from '../router'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import DataTable from '../ui/DataTable.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import EmptyState from '../ui/EmptyState.vue'
import Button from '../ui/Button.vue'
import Skeleton from '../ui/Skeleton.vue'
import ErrorBox from '../components/ErrorBox.vue'

const dep = useLoad(loadDeployments, 15000)
const cols = [{ key: 'name', label: 'Environment' }, { key: 'profile', label: 'Profile' }, { key: 'status', label: 'Status' }, { key: 'updated', label: 'Updated' }]
const canNew = () => hasPath('/deployments/new')
// owner 2026-11-21: "it isnt showing any deployments": live ones first (newest change first); destroyed ones are history, behind a toggle
const showGone = ref(false)
const isGone = (d: Deployment) => d.status === 'destroyed'
const split = computed(() => splitDeployments(dep.data.value?.data ?? []))
const live = computed(() => split.value.live)
const gone = computed(() => split.value.gone)
const rows = computed(() => (showGone.value ? [...live.value, ...gone.value] : live.value))
const cols2 = [...cols, { key: 'people', label: '' }]
</script>
<template>
  <div class="page">
    <PageHeader title="Deployments" sub="Customer environments managed by Office Unbound, with their desired and actual state." help="A deployment is a set of VMs, containers and services created from a profile and managed as one unit.">
      <template #actions><Button v-if="canNew()" variant="primary" icon="plus" to="/deployments/new">New deployment</Button></template>
    </PageHeader>
    <ErrorBox :error="dep.error.value" />
    <Skeleton v-if="!dep.data.value && !dep.error.value" />
    <Card v-else-if="dep.data.value" flush>
      <EmptyState v-if="!dep.data.value.data.length" icon="rocket" title="No deployments yet" :text="canNew() ? 'Create your first environment from a profile. You will review a plan and its capacity impact before anything runs.' : 'Environments you deploy appear here with their status, resources and change history.'">
        <Button v-if="canNew()" variant="primary" icon="plus" to="/deployments/new">New deployment</Button>
      </EmptyState>
      <template v-else>
        <EmptyState v-if="!live.length && !showGone" compact title="No live deployments" text="Every deployment listed here has been destroyed." />
        <DataTable v-if="rows.length" :cols="cols2" :rows="rows" :row-key="(d: Deployment) => d.id" :href="(d: Deployment) => '/deployments/' + d.id">
          <template #cell-status="{ row }"><StatusBadge :s="row.status" /></template>
          <template #cell-updated="{ row }">{{ ago(row.updated ?? row.created) }}</template>
          <template #cell-people="{ row }"><router-link v-if="!isGone(row)" :to="{ path: '/deployments/' + row.id, query: { section: 'people' } }" class="small" @click.stop>People</router-link></template>
        </DataTable>
        <p v-if="gone.length" class="dp-gone"><Button size="sm" variant="ghost" data-testid="dep-show-gone" @click="showGone = !showGone">{{ showGone ? 'Hide' : 'Show' }} {{ gone.length }} destroyed</Button></p>
      </template>
    </Card>
  </div>
</template>
<style scoped>
.dp-gone { padding: 6px 12px 10px; margin: 0; }
</style>
