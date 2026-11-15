<script setup lang="ts">
import { computed } from 'vue'
import { useLoad } from '../store'
import { loadInfra } from '../infra'
import UtilizationPanel from '../components/UtilizationPanel.vue'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import EmptyState from '../ui/EmptyState.vue'
import Button from '../ui/Button.vue'
import ErrorBox from '../components/ErrorBox.vue'

const infra = useLoad(loadInfra, 60000)
const scopes = computed(() => {
  const i = infra.data.value
  if (!i) return []
  return i.nodes.filter((n) => n.raw.managed !== false).map((n) => ({ scope: 'node', id: n.id, name: 'Node: ' + n.name }))
})
</script>
<template>
  <div class="page">
    <PageHeader title="Utilization" sub="CPU, memory, storage and network over time, per node." help="Charts use metric samples collected from your clusters. Pick a scope and a time range." />
    <ErrorBox :error="infra.error.value" />
    <UtilizationPanel v-if="infra.data.value" :scopes="scopes" :connected="infra.data.value.connected" title="Resource utilization" />
    <Card v-else><EmptyState compact title="Loading…" /></Card>
    <Card v-if="infra.data.value && !infra.data.value.connected"><EmptyState icon="cluster" title="Connect your first Proxmox cluster" text="Utilization history starts once a cluster is connected."><Button variant="primary" to="/endpoints">Add a cluster</Button></EmptyState></Card>
  </div>
</template>
