<script setup lang="ts">
import { watchEffect } from 'vue'
import { useLoad } from '../store'
import { ago, crumbLabel } from '../format'
import { asList, normDeployment, tryGet } from '../infra'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import EmptyState from '../ui/EmptyState.vue'
import Button from '../ui/Button.vue'
import Skeleton from '../ui/Skeleton.vue'
import ErrorBox from '../components/ErrorBox.vue'
import BootstrapPanel from '../components/BootstrapPanel.vue'
import AppsPanel from '../components/AppsPanel.vue'
import PeoplePanel from '../components/PeoplePanel.vue'
import ResizePanel from '../wizards/deploy/ResizePanel.vue'
import { hasRole } from '../store'

const props = defineProps<{ id: string }>()
const enc = encodeURIComponent(props.id)
const dep = useLoad(async () => { const r = await tryGet<Record<string, unknown> | null>(`deployments/${enc}`, null); return r.data ? normDeployment(r.data) : null }, 10000)
const resources = useLoad(async () => asList((await tryGet<unknown>(`deployments/${enc}/resources`, [])).data), 10000)
const events = useLoad(async () => asList((await tryGet<unknown>(`deployments/${enc}/events`, [])).data), 10000)
watchEffect(() => { crumbLabel.value = dep.data.value?.name ?? '' })
const canResize = () => hasRole('operator')
const s = (v: unknown) => (v === undefined || v === null ? '-' : String(v))
</script>
<template>
  <div class="page">
    <ErrorBox :error="dep.error.value" />
    <Skeleton v-if="!dep.data.value && !dep.error.value && dep.loading.value" />
    <EmptyState v-else-if="!dep.data.value" icon="rocket" title="Deployment not found" text="It may have been removed, or deployments are not available yet."><Button to="/deployments">All deployments</Button></EmptyState>
    <template v-else>
      <PageHeader :title="dep.data.value.name" :sub="dep.data.value.profile ? 'Profile: ' + dep.data.value.profile : undefined"><template #actions><StatusBadge :s="dep.data.value.status" /></template></PageHeader>
      <AppsPanel v-if="hasRole('admin')" :slug="props.id" />
      <PeoplePanel v-if="hasRole('admin')" :slug="props.id" />
      <BootstrapPanel :slug="props.id" />
      <div class="grid cols-2">
        <Card title="Resources" flush>
          <EmptyState v-if="!resources.data.value?.length" compact title="No resources recorded" />
          <table v-else class="dense"><thead><tr><th>Name</th><th>Kind</th><th>State</th></tr></thead>
            <tbody><tr v-for="(r, i) in resources.data.value" :key="i"><td>{{ s(r.logical_name ?? r.name) }}</td><td>{{ s(r.kind) }}</td><td><StatusBadge :s="s(r.state ?? r.status)" /></td></tr></tbody></table>
        </Card>
        <Card title="Events" flush>
          <EmptyState v-if="!events.data.value?.length" compact title="No events yet" />
          <ul v-else class="feed feedpad"><li v-for="(e, i) in events.data.value.slice(0, 20)" :key="i"><span class="t">{{ s(e.message ?? e.event ?? e.type) }}</span><span class="w">{{ ago(e.at as string ?? e.created_at as string) }}</span></li></ul>
        </Card>
      </div>
      <ResizePanel v-if="canResize()" :slug="props.id" />
    </template>
  </div>
</template>
