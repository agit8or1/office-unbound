<script setup lang="ts">
// Title + tab bar shared by the cluster dashboard, permissions and credentials pages.
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import PageHeader from '../../ui/PageHeader.vue'
import { HEALTH_TEXT, healthTone, providerTitle, type ProviderEndpoint } from './model'
const props = defineProps<{ id: string; ep: ProviderEndpoint | null; sub?: string }>()
const current = useRoute()
const tabs = computed(() => [
  { label: 'Overview', to: `/infrastructure/providers/${props.id}` },
  { label: 'Permissions', to: `/infrastructure/providers/${props.id}/permissions` },
  { label: 'Credentials', to: `/infrastructure/providers/${props.id}/credentials` },
])
const status = computed(() => (props.ep ? (props.ep.enabled ? props.ep.health.status : 'disabled') : 'unknown'))
const label = computed(() => HEALTH_TEXT[status.value] ?? status.value)
const tone = computed(() => healthTone(status.value))
const title = computed(() => (props.ep ? providerTitle(props.ep) : 'Cluster'))
const subtitle = computed(() => props.sub ?? (props.ep ? props.ep.base_url.replace('https://', '') : ''))
const here = computed(() => current.path)
</script>
<template>
  <div class="pv-head">
    <PageHeader :title="title" :sub="subtitle">
      <template #actions><span v-if="ep" class="badge" :class="tone">{{ label }}</span>
        <router-link v-if="ep" class="wz-btn primary" :to="`/infrastructure/providers/${id}/access`" data-testid="manage-access">Manage access</router-link></template>
    </PageHeader>
    <nav class="pv-tabs" aria-label="Cluster sections">
      <router-link v-for="t in tabs" :key="t.to" :to="t.to" :aria-current="here === t.to ? 'page' : undefined">{{ t.label }}</router-link>
    </nav>
  </div>
</template>
