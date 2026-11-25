<script setup lang="ts">
// ADR-0021 §2: one tenant's settings. Step 1: Overview, Domains (with the DNS checker), Users (per deployment), Policy.
import { computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { hasRole, useLoad } from '../../store'
import PageHeader from '../../ui/PageHeader.vue'
import Card from '../../ui/Card.vue'
import Tabs from '../../ui/Tabs.vue'
import EmptyState from '../../ui/EmptyState.vue'
import StatusBadge from '../../ui/StatusBadge.vue'
import ErrorBox from '../../components/ErrorBox.vue'
import PeoplePanel from '../../components/PeoplePanel.vue'
import DnsCheck from './DnsCheck.vue'
import DeploymentCard from './DeploymentCard.vue'
import { MODE_LABEL, tenantsApi } from './tenants'

const props = defineProps<{ id: string; tab?: string }>()
const route = useRoute()
const router = useRouter()
const TABS = [{ id: 'overview', label: 'Overview' }, { id: 'domains', label: 'Domains' }, { id: 'users', label: 'Users' }, { id: 'policy', label: 'Policy' }]
const tab = computed({
  get: () => (TABS.some((t) => t.id === props.tab) ? (props.tab as string) : 'overview'),
  set: (v: string) => { void router.replace({ path: `/tenants/${props.id}/${v}`, query: route.query }) },
})
const t = useLoad(() => tenantsApi.one(props.id))
watch(() => props.id, () => { void t.reload() })   // another tenant opened from this page: load it
const withDomain = computed(() => (t.data.value?.deployments ?? []).filter((d) => d.domain))
const isAdmin = computed(() => hasRole('admin'))
</script>
<template>
  <div class="page">
    <ErrorBox :error="t.error.value" />
    <p v-if="!t.data.value && !t.error.value" class="muted" role="status">Loading tenant…</p>
    <template v-if="t.data.value">
      <PageHeader :title="t.data.value.name" :sub="t.data.value.domains.join(', ') || 'No domain yet'">
        <template #actions><StatusBadge v-if="t.data.value.disabled" s="disabled" text="Disabled" /></template>
      </PageHeader>
      <Tabs v-model="tab" :tabs="TABS" />

      <template v-if="tab === 'overview'">
        <DeploymentCard v-for="d in t.data.value.deployments" :key="d.slug" :tenant="t.data.value.id" :d="d" />
        <EmptyState v-if="!t.data.value.deployments.length" title="No deployments yet">
          <router-link v-if="hasRole('operator')" class="btn" to="/deployments/new">New deployment</router-link>
        </EmptyState>
      </template>

      <template v-else-if="tab === 'domains'">
        <Card v-for="d in withDomain" :key="d.slug" :title="d.domain ?? ''" :hint="`Deployment ${d.slug}`">
          <DnsCheck :tenant="t.data.value.id" :deployment="d.slug" :domain="d.domain" />
        </Card>
        <EmptyState v-if="!withDomain.length" title="No domains yet" text="A domain appears here once a deployment of this tenant has been created." icon="network" />
      </template>

      <template v-else-if="tab === 'users'">
        <template v-if="isAdmin">
          <Card v-for="d in t.data.value.deployments" :key="d.slug" :title="`People of ${d.domain ?? d.slug}`" :hint="`Directory of deployment ${d.slug}`">
            <PeoplePanel :slug="d.slug" />
          </Card>
          <EmptyState v-if="!t.data.value.deployments.length" title="No users yet" text="Users live in a deployment's directory: create a deployment first." icon="users" />
        </template>
        <EmptyState v-else title="Admins only" text="Reading a tenant's people needs the admin role." icon="shield" />
      </template>

      <template v-else-if="tab === 'policy'">
        <Card title="How changes are approved">
          <p>{{ MODE_LABEL[t.data.value.provisioning_mode] }}.</p>
          <dl class="kv">
            <dt>Contact</dt><dd>{{ t.data.value.contact_name || 'Not set' }}<span v-if="t.data.value.contact_email" class="muted"> · {{ t.data.value.contact_email }}</span></dd>
            <dt>Run by the platform owner</dt><dd>{{ t.data.value.msp_owned ? 'Yes' : 'No' }}</dd>
          </dl>
          <p v-if="isAdmin"><router-link to="/administration/customers">Edit approval policy and contact</router-link></p>
        </Card>
      </template>
    </template>
  </div>
</template>
