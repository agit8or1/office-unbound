<script setup lang="ts">
// ADR-0021 §2: one tenant's settings. Step 1: Overview, Domains (with the DNS checker), Users (per deployment), Policy.
import { computed, watch, watchEffect } from 'vue'
import { crumbLabel } from '../../format'
import StatCard from '../../ui/StatCard.vue'
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
watchEffect(() => { crumbLabel.value = t.data.value?.name ?? '' })   // the breadcrumb names the tenant, not the first 8 characters of its id
const vms = computed(() => (t.data.value?.deployments ?? []).flatMap((d) => d.vms ?? []))
const checks = computed(() => vms.value.reduce((n, v) => n + (v.health?.checks ?? 0), 0))
const failing = computed(() => vms.value.reduce((n, v) => n + (v.health?.failing?.length ?? 0), 0))
const base = computed(() => `/tenants/${props.id}`)
</script>
<template>
  <div class="page">
    <ErrorBox :error="t.error.value" />
    <p v-if="!t.data.value && !t.error.value" class="muted" role="status">Loading tenant…</p>
    <template v-if="t.data.value">
      <PageHeader :title="t.data.value.name" :sub="t.data.value.domains.join(', ') || 'No domain yet'">
        <template #actions><StatusBadge v-if="t.data.value.disabled" s="disabled" text="Disabled" /></template>
      </PageHeader>
      <section class="statgrid tstats" aria-label="Tenant summary">
        <StatCard label="Deployments" :value="t.data.value.deployments.length" :sub="t.data.value.deployments.filter((d) => d.status === 'active').length + ' active'" icon="rocket" tone="info" :to="base + '/overview'" />
        <StatCard label="Virtual machines" :value="vms.length" :sub="vms.filter((v) => v.agent).length + ' with a node agent'" icon="vm" tone="info" :to="base + '/overview'" />
        <StatCard label="Health checks" :value="checks - failing" :of="checks" :sub="!checks ? 'none yet' : failing ? failing + ' failing' : 'all passing'" icon="shield"
                  :tone="!checks ? 'idle' : failing ? 'bad' : 'ok'" :to="base + '/overview'" />
        <StatCard label="Domains" :value="t.data.value.domains.length" :sub="t.data.value.domains.join(', ') || 'none yet'" icon="network" tone="info" :to="base + '/domains'" />
      </section>
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
          <!-- one directory per deployment; PeoplePanel is its own card, so no card around it (a heading only when there are several) -->
          <section v-for="d in t.data.value.deployments" :key="d.slug" class="tsect">
            <h2 v-if="t.data.value.deployments.length > 1" class="h2like">People of {{ d.domain ?? d.slug }} <span class="muted small">deployment {{ d.slug }}</span></h2>
            <PeoplePanel :slug="d.slug" />
          </section>
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
          <p v-if="isAdmin" class="tedit"><router-link class="btn sm" to="/administration/customers">Edit approval policy and contact</router-link></p>
        </Card>
      </template>
    </template>
  </div>
</template>
<style scoped>
.tstats { margin-bottom: 18px; }
.tsect + .tsect { margin-top: 18px; }
.tsect .h2like { display: flex; gap: 10px; align-items: baseline; margin: 0 0 10px; }
.tedit { margin: 16px 0 0; }
</style>
