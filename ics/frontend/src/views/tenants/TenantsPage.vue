<script setup lang="ts">
// ADR-0021: Administration > Tenants. One tenant (single-tenant installation) opens directly.
import { watch } from 'vue'
import { useRouter } from 'vue-router'
import { useLoad } from '../../store'
import PageHeader from '../../ui/PageHeader.vue'
import Card from '../../ui/Card.vue'
import EmptyState from '../../ui/EmptyState.vue'
import StatusBadge from '../../ui/StatusBadge.vue'
import ErrorBox from '../../components/ErrorBox.vue'
import { MODE_LABEL, tenantsApi } from './tenants'

const router = useRouter()
const st = useLoad(() => tenantsApi.list())
watch(() => st.data.value, (d) => {
  if (d && d.mode === 'single' && d.tenants.length === 1) void router.replace(`/tenants/${d.tenants[0].id}`)
})
</script>
<template>
  <div class="page">
    <PageHeader title="Tenants" sub="The organisations this installation serves: their domains, people and settings"
                help="A tenant has its own deployments, domains, users and tenant admins. Platform admins (Administration > Platform admins) run the installation itself." />
    <ErrorBox :error="st.error.value" />
    <p v-if="!st.data.value && !st.error.value" class="muted" role="status">Loading tenants…</p>
    <Card v-else-if="st.data.value && st.data.value.tenants.length" flush>
      <div class="tablewrap" tabindex="0" role="region" aria-label="Tenants">
        <table class="dense">
          <thead><tr><th scope="col">Tenant</th><th scope="col">Domains</th><th scope="col">Deployments</th><th scope="col">Changes</th></tr></thead>
          <tbody>
            <tr v-for="t in st.data.value.tenants" :key="t.id">
              <th scope="row"><router-link :to="`/tenants/${t.id}`">{{ t.name }}</router-link>
                <StatusBadge v-if="t.disabled" s="disabled" text="Disabled" /></th>
              <td><span v-if="t.domains.length" class="mono">{{ t.domains.join(', ') }}</span><span v-else class="muted">None yet</span></td>
              <td>{{ t.deployments.length }}</td>
              <td class="muted">{{ MODE_LABEL[t.provisioning_mode] }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </Card>
    <EmptyState v-else-if="st.data.value" title="No tenants in your scope" text="Ask an administrator with access to all tenants to add you to one." icon="users" />
  </div>
</template>
