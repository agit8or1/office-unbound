<script setup lang="ts">
// Infrastructure > Providers > Proxmox: one card per connected cluster.
import { computed } from 'vue'
import { useLoad } from '../../store'
import { ago } from '../../format'
import PageHeader from '../../ui/PageHeader.vue'
import Button from '../../ui/Button.vue'
import EmptyState from '../../ui/EmptyState.vue'
import Skeleton from '../../ui/Skeleton.vue'
import ErrorBox from '../../components/ErrorBox.vue'
import { api, load } from './api'
import { HEALTH_TEXT, credentialsFor, healthTone, policyStatus, providerTitle, scopeSummary, worstCredential, type CredentialMeta, type PermissionsView, type ProviderEndpoint } from './model'
import './providers.css'

interface Card { ep: ProviderEndpoint; perms: PermissionsView | null; creds: CredentialMeta[] }
const state = useLoad(async () => {
  const eps = (await api.endpoints()).filter((e) => e.type === 'proxmox' && !e.detached_at)
  const creds = await load(() => api.credentials())
  const cards: Card[] = await Promise.all(eps.map(async (ep) => {
    const p = await load(() => api.permissions(ep.id))
    return { ep, perms: p.state === 'ok' ? p.data : null, creds: creds.state === 'ok' ? credentialsFor(ep, creds.data) : [] }
  }))
  return cards
}, 30000)
const cards = computed(() => state.data.value ?? [])
const tone = (t: string) => (t === 'ok' ? 'ok' : t === 'warn' ? 'warn' : t === 'bad' ? 'bad' : t === 'info' ? 'info' : 'idle')
</script>

<template>
  <div class="pv">
    <PageHeader title="Proxmox clusters" sub="The clusters Office Unbound can see and, where you allow it, manage." help="Each card is one connected Proxmox cluster, with what Office Unbound is allowed to touch.">
      <template #actions><Button v-if="cards.length" variant="primary" icon="plus" to="/infrastructure/providers/proxmox/connect">Connect a cluster</Button>
        <Button v-if="cards.length" icon="plus" to="/infrastructure/providers/proxmox/connect-token">Use an API token</Button></template>
    </PageHeader>
    <ErrorBox v-if="state.error.value" :error="state.error.value" @retry="state.reload" />
    <div v-else-if="state.loading.value && !state.data.value" class="pv-cards"><div v-for="i in 2" :key="i" class="card"><Skeleton /></div></div>
    <div v-else-if="!cards.length" class="pv-hero card">
      <EmptyState icon="cluster" title="Connect a Proxmox cluster" text="Office Unbound reads your cluster to show health and capacity, and can deploy and manage virtual machines inside limits that you set. You choose exactly what it may touch.">
        <Button variant="primary" size="md" icon="plus" to="/infrastructure/providers/proxmox/connect">Connect a Proxmox cluster</Button>
        <Button size="md" to="/infrastructure/providers/proxmox/connect-token">Use an API token or setup package</Button>
        <Button size="md" to="/infrastructure/providers/proxmox/connect-ssh">Connect with SSH</Button>
      </EmptyState>
      <ul class="pv-steps muted small"><li>Sign in with your Proxmox user (two-factor supported)</li><li>See everything in the cluster</li><li>Tick exactly what Office Unbound may use</li><li>Review the permissions, approve, done</li></ul>
    </div>
    <div v-else class="pv-cards">
      <article v-for="c in cards" :key="c.ep.id" class="card pv-card">
        <header>
          <div><h2><router-link :to="`/infrastructure/providers/${c.ep.id}`">{{ providerTitle(c.ep) }}</router-link></h2>
            <div class="muted small mono">{{ c.ep.base_url.replace('https://', '') }}<template v-if="c.ep.last_probe?.version"> &middot; PVE {{ c.ep.last_probe.version }}</template></div></div>
          <span class="badge" :class="tone(healthTone(c.ep.enabled ? c.ep.health.status : 'disabled'))">{{ HEALTH_TEXT[c.ep.enabled ? c.ep.health.status : 'disabled'] ?? c.ep.health.status }}</span>
        </header>
        <p v-if="c.ep.health.reason" class="muted small">{{ c.ep.health.reason }}</p>
        <dl class="pv-dl">
          <template v-for="r in scopeSummary(c.ep)" :key="r.label"><dt>{{ r.label }}</dt><dd>{{ r.value }}</dd></template>
          <dt>Last sync</dt><dd>{{ ago(c.ep.last_discovery.at) }}</dd>
          <dt>Credential</dt><dd><span class="badge" :class="tone(worstCredential(c.creds).tone)">{{ worstCredential(c.creds).text }}</span></dd>
          <dt>Permissions</dt><dd><span class="badge" :class="tone(policyStatus(c.perms).tone)">{{ policyStatus(c.perms).text }}</span></dd>
        </dl>
        <footer class="row">
          <Button size="sm" variant="primary" :to="`/infrastructure/providers/${c.ep.id}`">Open</Button>
          <Button size="sm" :to="`/infrastructure/providers/${c.ep.id}/permissions`">Permissions</Button>
          <Button size="sm" variant="ghost" :to="`/infrastructure/providers/${c.ep.id}/credentials`">Credentials</Button>
        </footer>
      </article>
    </div>
  </div>
</template>
