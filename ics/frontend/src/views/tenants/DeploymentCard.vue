<script setup lang="ts">
// ADR-0021: one deployment of a tenant: its VMs (what runs where, size, agent, health) and the DNS records it needs with their status.
import { ref } from 'vue'
import Card from '../../ui/Card.vue'
import StatusBadge from '../../ui/StatusBadge.vue'
import { serviceLabel } from '../../wizards/deploy/sizing'
import DnsCheck from './DnsCheck.vue'
import type { TenantDeployment } from './tenants'

defineProps<{ tenant: string; d: TenantDeployment }>()
const showDns = ref(false)
const APP_OF: Record<string, string> = { groupware: 'mail', files: 'files', office: 'office', chat: 'chat', meetings: 'meetings', telephony: 'telephony' }
const ROLE: Record<string, string> = { identity: 'Sign-in', edge: 'Gateway', portal: 'Portal' }
// the monitoring agent runs on every VM: it is not something the VM "runs" for the tenant
const runs = (comps: string[]) => comps.filter((c) => c !== 'monitoring-agent').map((c) => (APP_OF[c] ? serviceLabel(APP_OF[c]) : ROLE[c] ?? c)).join(', ')
const short = (name: string, slug: string) => (name.startsWith(slug + '-') ? name.slice(slug.length + 1) : name)
const gb = (mb: number | null) => (mb == null ? '–' : `${Math.round(mb / 1024)} GB`)
const ago = (s: string | null) => {
  if (!s) return 'never'
  const m = Math.round((Date.now() - new Date(s).getTime()) / 60000)
  return m < 1 ? 'just now' : m < 60 ? `${m} min ago` : m < 1440 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} d ago`
}
</script>
<template>
  <Card :title="d.domain ?? d.slug" :hint="`Deployment ${d.slug}`">
    <template #actions>
      <StatusBadge :s="d.status" />
      <router-link class="btn sm" :to="`/deployments/${d.slug}`">Open deployment</router-link>
    </template>
    <h3 class="sub">Virtual machines</h3>
    <div v-if="d.vms && d.vms.length" class="tablewrap" tabindex="0" role="region" :aria-label="`Virtual machines of ${d.slug}`">
      <table class="dense">
        <thead><tr><th scope="col">VM</th><th scope="col">Runs</th><th scope="col">Location</th><th scope="col">Size</th>
          <th scope="col">Node agent</th><th scope="col">Health</th></tr></thead>
        <tbody>
          <tr v-for="v in d.vms" :key="v.name">
            <th scope="row" :title="v.name"><b>{{ short(v.name, d.slug) }}</b><div v-if="v.state !== 'present'" class="muted small">{{ v.state }}</div></th>
            <td>{{ runs(v.components) }}</td>
            <td><span class="mono">{{ v.node ?? '–' }}</span><span v-if="v.vmid != null" class="muted"> · VM {{ v.vmid }}</span>
              <div class="muted small">{{ v.endpoint ?? '' }}<template v-if="v.storage.length"> · {{ v.storage.join(', ') }}</template></div></td>
            <td class="nw">{{ v.cores ?? '–' }} vCPU · {{ gb(v.memory_mb) }}<div class="muted small">{{ v.disk_gb }} GB disk</div></td>
            <td><template v-if="v.agent"><StatusBadge :s="v.agent.status" /><div class="muted small">{{ v.agent.version ? 'v' + v.agent.version + ' · ' : '' }}seen {{ ago(v.agent.last_seen_at) }}</div>
              <div class="muted small mono">{{ v.agent.address }}</div></template><span v-else class="muted">Not enrolled</span></td>
            <td class="nwh"><StatusBadge :s="v.health.status" :text="v.health.checks ? undefined : 'No checks'" />
              <div v-if="v.health.failing.length" class="muted small">{{ v.health.failing.length }} failing: <span class="mono">{{ v.health.failing.join(', ') }}</span></div>
              <div v-else-if="v.health.checks" class="muted small">{{ v.health.checks }} checks</div></td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-else class="muted">No VMs yet: the deployment has not been created.</p>
    <template v-if="d.domain">
      <h3 class="sub">DNS records</h3>
      <DnsCheck v-if="showDns" :tenant="tenant" :deployment="d.slug" :domain="d.domain" />
      <p v-else><button type="button" class="btn sm dnsbtn" @click="showDns = true">Show the DNS records this deployment needs</button></p>
    </template>
  </Card>
</template>
<style scoped>
.dnsbtn { white-space: normal; height: auto; min-height: 30px; text-align: left; max-width: 100%; }
/* the VM name is a row header: plain, not the shaded header cell; size and health stay on one line */
tbody th { background: transparent; font-weight: 600; text-align: left; vertical-align: top; white-space: nowrap; }
td { vertical-align: top; } td.nw { white-space: nowrap; } td.nwh > .muted { white-space: nowrap; }
h3.sub { font-size: 14px; font-weight: 600; margin: 4px 0 8px; }
h3.sub + p, .tablewrap { margin-bottom: 16px; }
.mono { overflow-wrap: anywhere; }
</style>
