<script setup lang="ts">
// Dashboard: where people sign in (portal URL), every app with its live status, and every service's health, per deployment.
// Owner 2026-11-20: "dashboard should show url for access, all apps status"; "links for services go to different locations, should be ONE
// login portal": every tile opens the portal (one sign-in, then the app); the apps' own addresses are not entry points.
import { get } from '../api'
import { useLoad } from '../store'
import Card from '../ui/Card.vue'
import StatusBadge from '../ui/StatusBadge.vue'

interface App { id: string; title: string; url: string; description: string; status: string }
interface Svc { id: string; title: string; status: string; checks: number; failing: string[] }
interface Dep { deployment: string; status: string; domain: string | null; portal: string | null; apps: App[]; services: Svc[]; health: string }
const data = useLoad(() => get<Dep[]>('dashboard/apps').catch(() => [] as Dep[]), 15000)
const TONE: Record<string, string> = { ok: 'ok', warning: 'warning', critical: 'failed', unknown: 'idle' }
const LABEL: Record<string, string> = { ok: 'Healthy', warning: 'Degraded', critical: 'Down', unknown: 'No data yet' }
</script>
<template>
  <Card v-for="d in (data.data.value ?? [])" :key="d.deployment" :title="'Apps: ' + d.deployment" :hint="d.domain ?? undefined" data-testid="apps-dashboard">
    <template #actions><router-link :to="{ path: '/deployments/' + d.deployment, query: { section: 'people' } }" class="small" data-testid="apps-dashboard-people">People</router-link>
      <router-link :to="'/deployments/' + d.deployment" class="small">Deployment details</router-link></template>
    <p v-if="d.portal" class="ad-portal">Users sign in at <a :href="d.portal" target="_blank" rel="noopener noreferrer" data-testid="apps-dashboard-portal"><b>{{ d.portal }}</b></a>
      <StatusBadge :s="TONE[d.health] ?? 'idle'" :text="'Overall: ' + (LABEL[d.health] ?? d.health)" /></p>
    <p v-else class="muted small">Links appear once the deployment has been created ({{ d.status }}).</p>
    <div class="ad-apps">
      <a v-for="a in d.apps" :key="a.id" class="ad-app" :class="TONE[a.status] ?? 'idle'" :href="d.portal ?? a.url" target="_blank" rel="noopener noreferrer" :title="a.description + ' (through the portal)'">
        <span class="ad-t">{{ a.title }}</span><span class="ad-u">{{ a.description }}</span>
        <StatusBadge :s="TONE[a.status] ?? 'idle'" :text="LABEL[a.status] ?? a.status" />
      </a>
    </div>
    <div v-if="d.services.length" class="ad-svc"><span class="muted small">Services:</span>
      <router-link v-for="s in d.services" :key="s.id" :to="'/checks'" class="ad-chip" :title="s.failing.length ? 'Failing: ' + s.failing.join(', ') : s.checks + ' checks passing'">
        <StatusBadge :s="TONE[s.status] ?? 'idle'" :text="s.title" /></router-link>
    </div>
  </Card>
</template>
<style scoped>
.ad-portal { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: center; margin: 0 0 10px; font-size: 15px; }
.ad-portal a { overflow-wrap: anywhere; }
.ad-apps { display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: 10px; }
.ad-app { display: grid; gap: 4px; padding: 10px 12px; border: 1px solid var(--line); border-radius: 8px; text-decoration: none; color: inherit; }
.ad-app:hover, .ad-app:focus-visible { border-color: var(--accent, #3b82f6); }
.ad-t { font-weight: 600; } .ad-u { font-size: 12px; opacity: .75; overflow-wrap: anywhere; }
.ad-svc { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-top: 12px; }
.ad-chip { text-decoration: none; }
</style>
