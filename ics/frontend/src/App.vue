<script setup lang="ts">
import { computed, onMounted, ref, watchEffect } from 'vue'
import { go, hasRole, loadSession, logout, route, session } from './store'
import type { Role } from './api'
import Login from './views/Login.vue'
import Enroll from './views/Enroll.vue'
import Overview from './views/Overview.vue'
import Endpoints from './views/Endpoints.vue'
import Plans from './views/Plans.vue'
import Jobs from './views/Jobs.vue'
import Inventory from './views/Inventory.vue'
import Users from './views/Users.vue'
import Audit from './views/Audit.vue'
import Preview from './views/Preview.vue'
import Checks from './views/Checks.vue'
import Incidents from './views/Incidents.vue'

const pages: { id: string; label: string; min: Role; comp: unknown }[] = [
  { id: 'overview', label: 'Overview', min: 'viewer', comp: Overview },
  { id: 'endpoints', label: 'Endpoints', min: 'viewer', comp: Endpoints },
  { id: 'checks', label: 'Checks', min: 'viewer', comp: Checks },
  { id: 'incidents', label: 'Incidents', min: 'viewer', comp: Incidents },
  { id: 'plans', label: 'Plans', min: 'viewer', comp: Plans },
  { id: 'jobs', label: 'Jobs', min: 'viewer', comp: Jobs },
  { id: 'inventory', label: 'Inventory', min: 'viewer', comp: Inventory },
  { id: 'preview', label: 'Plan preview', min: 'operator', comp: Preview },
  { id: 'users', label: 'Users', min: 'admin', comp: Users },
  { id: 'audit', label: 'Audit', min: 'approver', comp: Audit },
]
const nav = computed(() => pages.filter((p) => hasRole(p.min)))
const current = computed(() => pages.find((p) => p.id === route.value.page))
const denied = computed(() => current.value && !hasRole(current.value.min))

const theme = ref<string>('auto')
function applyTheme() {
  if (theme.value === 'auto') document.documentElement.removeAttribute('data-theme')
  else document.documentElement.setAttribute('data-theme', theme.value)
}
function cycleTheme() {
  theme.value = { auto: 'light', light: 'dark', dark: 'auto' }[theme.value] ?? 'auto'
  try { localStorage.setItem('ics-theme', theme.value) } catch { /* storage may be blocked */ }
  applyTheme()
}

onMounted(async () => {
  try { theme.value = localStorage.getItem('ics-theme') || 'auto' } catch { /* ignore */ }
  applyTheme()
  await loadSession()
})
watchEffect(() => {
  if (!session.ready) return
  const p = route.value.page
  if (p === 'enroll') return
  if (!session.user && p !== 'login') go('login')
  else if (session.user && (p === 'login' || !p)) go('overview')
})
const navOpen = ref(false)
</script>

<template>
  <a class="skip" href="#main" @click.prevent="($refs.main as HTMLElement)?.focus()">Skip to content</a>
  <div v-if="!session.ready" class="center muted" role="status">Loading…</div>
  <template v-else-if="route.page === 'enroll'"><Enroll /></template>
  <template v-else-if="!session.user"><Login /></template>
  <div v-else class="shell">
    <header class="top">
      <button class="ghost navbtn" :aria-expanded="navOpen" aria-controls="nav" @click="navOpen = !navOpen">Menu</button>
      <div class="brand"><span class="mark" aria-hidden="true"></span>Office Unbound <span class="muted">ICS</span></div>
      <div class="who">
        <span class="chip info" :title="'Role: ' + session.user.role">{{ session.user.role }}</span>
        <span>{{ session.user.username }}</span>
        <button class="ghost" @click="cycleTheme" :aria-label="'Theme: ' + theme + '. Click to change.'">Theme: {{ theme }}</button>
        <button class="ghost" @click="logout">Sign out</button>
      </div>
    </header>
    <nav id="nav" class="side" :class="{ open: navOpen }" aria-label="Main">
      <a v-for="p in nav" :key="p.id" :href="'#/' + p.id" :aria-current="route.page === p.id ? 'page' : undefined"
         @click="navOpen = false">{{ p.label }}</a>
    </nav>
    <main id="main" ref="main" tabindex="-1">
      <div v-if="denied" class="alert bad" role="alert">Your role ({{ session.user.role }}) cannot open this page.</div>
      <component :is="current.comp" v-else-if="current" :key="route.page" />
      <div v-else class="alert warn">Unknown page.</div>
    </main>
  </div>
</template>
