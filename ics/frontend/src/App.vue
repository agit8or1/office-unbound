<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { get, type BuildInfo, type Incident, type Plan } from './api'
import { hasRole, loadSession, logout, session } from './store'
import { buildLabel, crumbLabel } from './format'
import { hasPath } from './router'
import { NAV, isActive, type NavItem } from './nav'
import Icon from './ui/Icon.vue'
import ToastHost from './ui/ToastHost.vue'

const route = useRoute()
const router = useRouter()

const theme = ref<'auto' | 'light' | 'dark'>('auto')
function applyTheme() {
  if (theme.value === 'auto') document.documentElement.removeAttribute('data-theme')
  else document.documentElement.setAttribute('data-theme', theme.value)
}
const dark = () => theme.value === 'dark' || (theme.value === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches)
function toggleTheme() {
  theme.value = dark() ? 'light' : 'dark'
  try { localStorage.setItem('ics-theme', theme.value) } catch { /* storage may be blocked */ }
  applyTheme()
}

const build = ref<BuildInfo | null>(null)
async function loadBuild() {
  try { build.value = await get<BuildInfo>('version') } catch { /* footer falls back to the product name */ }
}
watch(() => session.user?.username, () => { if (session.user) void loadBuild() })

// nav badges: active incidents and plans waiting for approval (real counts, refreshed every 20 s)
const badges = ref({ incidents: 0, approvals: 0 })
let timer: number | undefined
async function refreshBadges() {
  if (!session.user) return
  try {
    const [i, p] = await Promise.all([get<Incident[]>('incidents?status=active&limit=200'), get<Plan[]>('plans')])
    badges.value = { incidents: i.length, approvals: p.filter((x) => x.status === 'pending_approval').length }
  } catch { /* badges are best effort */ }
}
onMounted(async () => {
  try { theme.value = (localStorage.getItem('ics-theme') as typeof theme.value) || 'auto' } catch { /* ignore */ }
  applyTheme()
  await loadSession()
  void loadBuild()
  void refreshBadges()
  timer = window.setInterval(() => { if (!document.hidden) void refreshBadges() }, 20000)
})
onUnmounted(() => clearInterval(timer))

// auth redirects
const bare = computed(() => !!route.meta.bare)
// Owner decision (2026-11-15): login always lands on the dashboard; the setup wizard is offered there (Overview getting-started card),
// never opened automatically.
watch([() => session.ready, () => session.user, () => route.name], () => {
  if (!session.ready) return
  if (route.name === 'enroll') return
  if (!session.user && route.name !== 'login') void router.replace('/login')
  else if (session.user && route.name === 'login') { void router.replace('/overview'); void refreshBadges() }
}, { immediate: true })
watch(() => route.fullPath, () => { navOpen.value = false; crumbLabel.value = '' })

const denied = computed(() => !!route.meta.min && !hasRole(route.meta.min))
const navOpen = ref(false)
const groups = computed(() => NAV.map((g) => ({ ...g, items: g.items.filter((i) => (!i.min || hasRole(i.min)) && (!i.ifPath || hasPath(i.ifPath))) })).filter((g) => g.items.length))
const count = (i: NavItem) => (i.badge ? badges.value[i.badge] : 0)

const crumbs = computed(() => {
  const out: { label: string; to?: string }[] = []
  const m = route.meta
  if (m.section) out.push({ label: m.section })
  if (m.parent) { out.push({ label: m.parent.label, to: m.parent.to }); out.push({ label: crumbLabel.value || String(route.params.id ?? '').slice(0, 8) }) }
  else if (route.params.id && typeof route.params.id === 'string') { out.push({ label: String(m.title), to: route.path.split('/').slice(0, 2).join('/') }); out.push({ label: crumbLabel.value || route.params.id.slice(0, 8) }) }
  else out.push({ label: m.title ?? '' })
  return out
})
watch(() => route.meta.title, (t) => { document.title = (t ? t + ' - ' : '') + 'Office Unbound' }, { immediate: true })
</script>

<template>
  <a class="skip" href="#main" @click.prevent="($refs.main as HTMLElement)?.focus()">Skip to content</a>
  <div v-if="!session.ready" class="center muted" role="status">Loading…</div>
  <router-view v-else-if="bare || !session.user" />
  <div v-else class="shell">
    <aside class="side" :class="{ open: navOpen }">
      <div class="brand"><span class="mark"><Icon name="cluster" /></span><div>Office Unbound<small>Control console</small></div></div>
      <nav aria-label="Main">
        <div v-for="(g, gi) in groups" :key="gi" class="navgroup">
          <div v-if="g.title" class="navtitle">{{ g.title }}</div>
          <template v-for="i in g.items" :key="i.label">
            <span v-if="i.planned" class="navitem planned" :title="i.label + ' is planned'"><Icon :name="i.icon" />{{ i.label }}<span class="tag">Planned</span></span>
            <router-link v-else :to="i.to!" class="navitem" :class="{ active: isActive(i, route.path) }" :aria-current="isActive(i, route.path) ? 'page' : undefined">
              <Icon :name="i.icon" />{{ i.label }}<span v-if="count(i)" class="count" :class="{ soft: i.badge === 'approvals' }">{{ count(i) }}</span>
            </router-link>
          </template>
        </div>
      </nav>
      <div class="foot">Signed in as {{ session.user.username }} ({{ session.user.role }})<div class="build" data-testid="build-label">{{ buildLabel(build) }}</div></div>
    </aside>
    <div class="scrim" :class="{ open: navOpen }" @click="navOpen = false"></div>
    <div class="main-col">
      <header class="top">
        <button class="iconbtn menu-btn" aria-label="Open navigation" :aria-expanded="navOpen" @click="navOpen = !navOpen"><Icon name="menu" /></button>
        <nav class="crumbs grow" aria-label="Breadcrumb">
          <router-link to="/overview">Console</router-link>
          <template v-for="(c, i) in crumbs" :key="i"><span class="sep">/</span>
            <router-link v-if="c.to" :to="c.to">{{ c.label }}</router-link>
            <span v-else :class="{ here: i === crumbs.length - 1 }">{{ c.label }}</span>
          </template>
        </nav>
        <button class="iconbtn" :aria-label="dark() ? 'Switch to light theme' : 'Switch to dark theme'" @click="toggleTheme"><Icon :name="dark() ? 'sun' : 'moon'" /></button>
        <div class="userchip"><span class="avatar" aria-hidden="true">{{ session.user.username.slice(0, 2) }}</span><span class="meta"><b>{{ session.user.username }}</b><span class="muted">{{ session.user.role }}</span></span></div>
        <button class="iconbtn" aria-label="Sign out" title="Sign out" @click="logout"><Icon name="logout" /></button>
      </header>
      <main id="main" ref="main" tabindex="-1">
        <div v-if="denied" class="alert bad" role="alert">Your role ({{ session.user.role }}) cannot open this page.</div>
        <router-view v-else v-slot="{ Component }"><component :is="Component" :key="String(route.name)" /></router-view>
      </main>
    </div>
  </div>
  <ToastHost />
</template>
