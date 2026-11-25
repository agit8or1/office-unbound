<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { tauriBackend, type Backend } from './api'
import { createStore } from './store'
import Icon from './Icon.vue'
import Welcome from './views/Welcome.vue'
import Home from './views/Home.vue'
import Launch from './views/Launch.vue'
import Settings from './views/Settings.vue'
import Chat from './views/Chat.vue'

const props = withDefaults(defineProps<{ api?: Backend; pollMs?: number }>(), { api: () => tauriBackend, pollMs: 2000 })
const store = createStore(props.api)
const s = store.s

type Page = 'home' | 'files' | 'chat' | 'meetings' | 'calendar' | 'mail' | 'contacts' | 'settings'
const page = ref<Page>('home')
const collapsed = ref(false)
const nav: { id: Page; label: string }[] = [
  { id: 'home', label: 'Home' }, { id: 'files', label: 'Files' }, { id: 'chat', label: 'Chat' }, { id: 'meetings', label: 'Meetings' },
  { id: 'calendar', label: 'Calendar' }, { id: 'mail', label: 'Mail' }, { id: 'contacts', label: 'Contacts' },
]
const launch: Record<string, { title: string; service: 'files' | 'chat' | 'mail' | 'calendar' | 'contacts' | null; note: string }> = {
  files: { title: 'Files', service: 'files', note: 'Folder sync, Files On-Demand and the O: drive are in development and not available yet. Your files are in the browser.' },
  chat: { title: 'Chat', service: 'chat', note: 'Chat inside this app is in development. Until then, chat opens in the browser with the same sign-in.' },
  meetings: { title: 'Meetings', service: null, note: 'Meetings are not available on your deployment yet.' },
  calendar: { title: 'Calendar', service: 'calendar', note: 'Your calendar opens in the browser (Office Unbound webmail).' },
  mail: { title: 'Mail', service: 'mail', note: 'Your mailbox opens in the browser (Office Unbound webmail).' },
  contacts: { title: 'Contacts', service: 'contacts', note: 'Your contacts open in the browser (Office Unbound webmail).' },
}
const overall = computed(() => {
  if (!s.accounts.length) return { cls: 'idle', text: 'Not signed in' }
  if (s.accounts.every((a) => a.state === 'signed_in')) return { cls: 'signed_in', text: s.paused ? 'Connected, paused' : 'Connected' }
  if (s.accounts.some((a) => a.state === 'offline')) return { cls: 'offline', text: 'Offline, retrying' }
  return { cls: 'signed_out', text: 'Action needed' }
})

let timer: ReturnType<typeof setInterval> | undefined
function poll() { if (!document.hidden) store.refresh() }
onMounted(() => { store.refresh(); timer = setInterval(poll, props.pollMs) })
onBeforeUnmount(() => clearInterval(timer))
</script>

<template>
  <div v-if="s.phase !== 'ready'" class="firstrun"><Welcome :store="store" /></div>
  <div v-else class="shell" :class="{ collapsed }">
    <nav class="rail" aria-label="Main">
      <button class="collapse" type="button" :aria-expanded="!collapsed" @click="collapsed = !collapsed" title="Collapse navigation">
        <img src="./assets/ou-mark.svg" alt="Office Unbound" width="24" height="24" />
      </button>
      <button v-for="n in nav" :key="n.id" type="button" :class="{ on: page === n.id }" :aria-current="page === n.id ? 'page' : undefined"
              @click="page = n.id" :title="n.label"><Icon :name="n.id" /><span>{{ n.label }}</span></button>
      <span class="grow"></span>
      <button type="button" :class="{ on: page === 'settings' }" @click="page = 'settings'" title="Settings"><Icon name="settings" /><span>Settings</span></button>
    </nav>
    <main>
      <div class="statusbar" role="status"><span class="dot" :class="overall.cls"></span>{{ overall.text }}</div>
      <Home v-if="page === 'home'" :store="store" />
      <Settings v-else-if="page === 'settings'" :store="store" :api="api" />
      <Chat v-else-if="page === 'chat'" :store="store" :api="api" />
      <Launch v-else :store="store" :title="launch[page].title" :service="launch[page].service" :note="launch[page].note" />
    </main>
  </div>
</template>
