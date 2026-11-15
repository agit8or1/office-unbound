// DEV-ONLY harness: mounts one wizard by hash route against the mock API. Not part of the production bundle.
import { computed, createApp, h, ref } from 'vue'
import '../../style.css'
import './dev.css'
import { wizardRoutes } from '../index'

const theme = new URLSearchParams(location.search).get('theme')
if (theme === 'dark' || theme === 'light') document.documentElement.setAttribute('data-theme', theme)

const path = ref(location.hash.replace(/^#/, '').split('?')[0] || '/setup')
window.addEventListener('hashchange', () => { path.value = location.hash.replace(/^#/, '').split('?')[0] || '/setup' })

createApp({
  setup() {
    const route = computed(() => wizardRoutes.find((r) => r.path === path.value) ?? wizardRoutes[0])
    return () => h('div', { class: 'dev-frame' }, [
      h('div', { class: 'dev-ribbon' }, 'MOCK DATA - design review. Not infrastructure data.'),
      h('nav', { class: 'dev-nav' }, wizardRoutes.map((r) => h('a', { href: '#' + r.path, 'aria-current': r.path === route.value.path ? 'page' : undefined }, r.title))),
      h('main', { class: 'dev-main' }, [h(route.value.component, { key: location.hash })]),
    ])
  },
}).mount('#app')
