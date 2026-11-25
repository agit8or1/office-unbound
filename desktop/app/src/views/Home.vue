<script setup lang="ts">
import type { Store } from '../store'
import type { Service } from '../api'
import { STATE_LABEL } from '../api'
import Icon from '../Icon.vue'
const props = defineProps<{ store: Store }>()
const s = props.store.s
const quick: { service: Service; label: string; icon: string }[] = [
  { service: 'files', label: 'Files', icon: 'files' },
  { service: 'chat', label: 'Chat', icon: 'chat' },
  { service: 'mail', label: 'Mail', icon: 'mail' },
  { service: 'calendar', label: 'Calendar', icon: 'calendar' },
  { service: 'portal', label: 'Portal', icon: 'home' },
]
function open(id: string, service: Service) {
  props.store.simple({ type: 'open_service', account_id: id, service })
}
</script>
<template>
  <section>
    <header class="pagehead"><h1>Home</h1></header>
    <article v-for="a in s.accounts" :key="a.id" class="card">
      <div class="cardhead">
        <div>
          <h2>{{ a.deployment }}</h2>
          <div class="muted">{{ a.label }}</div>
        </div>
        <span class="badge" :class="a.state">{{ STATE_LABEL[a.state] }}</span>
      </div>
      <p v-if="a.detail && a.state !== 'signed_in'" class="muted">{{ a.detail }}</p>
      <div class="quick">
        <button v-for="q in quick.filter((q) => a.services.includes(q.service))" :key="q.service" type="button"
                :disabled="a.state === 'signed_out'" @click="open(a.id, q.service)" :title="`Open ${q.label} in the browser`">
          <Icon :name="q.icon" /> {{ q.label }} <Icon name="external" class="ext" />
        </button>
      </div>
    </article>
    <article class="card subtle">
      <h2>File sync</h2>
      <p class="muted">Folder sync and the mapped drive are being built (Phase 2). Until then, open Files in the browser.</p>
    </article>
  </section>
</template>
