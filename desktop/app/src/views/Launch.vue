<script setup lang="ts">
import { computed } from 'vue'
import type { Store } from '../store'
import type { Service } from '../api'
import Icon from '../Icon.vue'
const props = defineProps<{ store: Store; title: string; service: Service | null; note: string }>()
const s = props.store.s
const accounts = computed(() => s.accounts.filter((a) => props.service && a.services.includes(props.service)))
</script>
<template>
  <section>
    <header class="pagehead"><h1>{{ title }}</h1></header>
    <p class="muted">{{ note }}</p>
    <div v-if="service && accounts.length" class="list">
      <button v-for="a in accounts" :key="a.id" type="button" class="rowbtn" :disabled="a.state === 'signed_out'"
              @click="store.simple({ type: 'open_service', account_id: a.id, service: service! })">
        <span><strong>{{ a.deployment }}</strong> <span class="muted">{{ a.label }}</span></span>
        <span>Open in browser <Icon name="external" /></span>
      </button>
    </div>
    <p v-else class="muted">Not available for your accounts.</p>
  </section>
</template>
